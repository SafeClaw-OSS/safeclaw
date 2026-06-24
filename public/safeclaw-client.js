// SafeClaw v1 client-side WebAuthn + crypto helpers.
//
// v1 delegates transport confidentiality to TLS (no application-layer ECIES),
// uses WebAuthn PRF two-eval for per-write key rotation, and binds every
// assertion to the specific request being authorized via a channel binding
// hash that the server recomputes and verifies.
//
// All authenticated requests follow this schema:
//
//   POST /path
//   {
//     "server_random": "<b64 16B>",
//     "credential_id": "<b64>",
//     "user_key":      "<b64 32B>",
//     "user_key_next": "<b64 32B>",   // optional, write-rotation only
//     "prf_salt_next": "<b64 32B>",   // optional, write-rotation only
//     "assertion":     { authenticator_data, client_data_json, signature },
//     ... operation-specific fields ...
//   }

window.SafeClaw = (() => {
  // ─── base64 helpers ────────────────────────────────────────────────────────

  function toBase64(u8) {
    let s = '';
    for (let i = 0; i < u8.byteLength; i++) s += String.fromCharCode(u8[i]);
    return btoa(s);
  }

  function toBase64url(u8) {
    return toBase64(u8).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function fromBase64(b64) {
    const std = b64.replace(/-/g, '+').replace(/_/g, '/');
    const s = atob(std);
    const u8 = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) u8[i] = s.charCodeAt(i);
    return u8;
  }

  // ─── JSON canonicalization (RFC 8785 subset matching Rust) ─────────────────

  const EXCLUDED_BINDING_FIELDS = new Set([
    'assertion',
    'server_random',
    'user_key',
    'user_key_next',
  ]);

  function canonicalizeJson(v) {
    if (v === null) return 'null';
    if (typeof v === 'boolean') return v ? 'true' : 'false';
    if (typeof v === 'number') {
      if (!Number.isFinite(v)) throw new Error('non-finite number');
      return JSON.stringify(v);
    }
    if (typeof v === 'string') return JSON.stringify(v);
    if (Array.isArray(v)) {
      return '[' + v.map(canonicalizeJson).join(',') + ']';
    }
    if (typeof v === 'object') {
      // Sort keys by UTF-16 code unit order.
      const keys = Object.keys(v).sort();
      return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalizeJson(v[k])).join(',') + '}';
    }
    throw new Error('cannot canonicalize ' + typeof v);
  }

  function canonicalizeBody(body) {
    if (body === null || typeof body !== 'object' || Array.isArray(body)) {
      return new TextEncoder().encode(canonicalizeJson(body));
    }
    const filtered = {};
    for (const k of Object.keys(body)) {
      if (!EXCLUDED_BINDING_FIELDS.has(k)) {
        filtered[k] = body[k];
      }
    }
    return new TextEncoder().encode(canonicalizeJson(filtered));
  }

  // ─── Channel binding ───────────────────────────────────────────────────────

  async function sha256(bytes) {
    const buf = await crypto.subtle.digest('SHA-256', bytes);
    return new Uint8Array(buf);
  }

  async function computeRequestHash(method, path, body) {
    const enc = new TextEncoder();
    const canon = canonicalizeBody(body);
    const parts = [
      enc.encode(method.toUpperCase()),
      new Uint8Array([0]),
      enc.encode(path),
      new Uint8Array([0]),
      canon,
    ];
    const total = parts.reduce((n, p) => n + p.length, 0);
    const buf = new Uint8Array(total);
    let off = 0;
    for (const p of parts) {
      buf.set(p, off);
      off += p.length;
    }
    return sha256(buf);
  }

  async function computeBinding(domain, serverRandomBytes, requestHash) {
    const enc = new TextEncoder();
    const domainBytes = enc.encode(domain);
    const total = domainBytes.length + 1 + serverRandomBytes.length + requestHash.length;
    const buf = new Uint8Array(total);
    let off = 0;
    buf.set(domainBytes, off); off += domainBytes.length;
    buf[off++] = 0;
    buf.set(serverRandomBytes, off); off += serverRandomBytes.length;
    buf.set(requestHash, off); off += requestHash.length;
    return sha256(buf);
  }

  const BINDING_STANDARD = 'safeclaw/v1/binding';
  const BINDING_SETUP = 'safeclaw/v1/binding-setup';
  const BINDING_SETUP_OVERWRITE = 'safeclaw/v1/binding-setup-overwrite';
  const BINDING_IDENTITY = 'safeclaw/v1/binding-identity';
  const BINDING_OFFLINE = 'safeclaw/v1/binding-offline';

  // ─── PRF → userKey derivation ──────────────────────────────────────────────

  async function hkdfUserKey(rawPrf, credentialIdBytes) {
    const keyMaterial = await crypto.subtle.importKey('raw', rawPrf, 'HKDF', false, ['deriveBits']);
    const info = new Uint8Array(21 + credentialIdBytes.length);
    info.set(new TextEncoder().encode('safeclaw/v1/userkey'), 0);
    info[19] = 0;
    // Wait — "safeclaw/v1/userkey" is 19 chars; +0x00 byte = 20 bytes; then credentialId.
    // Rebuild more cleanly:
    const prefix = new TextEncoder().encode('safeclaw/v1/userkey');
    const infoBuf = new Uint8Array(prefix.length + 1 + credentialIdBytes.length);
    infoBuf.set(prefix, 0);
    infoBuf[prefix.length] = 0;
    infoBuf.set(credentialIdBytes, prefix.length + 1);
    const bits = await crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(32),
        info: infoBuf,
      },
      keyMaterial,
      256
    );
    return new Uint8Array(bits);
  }

  // ─── Challenge fetch ───────────────────────────────────────────────────

  async function challengeInit() {
    const res = await fetch('/challenge');
    if (!res.ok) throw new Error('challenge fetch failed: ' + res.status);
    return res.json();
  }

  // ─── Build an authenticated request ────────────────────────────────────────

  /**
   * Run the WebAuthn ceremony and return everything the server needs.
   *
   * @param {Object} opts
   * @param {string} opts.method       HTTP method (e.g. "POST")
   * @param {string} opts.path         URL path (e.g. "/vault/unlock")
   * @param {Object} opts.body         Operation-specific body fields (will not
   *                                   contain assertion/server_random/user_key*).
   * @param {string} opts.domain       Channel-binding domain separator.
   * @param {boolean} [opts.rotate]    Whether to rotate prf_salt (writes only).
   * @param {Uint8Array} [opts.credentialId]  Specific credential to target. If
   *                                   omitted, discoverable credential flow is used.
   * @param {Uint8Array} [opts.prfSalt]       Current prf_salt from session/init.
   * @param {Uint8Array} [opts.prfSaltNext]   Fresh next salt (write only); if omitted
   *                                   and rotate=true, generated here.
   * @returns {Object} Full request body ready to JSON.stringify and POST.
   */
  async function buildAuthenticatedRequest(opts) {
    const {
      method, path, body, domain,
      rotate = false,
    } = opts;
    let { credentialId, prfSalt, prfSaltNext } = opts;

    // Fetch session init if we don't have the prerequisites.
    if (!credentialId || !prfSalt) {
      const init = await challengeInit();
      const serverRandom = init.server_random;
      if (!init.dek_wraps || init.dek_wraps.length === 0) {
        throw new Error('no registered passkeys');
      }
      // Pick the first (or let the browser choose via no allowCredentials).
      const entry = init.dek_wraps[0];
      credentialId = fromBase64(entry.credential_id);
      prfSalt = fromBase64(entry.prf_salt);
      opts.serverRandomBytes = fromBase64(serverRandom);
      opts.serverRandom = serverRandom;
    }

    // If caller didn't fetch server_random separately, do it now.
    if (!opts.serverRandom) {
      const init = await challengeInit();
      opts.serverRandom = init.server_random;
      opts.serverRandomBytes = fromBase64(init.server_random);
    }

    if (rotate && !prfSaltNext) {
      prfSaltNext = crypto.getRandomValues(new Uint8Array(32));
    }

    // Build the body that will be hashed (no assertion/user_key yet).
    const bodyForHash = Object.assign(
      {
        server_random: opts.serverRandom,
        credential_id: toBase64(credentialId),
      },
      body || {}
    );
    if (rotate) {
      bodyForHash.prf_salt_next = toBase64(prfSaltNext);
    }

    // Compute channel binding.
    const requestHash = await computeRequestHash(method, path, bodyForHash);
    const binding = await computeBinding(domain, opts.serverRandomBytes, requestHash);

    // Run WebAuthn.
    const prfEval = rotate
      ? { first: prfSalt, second: prfSaltNext }
      : { first: prfSalt };
    const getOptions = {
      publicKey: {
        challenge: binding,
        userVerification: 'required',
        extensions: { prf: { eval: prfEval } },
      },
    };
    if (credentialId) {
      getOptions.publicKey.allowCredentials = [
        { type: 'public-key', id: credentialId },
      ];
    }
    const assertion = await navigator.credentials.get(getOptions);

    const extResults = assertion.getClientExtensionResults();
    const rawPrf = extResults?.prf?.results?.first;
    if (!rawPrf) {
      throw new Error('Authenticator did not return a PRF result (PRF not supported?)');
    }
    const userKey = await hkdfUserKey(new Uint8Array(rawPrf), credentialId);

    let userKeyNext;
    if (rotate) {
      const rawPrfNext = extResults?.prf?.results?.second;
      if (!rawPrfNext) {
        throw new Error('Authenticator does not support two-eval PRF (required for writes)');
      }
      userKeyNext = await hkdfUserKey(new Uint8Array(rawPrfNext), credentialId);
    }

    // Build final body.
    const finalBody = Object.assign({}, bodyForHash, {
      user_key: toBase64(userKey),
      assertion: {
        authenticator_data: toBase64(new Uint8Array(assertion.response.authenticatorData)),
        client_data_json: toBase64(new Uint8Array(assertion.response.clientDataJSON)),
        signature: toBase64(new Uint8Array(assertion.response.signature)),
        credential_id: toBase64(credentialId),
      },
    });
    if (rotate && userKeyNext) {
      finalBody.user_key_next = toBase64(userKeyNext);
    }

    // Best-effort zeroize.
    userKey.fill(0);
    if (userKeyNext) userKeyNext.fill(0);

    return finalBody;
  }

  // v1 returns plaintext JSON directly (protected by TLS); no sealing helpers.

  return {
    toBase64,
    toBase64url,
    fromBase64,
    canonicalizeJson,
    canonicalizeBody,
    computeRequestHash,
    computeBinding,
    hkdfUserKey,
    challengeInit,
    buildAuthenticatedRequest,
    BINDING_STANDARD,
    BINDING_SETUP,
    BINDING_SETUP_OVERWRITE,
    BINDING_IDENTITY,
    BINDING_OFFLINE,
  };
})();
