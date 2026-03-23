// SafeClaw Client — shared crypto + WebAuthn helpers
// Used by setup.html, unlock.html, admin.html
// Protocol: P-256 ECDH + HKDF-SHA256 + AES-256-GCM

window.SafeClaw = (() => {
  function toBase64(u8) {
    let s = '';
    for (let i = 0; i < u8.byteLength; i++) s += String.fromCharCode(u8[i]);
    return btoa(s);
  }

  function fromBase64(b64) {
    // Accept both standard base64 and base64url
    const std = b64.replace(/-/g, '+').replace(/_/g, '/');
    const s = atob(std);
    const u8 = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) u8[i] = s.charCodeAt(i);
    return u8;
  }

  // ECIES encrypt: P-256 ECDH → HKDF → AES-256-GCM
  async function e2eEncrypt(plaintext, vmPkJwk) {
    const ephemeral = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']
    );
    const serverPub = await crypto.subtle.importKey(
      'jwk', vmPkJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, []
    );
    const sharedBits = await crypto.subtle.deriveBits(
      { name: 'ECDH', public: serverPub }, ephemeral.privateKey, 256
    );
    const hkdfKey = await crypto.subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveBits']);
    const aesKeyBits = await crypto.subtle.deriveBits({
      name: 'HKDF', hash: 'SHA-256',
      salt: new Uint8Array(32),
      info: new TextEncoder().encode('safeclaw-e2e'),
    }, hkdfKey, 256);
    const aesKey = await crypto.subtle.importKey(
      'raw', aesKeyBits, { name: 'AES-GCM' }, false, ['encrypt']
    );

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, plaintext);
    const epk = await crypto.subtle.exportKey('jwk', ephemeral.publicKey);

    const wire = JSON.stringify({
      epk, iv: toBase64(iv), ct: toBase64(new Uint8Array(ct)),
    });
    return new TextEncoder().encode(wire);
  }

  // Response key derivation: HKDF(ikm=userKey, salt=nonce, info="safeclaw-response-v1")
  async function deriveResponseKey(userKey, nonce) {
    const keyMaterial = await crypto.subtle.importKey('raw', userKey, 'HKDF', false, ['deriveBits']);
    return crypto.subtle.deriveBits({
      name: 'HKDF', hash: 'SHA-256',
      salt: new Uint8Array(nonce),
      info: new TextEncoder().encode('safeclaw-response-v1'),
    }, keyMaterial, 256);
  }

  // AES-256-GCM decrypt (for response E2E)
  async function aesDecrypt(keyBits, sealedB64) {
    const sealed = fromBase64(sealedB64);
    const iv = sealed.slice(0, 12);
    const ct = sealed.slice(12);
    const aesKey = await crypto.subtle.importKey(
      'raw', keyBits, { name: 'AES-GCM' }, false, ['decrypt']
    );
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ct);
    return new TextDecoder().decode(plaintext);
  }

  // PRF salt for WebAuthn
  function getPrfSalt() {
    return new TextEncoder().encode('safeclaw-prf-v1');
  }

  // Convert WebAuthn assertion to serializable data
  function assertionToData(assertion) {
    return {
      authenticatorData: toBase64(new Uint8Array(assertion.response.authenticatorData)),
      clientDataJSON: toBase64(new Uint8Array(assertion.response.clientDataJSON)),
      signature: toBase64(new Uint8Array(assertion.response.signature)),
    };
  }

  // Derive PRF user_key from credential via WebAuthn PRF extension
  async function derivePRF(credential) {
    const results = credential.getClientExtensionResults();
    const prfResults = results.prf?.results;
    if (!prfResults?.first) return null;
    const rawKey = new Uint8Array(prfResults.first);
    // HKDF to normalize PRF output
    const keyMaterial = await crypto.subtle.importKey('raw', rawKey, 'HKDF', false, ['deriveBits']);
    const derived = await crypto.subtle.deriveBits({
      name: 'HKDF', hash: 'SHA-256',
      salt: new Uint8Array(32),
      info: new TextEncoder().encode('safeclaw-user-key'),
    }, keyMaterial, 256);
    return new Uint8Array(derived);
  }

  // Discoverable credential PRF derivation (for unlock/admin — no credentialId needed upfront)
  async function derivePRFDiscoverable() {
    const credential = await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rpId: location.hostname,
        userVerification: 'required',
        extensions: { prf: { eval: { first: getPrfSalt() } } },
      },
    });
    const userKey = await derivePRF(credential);
    if (!userKey) return null;
    const credentialId = toBase64(new Uint8Array(credential.rawId));
    const assertion = assertionToData(credential);
    return { userKey, credentialId, assertion };
  }

  return {
    toBase64,
    fromBase64,
    e2eEncrypt,
    deriveResponseKey,
    aesDecrypt,
    getPrfSalt,
    assertionToData,
    derivePRF,
    derivePRFDiscoverable,
  };
})();
