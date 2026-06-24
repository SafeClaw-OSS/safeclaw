// Passkey-gesture page for SafeClaw ops.
//
// Two modes depending on URL params:
//
// CLI flow (cb present):  CLI opens this page with ?challenge=&cred_id=&cb=
//   → run navigator.credentials.get() → redirect result to localhost callback.
//   All SUDP computation (HKDF, canonical binding) runs in the CLI process.
//
// Browser-direct flow (no cb):  Human opens approve_url issued by an
//   agent-initiated Use op.  No CLI process is waiting.
//   → fetch op JSON, compute β + wrappingKey in-browser, POST /approve directly.

const ALLOWED_CB = new Set(["127.0.0.1", "localhost", "[::1]"]);
const $ = id => document.getElementById(id);

const p = new URLSearchParams(location.search);
const challenge = p.get("challenge");    // base64url β (from CLI)
const prfSalt = p.get("prf_salt");       // base64url η_c (optional — only for unlock-class ops)
const credId = p.get("cred_id");         // base64url credential_id
const vid = p.get("vid");                // vault id (for display + passkey list fallback)
const cb = p.get("cb");                  // CLI localhost callback
const state = p.get("state");            // CSRF token
const opLabel = p.get("label") || "CLI operation";
const enroll = p.get("enroll") === "1";  // if true, run create() instead of get()

$("op-label").textContent = vid ? "…" : opLabel;
$("vault-label").textContent = vid ? `· vault ${vid}` : "";

function status(msg, cls) {
  const el = $("status");
  el.textContent = msg;
  el.className = cls || "muted";
}

// ─── shared byte helpers ──────────────────────────────────────────────────────

function b64urlDecode(s) {
  const std = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = std.length % 4;
  const padded = pad ? std + "=".repeat(4 - pad) : std;
  const bin = atob(padded);
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}
function b64Decode(s) {
  const bin = atob(s);
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}
function b64encode(u8) {
  let s = ""; for (let i = 0; i < u8.byteLength; i++) s += String.fromCharCode(u8[i]);
  return btoa(s);
}
function b64urlEncode(u8) {
  return b64encode(u8).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function toAB(u8) { return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength); }
function utf8(s) { return new TextEncoder().encode(s); }
function concat(...arrays) {
  let total = 0;
  for (const a of arrays) total += a.byteLength;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    out.set(new Uint8Array(a instanceof ArrayBuffer ? a : a.buffer.slice(a.byteOffset, a.byteOffset + a.byteLength)), off);
    off += a.byteLength;
  }
  return out;
}

async function sha256(data) {
  const buf = await crypto.subtle.digest("SHA-256", data instanceof Uint8Array ? toAB(data) : data);
  return new Uint8Array(buf);
}

async function hkdf(ikm, salt, info, len = 32) {
  const km = await crypto.subtle.importKey("raw", ikm instanceof Uint8Array ? toAB(ikm) : ikm, "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: salt instanceof Uint8Array ? toAB(salt) : salt, info: info instanceof Uint8Array ? toAB(info) : info }, km, len * 8);
  return new Uint8Array(bits);
}

// ─── canonical JSON (JCS subset) ─────────────────────────────────────────────
// Must match sudp::canonical::canonicalize_strict. Rejects floats.

function canonicalStr(v) {
  if (v === null || v === undefined) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new Error("canonical: non-finite number");
    if (!Number.isInteger(v)) throw new Error("canonical: float not allowed");
    return v.toString();
  }
  if (typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canonicalStr).join(",") + "]";
  if (typeof v === "object") {
    const keys = Object.keys(v).sort();
    return "{" + keys.map(k => JSON.stringify(k) + ":" + canonicalStr(v[k])).join(",") + "}";
  }
  throw new Error("canonical: unsupported type " + typeof v);
}
function canonical(obj) { return utf8(canonicalStr(obj)); }

// ─── CLI flow helpers ─────────────────────────────────────────────────────────

function redirectBack(params) {
  if (!cb) return;
  try {
    const u = new URL(cb);
    if (!ALLOWED_CB.has(u.hostname)) { status("callback not localhost", "err"); return; }
    for (const [k, v] of Object.entries(params)) u.searchParams.set(k, v);
    if (state) u.searchParams.set("state", state);
    location.replace(u.toString());
  } catch { status("invalid callback URL", "err"); }
}

function abort(msg) { status(msg, "err"); redirectBack({ status: "error", error: msg.slice(0, 200) }); }

// ─── mode dispatch ────────────────────────────────────────────────────────────

if (!cb) {
  // Browser-direct approval flow (agent-initiated op, no CLI waiting).
  initBrowserApprove();
} else if (!challenge && !enroll) {
  abort("missing ?challenge=");
} else {
  status("ready — click Authorize", "muted");
  $("go-btn").disabled = false;
}

$("cancel-btn").addEventListener("click", () => {
  if (cb) redirectBack({ status: "cancelled" });
  else { status("Cancelled.", "muted"); }
});

$("go-btn").addEventListener("click", async () => {
  $("go-btn").disabled = true;
  $("cancel-btn").disabled = true;
  try {
    if (enroll) {
      await runEnroll();
    } else {
      await runAssertion();
    }
  } catch (e) {
    const msg = String(e?.message || e);
    status(msg, "err");
    redirectBack({ status: "error", error: msg.slice(0, 200) });
    $("cancel-btn").disabled = false;
  }
});

// ─── CLI assertion ────────────────────────────────────────────────────────────

async function runAssertion() {
  status("touch passkey…");
  const challengeBytes = b64urlDecode(challenge);
  const publicKey = {
    challenge: toAB(challengeBytes),
    userVerification: "required",
  };
  if (credId) {
    publicKey.allowCredentials = [{ type: "public-key", id: toAB(b64urlDecode(credId)), transports: ["internal", "hybrid"] }];
  }
  if (prfSalt) {
    publicKey.extensions = { prf: { eval: { first: toAB(b64urlDecode(prfSalt)) } } };
  }
  const cred = await navigator.credentials.get({ publicKey });
  if (!cred) throw new Error("no credential returned");

  const resp = cred.response;
  const result = {
    status: "ok",
    credential_id: b64urlEncode(new Uint8Array(cred.rawId)),
    authenticator_data: b64encode(new Uint8Array(resp.authenticatorData)),
    client_data_json: b64encode(new Uint8Array(resp.clientDataJSON)),
    signature: b64encode(new Uint8Array(resp.signature)),
  };
  if (prfSalt) {
    const ext = cred.getClientExtensionResults();
    const prfFirst = ext?.prf?.results?.first;
    if (!prfFirst) throw new Error("PRF unavailable on this authenticator");
    result.prf_first = b64urlEncode(new Uint8Array(prfFirst));
  }
  status("ok", "ok");
  redirectBack(result);
}

// ─── CLI enroll ───────────────────────────────────────────────────────────────

async function runEnroll() {
  status("create passkey…");
  const challengeBytes = challenge ? b64urlDecode(challenge) : crypto.getRandomValues(new Uint8Array(32));
  const userId = vid ? new TextEncoder().encode(vid) : crypto.getRandomValues(new Uint8Array(16));
  const prfExt = prfSalt ? { prf: { eval: { first: toAB(b64urlDecode(prfSalt)) } } } : {};
  const publicKey = {
    challenge: toAB(challengeBytes),
    rp: { name: "SafeClaw" },
    user: { id: toAB(userId), name: vid || "vault", displayName: vid || "SafeClaw Vault" },
    pubKeyCredParams: [{ alg: -7, type: "public-key" }],
    authenticatorSelection: { residentKey: "required", userVerification: "required" },
    extensions: prfExt,
  };
  const cred = await navigator.credentials.create({ publicKey });
  if (!cred) throw new Error("no credential created");

  const resp = cred.response;
  // P-256 SPKI = 26-byte header + 0x04 + 32-byte x + 32-byte y (91 bytes total).
  const spki = new Uint8Array(resp.getPublicKey());
  if (spki.length < 91 || spki[26] !== 0x04) throw new Error("unexpected SPKI format (expected P-256 uncompressed)");
  const x = spki.slice(27, 59);
  const y = spki.slice(59, 91);

  const result = {
    status: "ok",
    credential_id: b64urlEncode(new Uint8Array(cred.rawId)),
    public_key_x: b64encode(x),
    public_key_y: b64encode(y),
    attestation_object: b64encode(new Uint8Array(resp.attestationObject)),
    client_data_json: b64encode(new Uint8Array(resp.clientDataJSON)),
  };
  const ext = cred.getClientExtensionResults();
  const prfFirst = ext?.prf?.results?.first;
  if (prfFirst) result.prf_first = b64urlEncode(new Uint8Array(prfFirst));
  status("ok", "ok");
  redirectBack(result);
}

// ─── browser-direct approval (no CLI) ────────────────────────────────────────
//
// Used when a human opens approve_url from a 202 response to an agent's
// Use request. No CLI process is waiting; after the passkey gesture we
// POST the grant directly to /op/{id}/approve and show success in-page.
//
// KDF chain (mirrors safeclaw CLI + vault-grant.ts):
//   userKey     = HKDF-SHA256(ikm=prf_first, salt=[0]×32, info="sudp/v1/webauthn-prf-userkey")
//   wrappingKey = HKDF-SHA256(ikm=userKey, salt=prf_salt, info="sudp/v1/wrap" ‖ credId ‖ [0,1])
//
// Binding (matches binding.rs / vault-crypto.ts):
//   β = SHA-256("safeclaw/v1/binding\x00" ‖ r_bytes ‖ SHA-256(canonical(op)))

const PRF_EVAL_SALT = utf8("safeclaw-prf-v1");
const DOMAIN_STANDARD = utf8("safeclaw/v1/binding\x00");
const DS_WRAP = utf8("sudp/v1/wrap");
const WRAP_VER = new Uint8Array([0x00, 0x01]);
const USER_KEY_INFO_PREFIX = utf8("sudp/v1/webauthn-prf-userkey");

async function initBrowserApprove() {
  // Extract op_id from /op/{op_id}
  const opId = location.pathname.replace(/\/$/, "").split("/").pop();
  if (!opId) { status("cannot determine op_id from URL", "err"); return; }

  status("Loading…");

  let opData;
  try {
    const resp = await fetch(location.pathname, { headers: { Accept: "application/json" } });
    if (!resp.ok) throw new Error(`GET /op/${opId} returned ${resp.status}`);
    opData = await resp.json();
  } catch (e) {
    status("Failed to load op: " + e.message, "err");
    return;
  }

  if (opData.status === "consumed") {
    $("op-label").textContent = "Already approved";
    status("This approval has already been used.", "muted");
    return;
  }
  if (opData.status === "rejected") {
    $("op-label").textContent = "Rejected";
    status("This approval was rejected.", "muted");
    return;
  }
  if (opData.status !== "pending") {
    $("op-label").textContent = opData.act || "Operation";
    status("Status: " + opData.status, "muted");
    return;
  }

  const op = opData.op;
  const vaultId = op?.bind?.redeemer;
  if (!vaultId) { status("cannot determine vault from op.bind.redeemer", "err"); return; }

  $("op-label").textContent = opData.display || opData.act || "Authorize";
  $("vault-label").textContent = `· vault ${vaultId}`;
  const expiresAt = opData.expires_at;
  if (expiresAt) {
    const secsLeft = expiresAt - Math.floor(Date.now() / 1000);
    const mins = Math.floor(secsLeft / 60);
    const secs = secsLeft % 60;
    status(secsLeft > 0 ? `ready — expires in ${mins}m ${secs}s` : "op may be expired", secsLeft > 0 ? "muted" : "err");
  } else {
    status("ready — click Authorize", "muted");
  }
  $("go-btn").disabled = false;

  $("go-btn").onclick = async () => {
    $("go-btn").disabled = true;
    $("cancel-btn").disabled = true;
    try {
      await runBrowserApprove(opId, opData, vaultId);
    } catch (e) {
      status(String(e?.message || e), "err");
      $("cancel-btn").disabled = false;
    }
  };
}

async function runBrowserApprove(opId, opData, vaultId) {
  // Re-validate op is still pending before the expensive passkey gesture.
  status("Checking op status…");
  try {
    const check = await fetch(location.pathname, { headers: { Accept: "application/json" } });
    if (!check.ok) throw new Error(`${check.status}`);
    const fresh = await check.json();
    if (fresh.status !== "pending") {
      throw new Error(`Op is ${fresh.status} — cannot approve.`);
    }
  } catch (e) {
    throw new Error("Op no longer valid: " + e.message + ". Ask the agent to retry.");
  }
  status("Fetching passkey info…");

  const pkResp = await fetch(`/v/${encodeURIComponent(vaultId)}/passkeys`);
  if (!pkResp.ok) throw new Error(`/passkeys returned ${pkResp.status}`);
  const pkData = await pkResp.json();

  if (!pkData.vault_exists || !pkData.passkeys?.length) {
    throw new Error("No passkeys enrolled for this vault.");
  }
  const meta = pkData.passkeys[0];
  const credIdBytes = b64urlDecode(meta.credential_id);
  const prfSaltBytes = b64Decode(meta.prf_salt);

  // Compute β = SHA-256(DOMAIN_STANDARD ‖ r_bytes ‖ SHA-256(canonical(op)))
  const rBytes = b64Decode(opData.r);
  const opHash = await sha256(canonical(opData.op));
  const beta = await sha256(concat(DOMAIN_STANDARD, rBytes, opHash));

  status("Touch your passkey to approve…");

  const publicKey = {
    challenge: toAB(beta),
    userVerification: "required",
    allowCredentials: [{ type: "public-key", id: toAB(credIdBytes), transports: ["internal", "hybrid"] }],
    extensions: { prf: { eval: { first: toAB(PRF_EVAL_SALT) } } },
  };
  const cred = await navigator.credentials.get({ publicKey });
  if (!cred) throw new Error("No credential returned.");

  const ext = cred.getClientExtensionResults();
  const prfFirst = ext?.prf?.results?.first;
  if (!prfFirst) throw new Error("PRF unavailable on this authenticator.");

  // Derive wrappingKey
  // userKey = HKDF(ikm=prf_first, salt=[0]×32, info="sudp/v1/webauthn-prf-userkey")
  const userKey = await hkdf(new Uint8Array(prfFirst), new Uint8Array(32), USER_KEY_INFO_PREFIX);
  // wrappingKey = HKDF(ikm=userKey, salt=prf_salt, info="sudp/v1/wrap" ‖ credId ‖ [0,1])
  const wkInfo = concat(DS_WRAP, credIdBytes, WRAP_VER);
  const wrappingKey = await hkdf(userKey, prfSaltBytes, wkInfo);

  const resp = cred.response;
  const grant = {
    o: opData.op,
    r: opData.r,
    credential_id: b64urlEncode(new Uint8Array(cred.rawId)),
    wrapping_key: b64encode(wrappingKey),
    assertion: {
      authenticator_data: b64encode(new Uint8Array(resp.authenticatorData)),
      client_data_json: b64encode(new Uint8Array(resp.clientDataJSON)),
      signature: b64encode(new Uint8Array(resp.signature)),
    },
  };

  status("Submitting…");

  const approveResp = await fetch(`/op/${opId}/approve`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(grant),
  });

  if (!approveResp.ok) {
    const body = await approveResp.text().catch(() => "");
    throw new Error(`Approve failed (${approveResp.status}): ${body}`);
  }

  status("✓ Approved — you can close this tab.", "ok");
  $("go-btn").textContent = "Done";
}
