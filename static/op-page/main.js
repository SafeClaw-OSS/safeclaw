// Minimal passkey-gesture page for CLI-initiated ops.
// Reads params from URL, runs navigator.credentials.get() (or create()
// for enroll), returns assertion + prf_first to CLI callback.
// No SUDP knowledge, no seal, no grant construction — CLI does all that.

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

$("op-label").textContent = opLabel;
$("vault-label").textContent = vid ? `· vault ${vid}` : "";

function status(msg, cls) {
  const el = $("status");
  el.textContent = msg;
  el.className = cls || "muted";
}

function b64urlDecode(s) {
  const std = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = std.length % 4;
  const padded = pad ? std + "=".repeat(4 - pad) : std;
  const bin = atob(padded);
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

if (!cb) abort("missing ?cb=");
else if (!challenge && !enroll) abort("missing ?challenge=");
else {
  status("ready — click Authorize", "muted");
  $("go-btn").disabled = false;
}

$("cancel-btn").addEventListener("click", () => redirectBack({ status: "cancelled" }));

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
  }
});

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
  // Extract P-256 public key (x, y) from SPKI DER returned by getPublicKey().
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
