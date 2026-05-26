// SafeClaw CLI auth page — drives the passkey ceremony for `vault-unlock` and
// `vault-lock` Custom ops, then redirects back to the CLI's localhost
// callback. This is the daemon-embedded counterpart to the pro-frontend's
// vault-grant.ts unlock/lock paths, narrowed to those two ops.

import { utf8 } from "./sudp/bytes.js";
import { computeBinding } from "./sudp/binding.js";
import { deriveWrappingKey } from "./sudp/kdf.js";
import { prfToUserKey, assertionToWire } from "./sudp/webauthn.js";

// Domain separator for β. Trailing 0x00 is part of the bytes — matches
// `safeclaw/src/crypto/binding.rs` (deployment-specific domain).
const DOMAIN_STANDARD = utf8("safeclaw/v1/binding\x00");
const PRF_SALT_FOR_PRF_EVAL = utf8("safeclaw-prf-v1");
const WRAP_VERSION = 1;

// Allowed CLI callback hosts. Browser-callback mode only ever points back
// at a localhost listener on the same machine. Any other host is rejected
// to prevent a hostile link from redirecting the grant elsewhere.
const ALLOWED_CB_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]"]);

const $ = (id) => document.getElementById(id);
const status = (msg, cls) => {
  const el = $("status");
  el.textContent = msg;
  el.classList.remove("ok", "err", "muted");
  if (cls) el.classList.add(cls);
};

const params = new URLSearchParams(window.location.search);
const op = params.get("op") || "";        // "unlock" | "lock"
const vault = params.get("vault") || "";
const cb = params.get("cb") || "";        // CLI's localhost callback URL
const state = params.get("state") || "";  // anti-CSRF token from CLI

$("daemon-origin").textContent = window.location.origin;

function redirectBack(extra) {
  if (!cb) {
    status("no callback URL; nothing to redirect to", "err");
    return;
  }
  const u = new URL(cb);
  for (const [k, v] of Object.entries(extra)) u.searchParams.set(k, v);
  if (state) u.searchParams.set("state", state);
  window.location.replace(u.toString());
}

function abort(msg) {
  status(msg, "err");
  $("go-btn").disabled = true;
  redirectBack({ status: "error", error: msg.slice(0, 200) });
}

// ── Param validation ────────────────────────────────────────────────────────
if (op !== "unlock" && op !== "lock") {
  abort(`unknown op: ${op || "(empty)"}`);
} else if (!vault) {
  abort("missing vault id (?vault=...)");
} else if (!cb) {
  abort("missing CLI callback (?cb=...)");
} else {
  try {
    const cbUrl = new URL(cb);
    if (!ALLOWED_CB_HOSTS.has(cbUrl.hostname)) {
      abort(`callback host ${cbUrl.hostname} not localhost — refusing`);
    }
  } catch {
    abort("invalid callback URL");
  }
}

// ── UI summary ──────────────────────────────────────────────────────────────
$("op-label").textContent = op === "unlock" ? "Unlock vault" : "Lock vault";
$("vault-label").textContent = vault ? `· vault ${vault}` : "";

// ── Helpers ────────────────────────────────────────────────────────────────
function toBase64(u8) {
  let s = ""; for (let i = 0; i < u8.byteLength; i++) s += String.fromCharCode(u8[i]);
  return btoa(s);
}
function toBase64url(u8) {
  return toBase64(u8).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function fromBase64(b64) {
  const std = b64.replace(/-/g, "+").replace(/_/g, "/");
  const pad = std.length % 4;
  const padded = pad ? std + "=".repeat(4 - pad) : std;
  const s = atob(padded);
  const u = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) u[i] = s.charCodeAt(i);
  return u;
}
function credIdAsArrayBuffer(u8) {
  return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength);
}

// vault-crypto.ts's `assertionToWire` wrap — base64-encode every field
// (credentialId base64url, others standard base64) so the daemon's
// `WebAuthnAssertion` deserializer is happy.
function assertionToWireBase64(credential) {
  const w = assertionToWire(credential);
  return {
    credentialId: toBase64url(w.credentialId),
    authenticatorData: toBase64(w.authenticatorData),
    clientDataJSON: toBase64(w.clientDataJSON),
    signature: toBase64(w.signature),
  };
}

async function safePasskeyGet({ challenge, allowCredentials, rpId, prfSalt }) {
  const publicKey = {
    challenge,
    userVerification: "required",
    ...(rpId ? { rpId } : {}),
    ...(allowCredentials ? {
      allowCredentials: allowCredentials.map((c) => ({
        type: "public-key",
        id: c.id,
        transports: ["internal", "hybrid"],
      })),
    } : {}),
    ...(prfSalt ? { extensions: { prf: { eval: { first: prfSalt } } } } : {}),
  };
  const credential = await navigator.credentials.get({ publicKey });
  if (!credential) throw new Error("no credential returned");
  let prfFirst = null;
  if (prfSalt) {
    const ext = credential.getClientExtensionResults();
    prfFirst = ext?.prf?.results?.first;
    if (!prfFirst) throw new Error("PRF extension unavailable on this authenticator");
  }
  return { credential, prfFirst };
}

// ── The ceremony ────────────────────────────────────────────────────────────
async function runCeremony() {
  status("fetching passkeys…");
  const passkeysResp = await fetch(`/v/${encodeURIComponent(vault)}/passkeys`);
  if (!passkeysResp.ok) throw new Error(`passkeys list HTTP ${passkeysResp.status}`);
  const passkeysBody = await passkeysResp.json();
  if (!passkeysBody.vault_exists) throw new Error("no vault to authorise — has it been enrolled?");
  if (!passkeysBody.passkeys?.length) throw new Error("vault has no enrolled passkeys");
  const meta = passkeysBody.passkeys[0];
  const credIdRaw = fromBase64(meta.credential_id);

  status("creating op…");
  const opBody = {
    act: { type: { custom: op === "unlock" ? "vault-unlock" : "vault-lock" }, target: "", scope: null },
    bind: { redeemer: vault },
    valid: { iat: Math.floor(Date.now() / 1000), multiplicity: "one" },
  };
  const createResp = await fetch(`/v/${encodeURIComponent(vault)}/op`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(opBody),
  });
  if (!createResp.ok) throw new Error(`create op HTTP ${createResp.status}: ${await createResp.text()}`);
  const created = await createResp.json();
  const rRaw = fromBase64(created.r);

  status("computing binding…");
  const beta = await computeBinding(DOMAIN_STANDARD, rRaw, opBody);

  status("touch passkey…");
  const got = await safePasskeyGet({
    challenge: beta,
    allowCredentials: [{ id: credIdAsArrayBuffer(credIdRaw) }],
    prfSalt: PRF_SALT_FOR_PRF_EVAL,
    // rpId omitted — defaults to current origin's hostname; daemon's
    // SAFECLAW_RP_ID config must match.
  });
  const userKey = await prfToUserKey(new Uint8Array(got.prfFirst));
  const prfSalt = fromBase64(meta.prf_salt);
  const wrappingKey = await deriveWrappingKey(userKey, prfSalt, credIdRaw, WRAP_VERSION);

  status("submitting grant…");
  const grant = {
    o: opBody,
    r: created.r,
    credential_id: meta.credential_id,
    wrapping_key: toBase64(wrappingKey),
    assertion: assertionToWireBase64(got.credential),
  };
  const approveResp = await fetch(`/op/${encodeURIComponent(created.op_id)}/approve`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(grant),
  });
  if (!approveResp.ok) {
    const text = await approveResp.text();
    throw new Error(`approve HTTP ${approveResp.status}: ${text.slice(0, 200)}`);
  }
  // Don't display the unlock response body (it includes plaintext kv).
  // The daemon's in-memory cache is what the CLI actually wanted.
  status(op === "unlock" ? "vault unlocked" : "vault locked", "ok");
}

$("go-btn").addEventListener("click", async () => {
  $("go-btn").disabled = true;
  try {
    await runCeremony();
    setTimeout(() => redirectBack({ status: "ok" }), 200);
  } catch (e) {
    const msg = String(e?.message || e);
    status(msg, "err");
    setTimeout(() => redirectBack({ status: "error", error: msg.slice(0, 200) }), 200);
  }
});
$("cancel-btn").addEventListener("click", () => {
  redirectBack({ status: "cancelled" });
});

// Auto-enable the button once initial validation passed.
if (op === "unlock" || op === "lock") {
  if (vault && cb) {
    status("ready — click Authorize to start the passkey ceremony", "muted");
    $("go-btn").disabled = false;
  }
}
