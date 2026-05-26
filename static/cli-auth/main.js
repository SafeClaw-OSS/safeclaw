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
const op = params.get("op") || "";        // "unlock" | "lock" | "export"
const vault = params.get("vault") || "";
const cb = params.get("cb") || "";        // CLI's localhost callback URL
const state = params.get("state") || "";  // anti-CSRF token from CLI
const exportKey = params.get("key") || ""; // for op=export: native-secrets key name

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
const KNOWN_OPS = new Set(["unlock", "lock", "export"]);
if (!KNOWN_OPS.has(op)) {
  abort(`unknown op: ${op || "(empty)"}`);
} else if (!vault) {
  abort("missing vault id (?vault=...)");
} else if (op === "export" && !exportKey) {
  abort("missing key (?key=...) for op=export");
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
const OP_LABELS = {
  unlock: "Unlock vault",
  lock: "Lock vault",
  export: `Reveal “${exportKey}”`,
};
$("op-label").textContent = OP_LABELS[op] || op;
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

// ── Op constructor ──────────────────────────────────────────────────────────
// Each known `op` URL param maps to a canonical sudp Operation. The page is
// a stateless ceremony runner — it doesn't store secrets, just shapes the
// op + drives the WebAuthn ceremony + submits the grant. New op kinds get
// a case here without touching the rest of the page.
function buildOp(op, vault, exportKey) {
  const valid = { iat: Math.floor(Date.now() / 1000), multiplicity: "one" };
  const bind = { redeemer: vault };
  switch (op) {
    case "unlock":
      return { act: { type: { custom: "vault-unlock" }, target: "", scope: null }, bind, valid };
    case "lock":
      return { act: { type: { custom: "vault-lock" }, target: "", scope: null }, bind, valid };
    case "export":
      return { act: { type: "export", target: exportKey, scope: null }, bind, valid };
    default:
      throw new Error(`unsupported op: ${op}`);
  }
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
  const opBody = buildOp(op, vault, exportKey);
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
  // Don't display the unlock/export response body (it may contain plaintext).
  // For export, the CLI will fetch the cached value via GET /op/{op_id} using
  // the op_id we hand back via the callback.
  const done = {
    unlock: "vault unlocked",
    lock: "vault locked",
    export: `revealed ${exportKey}`,
  };
  status(done[op] || "ok", "ok");
  // Return the op_id so the caller can pull the cached value (export) or
  // correlate audit (unlock/lock). Unused by unlock/lock callers — safe.
  return { op_id: created.op_id };
}

$("go-btn").addEventListener("click", async () => {
  $("go-btn").disabled = true;
  try {
    const result = await runCeremony();
    setTimeout(() => redirectBack({ status: "ok", op_id: result.op_id }), 200);
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
if (KNOWN_OPS.has(op) && vault && cb && (op !== "export" || exportKey)) {
  status("ready — click Authorize to start the passkey ceremony", "muted");
  $("go-btn").disabled = false;
}
