//! Daemon HPKE outer envelope — `sc_pk` / `sc_sk` lifecycle (PROTOCOL.md §4.2.1 M1).
//!
//! A single X25519 keypair per daemon, **role-strict**: used only for HPKE
//! outer envelope (currently: cross-device pending-passkey seals; future:
//! grant submission confidentiality on `[HPKE: MUST]` endpoints). **Not**
//! involved in any KEK derivation or SUDP key hierarchy.
//!
//! Suite (matches PROTOCOL.md §4.2):
//!   KEM:  DHKEM(X25519, HKDF-SHA-256)
//!   KDF:  HKDF-SHA-256
//!   AEAD: ChaCha20-Poly1305
//!
//! Storage:
//!   `~/.safeclaw/crypto/sc_sk.bin` — raw 32-byte X25519 scalar
//!
//! Lifecycle: generated once on first daemon start, persists across restarts.
//! Loss = clients pinning the old `sc_pk` see a fingerprint mismatch on next
//! connect and must re-pin. Vault data is unaffected (sc_sk is NOT a KEK).

use std::fs;
use std::path::PathBuf;

use hpke::{
    aead::ChaCha20Poly1305,
    kdf::HkdfSha256,
    kem::X25519HkdfSha256,
    Deserializable, Kem, OpModeR, OpModeS, Serializable,
};
use rand::rngs::OsRng;

use crate::error::{AppError, Result};

pub type SuiteKem = X25519HkdfSha256;
pub type SuiteAead = ChaCha20Poly1305;
pub type SuiteKdf = HkdfSha256;

/// HPKE `info` prefix for sealing a grant's wrapping key `W_c` to `sc_pk`.
///
/// The browser seals `W_c` with `info = GRANT_SEAL_INFO_PREFIX ‖ 0x1f ‖ op_id`,
/// binding the seal to exactly one op so a captured seal can't be replayed
/// against a different op. Mirrors the pending-passkey info-binding precedent
/// (`approve.rs` cross-device deposit). The daemon opens with the same `info`.
pub const GRANT_SEAL_INFO_PREFIX: &[u8] = b"safeclaw/v1/grant-seal";

/// Build the grant-seal HPKE `info` bound to `op_id`. Seal and open MUST use
/// byte-identical `info` or the AEAD open fails.
pub fn grant_seal_info(op_id: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(GRANT_SEAL_INFO_PREFIX.len() + 1 + op_id.len());
    v.extend_from_slice(GRANT_SEAL_INFO_PREFIX);
    v.push(0x1f);
    v.extend_from_slice(op_id.as_bytes());
    v
}

/// HPKE single-shot seal to a recipient public key. Returns
/// `(encapped_key, ciphertext)`, both raw bytes. The daemon never needs to
/// seal in production (it only `open`s the browser's seal); this exists for
/// round-trip tests and for tooling that produces material the daemon opens.
pub fn seal_to(
    recipient_pk: &[u8],
    plaintext: &[u8],
    info: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let pk = <<SuiteKem as Kem>::PublicKey as Deserializable>::from_bytes(recipient_pk)
        .map_err(|e| AppError::BadRequest(format!("recipient pk deserialize: {}", e)))?;
    let (encapped, mut ctx) = hpke::setup_sender::<SuiteAead, SuiteKdf, SuiteKem, _>(
        &OpModeS::Base,
        &pk,
        info,
        &mut OsRng,
    )
    .map_err(|e| AppError::Internal(format!("hpke setup_sender: {}", e)))?;
    let ct = ctx
        .seal(plaintext, aad)
        .map_err(|e| AppError::Internal(format!("hpke seal: {}", e)))?;
    Ok((encapped.to_bytes().to_vec(), ct))
}

/// Daemon's static HPKE keypair, loaded once at startup.
pub struct ScKeyPair {
    pub sk: <SuiteKem as Kem>::PrivateKey,
    pub pk: <SuiteKem as Kem>::PublicKey,
}

impl ScKeyPair {
    /// Load from disk, or generate + persist if missing. Idempotent.
    pub fn load_or_generate() -> Result<Self> {
        let path = sk_path()?;
        if path.exists() {
            let bytes = fs::read(&path)
                .map_err(|e| AppError::Internal(format!("read sc_sk: {}", e)))?;
            let sk = <SuiteKem as Kem>::PrivateKey::from_bytes(&bytes)
                .map_err(|e| AppError::Internal(format!("sc_sk deserialize: {}", e)))?;
            let pk = <SuiteKem as Kem>::sk_to_pk(&sk);
            return Ok(Self { sk, pk });
        }
        // Generate fresh keypair + persist with restrictive perms.
        let (sk, pk) = <SuiteKem as Kem>::gen_keypair(&mut OsRng);
        let sk_bytes = sk.to_bytes();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| AppError::Internal(format!("mkdir crypto: {}", e)))?;
        }
        write_secret(&path, &sk_bytes)?;
        tracing::info!(path = %path.display(), "generated fresh sc_sk");
        Ok(Self { sk, pk })
    }

    /// Public key in raw 32-byte form (X25519 little-endian).
    pub fn pk_bytes(&self) -> Vec<u8> {
        self.pk.to_bytes().to_vec()
    }

    /// HPKE single-shot open. `info` MUST commit to any deployment context
    /// the sender bound the seal to (for pending-passkeys: vault_id ‖ cid).
    pub fn open(&self, encapped_key: &[u8], ciphertext: &[u8], info: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let encapped = <<SuiteKem as Kem>::EncappedKey as Deserializable>::from_bytes(encapped_key)
            .map_err(|e| AppError::BadRequest(format!("encapped_key deserialize: {}", e)))?;
        let mut ctx = hpke::setup_receiver::<SuiteAead, SuiteKdf, SuiteKem>(
            &OpModeR::Base,
            &self.sk,
            &encapped,
            info,
        )
        .map_err(|e| AppError::BadRequest(format!("hpke setup_receiver: {}", e)))?;
        ctx.open(ciphertext, aad)
            .map_err(|e| AppError::BadRequest(format!("hpke open: {}", e)))
    }
}

fn sk_path() -> Result<PathBuf> {
    let home = dirs::home_dir()
        .ok_or_else(|| AppError::Internal("no home dir".into()))?;
    Ok(home.join(".safeclaw").join("crypto").join("sc_sk.bin"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ephemeral() -> ScKeyPair {
        let (sk, pk) = <SuiteKem as Kem>::gen_keypair(&mut OsRng);
        ScKeyPair { sk, pk }
    }

    #[test]
    fn grant_seal_roundtrip() {
        let kp = ephemeral();
        let w_c = [7u8; 32];
        let info = grant_seal_info("op-abc-123");
        let (enc, ct) = seal_to(&kp.pk_bytes(), &w_c, &info, b"").unwrap();
        let opened = kp.open(&enc, &ct, &info, b"").unwrap();
        assert_eq!(opened, w_c);
    }

    #[test]
    fn grant_seal_wrong_op_id_fails() {
        // A seal bound to one op must not open under another op's info.
        let kp = ephemeral();
        let (enc, ct) = seal_to(&kp.pk_bytes(), &[9u8; 32], &grant_seal_info("op-A"), b"").unwrap();
        assert!(kp.open(&enc, &ct, &grant_seal_info("op-B"), b"").is_err());
    }

    #[test]
    fn grant_seal_wrong_key_fails() {
        let kp1 = ephemeral();
        let kp2 = ephemeral();
        let info = grant_seal_info("op-x");
        let (enc, ct) = seal_to(&kp1.pk_bytes(), &[3u8; 32], &info, b"").unwrap();
        assert!(kp2.open(&enc, &ct, &info, b"").is_err());
    }

    #[test]
    fn grant_seal_info_shape() {
        let info = grant_seal_info("zz");
        assert_eq!(&info[..GRANT_SEAL_INFO_PREFIX.len()], GRANT_SEAL_INFO_PREFIX);
        assert_eq!(info[GRANT_SEAL_INFO_PREFIX.len()], 0x1f);
        assert_eq!(&info[GRANT_SEAL_INFO_PREFIX.len() + 1..], b"zz");
    }
}

fn write_secret<B: AsRef<[u8]>>(path: &PathBuf, bytes: B) -> Result<()> {
    use std::io::Write;
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .map_err(|e| AppError::Internal(format!("create sc_sk: {}", e)))?;
    f.write_all(bytes.as_ref())
        .map_err(|e| AppError::Internal(format!("write sc_sk: {}", e)))?;
    Ok(())
}
