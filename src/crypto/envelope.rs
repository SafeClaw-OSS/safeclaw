//! The device encryption key (trust-reset design D2: a device's pair is its DIK
//! plus this X25519 key) and the HPKE suite every grant seal uses.
//!
//! A grant delivers the vault's K bundle HPKE-sealed to the requesting
//! device's admitted `enc_pub` with `info = grant_seal_info(op_id)` (contract
//! 1.7); the daemon opens it here. The key is minted by `sc login` together with
//! the DIK, admitted into the person's ledger with it, and deleted by
//! `sc logout`. It is never regenerated behind the ledger's back: changing it
//! makes the machine a new device that must pair again.
//!
//! Suite (contract 0):
//!   KEM:  DHKEM(X25519, HKDF-SHA-256)
//!   KDF:  HKDF-SHA-256
//!   AEAD: ChaCha20-Poly1305
//!
//! Storage: `~/.safeclaw/crypto/sc_sk.bin`, the raw 32-byte X25519 scalar, 0600.

use std::fs;
use std::path::{Path, PathBuf};

use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, Kem, OpModeR,
    OpModeS, Serializable,
};
use rand::rngs::OsRng;

use crate::error::{AppError, Result};

pub type SuiteKem = X25519HkdfSha256;
pub type SuiteAead = ChaCha20Poly1305;
pub type SuiteKdf = HkdfSha256;

/// HPKE `info` prefix for sealing a grant's K bundle to the requesting device.
///
/// The console seals with `info = GRANT_SEAL_INFO_PREFIX ‖ 0x1f ‖ op_id`, binding
/// the seal to exactly one op so a captured seal can't be replayed against a
/// different op. The daemon opens with the same `info`.
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
/// `(encapped_key, ciphertext)`, both raw bytes. The daemon never seals a grant
/// in production (it only opens the console's seal); this exists for round-trip
/// tests and for tooling that produces material the daemon opens.
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

/// The device's X25519 encryption key (the `enc_pub` half of the device pair).
pub struct DeviceEncKey {
    sk: <SuiteKem as Kem>::PrivateKey,
    pk: <SuiteKem as Kem>::PublicKey,
}

impl DeviceEncKey {
    /// Mint a fresh key from the OS CSPRNG. Nothing is written.
    pub fn generate() -> Self {
        let (sk, pk) = <SuiteKem as Kem>::gen_keypair(&mut OsRng);
        Self { sk, pk }
    }

    /// Adopt a raw 32-byte X25519 scalar.
    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self> {
        let sk = <SuiteKem as Kem>::PrivateKey::from_bytes(bytes)
            .map_err(|e| AppError::Internal(format!("device enc key: {}", e)))?;
        let pk = <SuiteKem as Kem>::sk_to_pk(&sk);
        Ok(Self { sk, pk })
    }

    /// Load the key at `path`. `Ok(None)` when the file does not exist.
    pub fn load(path: &Path) -> Result<Option<Self>> {
        match fs::read(path) {
            Ok(bytes) => Self::from_secret_bytes(&bytes).map(Some),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(AppError::Internal(format!(
                "read {}: {}",
                path.display(),
                e
            ))),
        }
    }

    /// Persist the key at `path` (0600), replacing any previous key.
    pub fn write(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| AppError::Internal(format!("mkdir {}: {}", parent.display(), e)))?;
        }
        let _ = fs::remove_file(path);
        write_secret(path, self.sk.to_bytes())
    }

    /// The public key in raw 32-byte form (X25519 little-endian).
    pub fn public_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.pk.to_bytes());
        out
    }

    /// HPKE single-shot open. `info` must equal the sender's (for a grant:
    /// [`grant_seal_info`] of the op id).
    pub fn open(
        &self,
        encapped_key: &[u8],
        ciphertext: &[u8],
        info: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
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

/// `~/.safeclaw/crypto/sc_sk.bin`, the device encryption key.
pub fn enc_key_path() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| AppError::Internal("no home dir".into()))?;
    Ok(home.join(".safeclaw").join("crypto").join("sc_sk.bin"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ephemeral() -> DeviceEncKey {
        DeviceEncKey::generate()
    }

    #[test]
    fn grant_seal_roundtrip() {
        let kp = ephemeral();
        let w_c = [7u8; 32];
        let info = grant_seal_info("op-abc-123");
        let (enc, ct) = seal_to(&kp.public_bytes(), &w_c, &info, b"").unwrap();
        let opened = kp.open(&enc, &ct, &info, b"").unwrap();
        assert_eq!(opened, w_c);
    }

    #[test]
    fn grant_seal_wrong_op_id_fails() {
        // A seal bound to one op must not open under another op's info.
        let kp = ephemeral();
        let (enc, ct) = seal_to(
            &kp.public_bytes(),
            &[9u8; 32],
            &grant_seal_info("op-A"),
            b"",
        )
        .unwrap();
        assert!(kp.open(&enc, &ct, &grant_seal_info("op-B"), b"").is_err());
    }

    #[test]
    fn grant_seal_wrong_key_fails() {
        let kp1 = ephemeral();
        let kp2 = ephemeral();
        let info = grant_seal_info("op-x");
        let (enc, ct) = seal_to(&kp1.public_bytes(), &[3u8; 32], &info, b"").unwrap();
        assert!(kp2.open(&enc, &ct, &info, b"").is_err());
    }

    #[test]
    fn grant_seal_info_shape() {
        let info = grant_seal_info("zz");
        assert_eq!(
            &info[..GRANT_SEAL_INFO_PREFIX.len()],
            GRANT_SEAL_INFO_PREFIX
        );
        assert_eq!(info[GRANT_SEAL_INFO_PREFIX.len()], 0x1f);
        assert_eq!(&info[GRANT_SEAL_INFO_PREFIX.len() + 1..], b"zz");
    }
}

fn write_secret<B: AsRef<[u8]>>(path: &Path, bytes: B) -> Result<()> {
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
        .map_err(|e| AppError::Internal(format!("create {}: {}", path.display(), e)))?;
    f.write_all(bytes.as_ref())
        .map_err(|e| AppError::Internal(format!("write {}: {}", path.display(), e)))?;
    Ok(())
}
