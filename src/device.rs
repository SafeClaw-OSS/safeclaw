//! This machine's device identity (trust-reset design D2/D8): the DIK (Ed25519,
//! `dv_` = fold(DIK pub)) and the device encryption key (X25519). The two are one
//! pair: `sc login` mints them together, the person's ledger admits them
//! together (`admit{device, dv_, dik_pub, enc_pub}`), and `sc logout` or a
//! verified self-revoke deletes them together. Changing either key makes the
//! machine a new device that must pair again, so neither is ever regenerated on
//! its own.
//!
//! Files (0600, owned by the user, design A1):
//!   - DIK: `~/.safeclaw/device/identity` ([`crate::identity_file`]);
//!   - enc key: `~/.safeclaw/crypto/sc_sk.bin` ([`crate::crypto::envelope`]).

use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::crypto::envelope::{enc_key_path, DeviceEncKey};
use crate::device_auth::DeviceRequestSigner;
use crate::identity::{IdKind, SigningIdentity};

/// The message every device-only path shows when this machine has no device
/// identity: actionable, never a raw file error.
pub const NOT_PAIRED: &str =
    "this machine is not paired with SafeClaw (no device identity) — run `sc login`";

/// A loaded device pair.
pub struct Device {
    signer: DeviceRequestSigner,
    sig_pub: [u8; 32],
    enc: DeviceEncKey,
}

impl Device {
    /// This device's `dv_` id.
    pub fn id(&self) -> &str {
        self.signer.device_id()
    }
    /// The DIK public key.
    pub fn sig_pub(&self) -> &[u8; 32] {
        &self.sig_pub
    }
    /// The device encryption public key.
    pub fn enc_pub(&self) -> [u8; 32] {
        self.enc.public_bytes()
    }
    /// The request signer (DIK + id).
    pub fn signer(&self) -> &DeviceRequestSigner {
        &self.signer
    }
    /// The encryption key (opens grant seals).
    pub fn enc(&self) -> &DeviceEncKey {
        &self.enc
    }
}

fn dik_path() -> Result<PathBuf, String> {
    crate::identity_file::device_identity_path()
}

/// Load the device pair. `Ok(None)` when this machine has no current device
/// identity: no DIK, a pre-trust-reset `dev_` DIK (treated as absent), or a DIK
/// without its enc key (an incomplete pair is not a device). A corrupt file is
/// an error.
pub fn load_optional() -> Result<Option<Device>, String> {
    load_from(&dik_path()?, &enc_key_path().map_err(|e| e.to_string())?)
}

/// [`load_optional`] from explicit paths.
pub fn load_from(dik: &Path, enc: &Path) -> Result<Option<Device>, String> {
    let Some(loaded) = crate::identity_file::load_device(dik)? else {
        return Ok(None);
    };
    let Some(enc) = DeviceEncKey::load(enc).map_err(|e| e.to_string())? else {
        return Ok(None);
    };
    let sig_pub = loaded.identity.public_bytes();
    Ok(Some(Device {
        signer: DeviceRequestSigner::new(loaded.identity, loaded.id),
        sig_pub,
        enc,
    }))
}

/// Load the device pair or fail with [`NOT_PAIRED`].
pub fn load() -> Result<Device, String> {
    load_optional()?.ok_or_else(|| NOT_PAIRED.to_string())
}

/// A freshly minted, not yet persisted device pair (the new side of `sc login`).
pub struct MintedDevice {
    seed: Zeroizing<[u8; 32]>,
    identity: SigningIdentity,
    id: String,
    enc: DeviceEncKey,
}

impl MintedDevice {
    /// Mint a fresh DIK and enc key from the OS CSPRNG.
    pub fn generate() -> Self {
        let (seed, id) = crate::identity_file::mint(IdKind::Device);
        let (identity, _) = crate::identity_file::resolve(IdKind::Device, &seed);
        Self {
            seed,
            identity,
            id,
            enc: DeviceEncKey::generate(),
        }
    }
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn sig_pub(&self) -> [u8; 32] {
        self.identity.public_bytes()
    }
    pub fn enc_pub(&self) -> [u8; 32] {
        self.enc.public_bytes()
    }

    /// Write both keys (0600), replacing any previous device identity. Called
    /// only after the admission verified and the user confirmed.
    pub fn persist(&self) -> Result<(), String> {
        self.persist_to(&dik_path()?, &enc_key_path().map_err(|e| e.to_string())?)
    }

    /// [`Self::persist`] to explicit paths.
    pub fn persist_to(&self, dik: &Path, enc: &Path) -> Result<(), String> {
        crate::identity_file::write(dik, IdKind::Device, &self.seed)?;
        self.enc.write(enc).map_err(|e| e.to_string())
    }
}

/// Delete the DIK and the enc key (`sc logout`, a verified self-revoke). Both
/// deletions are attempted; a file that is already gone is not an error.
pub fn wipe() -> Result<(), String> {
    wipe_paths(&dik_path()?, &enc_key_path().map_err(|e| e.to_string())?)
}

/// [`wipe`] at explicit paths.
pub fn wipe_paths(dik: &Path, enc: &Path) -> Result<(), String> {
    let mut errs = Vec::new();
    for path in [dik, enc] {
        if let Err(e) = std::fs::remove_file(path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                errs.push(format!("remove {}: {}", path.display(), e));
            }
        }
    }
    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs.join("; "))
    }
}

/// Deterministic in-memory devices for tests (no files touched).
#[cfg(test)]
pub(crate) mod tests_support {
    use super::*;

    /// A device whose DIK seed is `[seed; 32]` and enc scalar `[seed ^ 0x5a; 32]`.
    pub fn device(seed: u8) -> Device {
        let (identity, id) = crate::identity_file::resolve(IdKind::Device, &[seed; 32]);
        let sig_pub = identity.public_bytes();
        Device {
            signer: DeviceRequestSigner::new(identity, id),
            sig_pub,
            enc: DeviceEncKey::from_secret_bytes(&[seed ^ 0x5a; 32]).unwrap(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_persist_load_wipe_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let dik = dir.path().join("device").join("identity");
        let enc = dir.path().join("crypto").join("sc_sk.bin");
        assert!(load_from(&dik, &enc).unwrap().is_none(), "no identity yet");

        let minted = MintedDevice::generate();
        assert!(minted.id().starts_with("dv_"));
        minted.persist_to(&dik, &enc).unwrap();
        let dev = load_from(&dik, &enc)
            .unwrap()
            .expect("persisted pair loads");
        assert_eq!(dev.id(), minted.id());
        assert_eq!(dev.sig_pub(), &minted.sig_pub());
        assert_eq!(dev.enc_pub(), minted.enc_pub());

        // A DIK without its enc key is not a device.
        std::fs::remove_file(&enc).unwrap();
        assert!(load_from(&dik, &enc).unwrap().is_none());

        // Re-persist, then wipe removes both halves; wipe is idempotent.
        minted.persist_to(&dik, &enc).unwrap();
        wipe_paths(&dik, &enc).unwrap();
        assert!(!dik.exists() && !enc.exists());
        assert!(load_from(&dik, &enc).unwrap().is_none());
        wipe_paths(&dik, &enc).unwrap();
    }

    #[test]
    fn a_fresh_mint_is_a_new_device_every_time() {
        let a = MintedDevice::generate();
        let b = MintedDevice::generate();
        assert_ne!(a.id(), b.id());
        assert_ne!(a.enc_pub(), b.enc_pub());
    }
}
