//! The UIK derivation (`root → signing identity, X25519 encryption key`).
//!
//! The daemon never holds a UIK: the console unwraps the person's root with a
//! passkey, signs ledger events and member records, and seals K to a device in
//! each grant (trust-reset D3, contract 1.7). What remains here is the pure
//! derivation, pinned so the daemon and the console agree on a person's keys
//! (`us_`, sign pub, enc pub), and used as the fixture that signs records and
//! ledgers in tests.
//!
//! **Iron rule:** UIK private material lives only in personal custody; it is
//! NEVER placed under a shared vault's `K`.

use zeroize::Zeroizing;

use crate::crypto::envelope::DeviceEncKey;
use crate::error::{AppError, Result};
use crate::identity::SigningIdentity;
use sudp::primitives::{Kdf, PrimitiveSuite, StdPrimitives};

/// HKDF `info` deriving the UIK Ed25519 signing seed from the root.
const UIK_IDENTITY_INFO: &[u8] = b"safeclaw/v1/uik-identity";
/// HKDF `info` deriving the UIK X25519 encryption scalar from the root.
const UIK_ENCRYPTION_INFO: &[u8] = b"safeclaw/v1/uik-encryption";

fn hkdf(root: &[u8; 32], info: &[u8]) -> [u8; 32] {
    <StdPrimitives as PrimitiveSuite>::Kdf::derive_32(root, &[], info)
        .expect("HKDF-SHA256 derive_32 is infallible for a 32-byte root")
}

/// A person's UIK root secret — the single seed all their UIK material derives
/// from. Held only in personal custody (never under a shared `K`).
pub struct UikRoot {
    root: Zeroizing<[u8; 32]>,
}

impl UikRoot {
    /// Adopt an existing 32-byte root (e.g. custody-unwrapped at unlock).
    pub fn from_root(root: [u8; 32]) -> Self {
        Self {
            root: Zeroizing::new(root),
        }
    }

    /// Mint a fresh UIK root from the OS CSPRNG (onboarding ceremony).
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut root = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut root);
        Self::from_root(root)
    }

    /// The Ed25519 signing identity (config / state signatures, no gesture).
    pub fn signing(&self) -> SigningIdentity {
        let seed = Zeroizing::new(hkdf(&self.root, UIK_IDENTITY_INFO));
        SigningIdentity::from_seed(&seed)
    }

    /// The account primary key `us_…` (self-certifying from the signing pubkey).
    pub fn user_id(&self) -> String {
        self.signing().user_id()
    }

    /// The UIK's X25519 encryption keypair (HPKE recipient for `K`).
    fn encryption_keypair(&self) -> Result<DeviceEncKey> {
        let scalar = Zeroizing::new(hkdf(&self.root, UIK_ENCRYPTION_INFO));
        DeviceEncKey::from_secret_bytes(&scalar[..])
            .map_err(|e| AppError::Internal(format!("uik x25519 sk from bytes: {}", e)))
    }

    /// The UIK's X25519 encryption PUBLIC key (raw 32 bytes) — what `K` is sealed
    /// to. Published in the keyset (cloud-visible); a member seals `K` here.
    pub fn encryption_public(&self) -> Result<Vec<u8>> {
        Ok(self.encryption_keypair()?.public_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    const ROOT: [u8; 32] = [0x33; 32];

    #[test]
    fn pinned_uik_derivation() {
        // Fixed root → stable signing pubkey / user_id / encryption pubkey. The
        // console pins the same values. Do NOT edit an
        // expected value to make this pass — find why the derivations diverged.
        let uik = UikRoot::from_root(ROOT);
        assert_eq!(
            hex(&uik.signing().public_bytes()),
            "1838406bdd286c1fe706cd570707d50dc4bd0d6e29d8e8e3beaec9ce0bd56285"
        );
        assert_eq!(uik.user_id(), "us_mzg6tb63typxzojujnvinkldck7jax6k");
        assert_eq!(
            hex(&uik.encryption_public().unwrap()),
            "9163381fc5434e03de47ffef26026b599c5a42882e1b2711ecfae861b338235a"
        );
    }
}
