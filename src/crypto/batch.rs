//! Batch-approve commitment — design/batch-approve.md.
//!
//! One WebAuthn assertion authorizes N pending ops: its challenge is
//! SHA-256(TAG ‖ root) where root is an RFC-6962-shaped Merkle root over the
//! ops' 32-byte bindings β. Leaf = SHA-256(0x00 ‖ β), node =
//! SHA-256(0x01 ‖ L ‖ R), odd node PROMOTED (never duplicated — duplication
//! reintroduces the CVE-2012-2459 `[a,b] ≡ [a,b,b]` ambiguity). The tag is
//! concatenated with NO separator (deliberately unlike binding.rs β).
//! Cross-language vectors in `batch_vectors.json` (mirrored in the console
//! repo) are the compatibility guarantee, not the library choice.

use rs_merkle::{Hasher, MerkleTree};
use sha2::{Digest, Sha256};

/// Domain tag for the batch challenge. Diverges from "safeclaw/v1/binding"
/// at byte 13, so a batch challenge can never be read as a single-op β.
pub const BATCH_TAG: &[u8] = b"safeclaw/v1/batch-approve";

/// Wire bounds (design §Commitment): enforced BEFORE loading any records.
pub const BATCH_MIN: usize = 2;
pub const BATCH_MAX: usize = 32;

/// SHA-256 with the RFC-6962 node prefix. rs_merkle's default
/// `concat_and_hash` omits the 0x01 prefix and we must never inherit a
/// silent change to its odd-node policy, so both are pinned here: prefix
/// added on every 2-child node, lone left node PROMOTED unchanged.
#[derive(Clone)]
pub struct BatchSha256;

impl Hasher for BatchSha256 {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> [u8; 32] {
        Sha256::digest(data).into()
    }

    fn concat_and_hash(left: &[u8; 32], right: Option<&[u8; 32]>) -> [u8; 32] {
        match right {
            Some(r) => {
                let mut h = Sha256::new();
                h.update([0x01]);
                h.update(left);
                h.update(r);
                h.finalize().into()
            }
            None => *left,
        }
    }
}

/// Leaf hash for one op binding: SHA-256(0x00 ‖ β). Input is the RAW
/// 32-byte β, never a hex/base64 rendering.
pub fn batch_leaf(beta: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(beta);
    h.finalize().into()
}

/// Merkle root over β_1..β_N in the batch's `op_ids` order (= the exact
/// order the console signed). Empty input has no root.
pub fn batch_root(betas: &[[u8; 32]]) -> Option<[u8; 32]> {
    if betas.is_empty() {
        return None;
    }
    let leaves: Vec<[u8; 32]> = betas.iter().map(batch_leaf).collect();
    MerkleTree::<BatchSha256>::from_leaves(&leaves).root()
}

/// The one WebAuthn challenge for the whole batch:
/// SHA-256("safeclaw/v1/batch-approve" ‖ root), no separator.
pub fn batch_challenge(root: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(BATCH_TAG);
    h.update(root);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    /// Every cross-language vector must reproduce exactly: leaves, root and
    /// challenge. The vectors file is the compatibility contract with the
    /// console's TS mirror — never regenerate it to make a test pass.
    #[test]
    fn cross_language_vectors() {
        let v: Value = serde_json::from_str(include_str!("batch_vectors.json")).unwrap();
        assert_eq!(v["tag"].as_str().unwrap().as_bytes(), BATCH_TAG);

        // Tag pin: exact no-separator concatenation over a fixed root.
        let pin_root = hex32(v["tag_pin"]["root"].as_str().unwrap());
        let pin_challenge = hex32(v["tag_pin"]["challenge"].as_str().unwrap());
        assert_eq!(batch_challenge(&pin_root), pin_challenge);

        let vectors = v["vectors"].as_array().unwrap();
        let ns: Vec<usize> = vectors
            .iter()
            .map(|c| c["n"].as_u64().unwrap() as usize)
            .collect();
        assert_eq!(ns, vec![1, 2, 3, 5, 6, 7, 11], "vector set changed");

        for case in vectors {
            let n = case["n"].as_u64().unwrap() as usize;
            let betas: Vec<[u8; 32]> = case["betas"]
                .as_array()
                .unwrap()
                .iter()
                .map(|b| hex32(b.as_str().unwrap()))
                .collect();
            assert_eq!(betas.len(), n);

            let leaves: Vec<[u8; 32]> = case["leaves"]
                .as_array()
                .unwrap()
                .iter()
                .map(|l| hex32(l.as_str().unwrap()))
                .collect();
            for (beta, want) in betas.iter().zip(&leaves) {
                assert_eq!(&batch_leaf(beta), want, "leaf mismatch at n={}", n);
            }

            let root = batch_root(&betas).unwrap();
            assert_eq!(root, hex32(case["root"].as_str().unwrap()), "root n={}", n);
            assert_eq!(
                batch_challenge(&root),
                hex32(case["challenge"].as_str().unwrap()),
                "challenge n={}",
                n
            );
        }
    }

    #[test]
    fn single_leaf_root_is_leaf() {
        let beta = [0x42u8; 32];
        assert_eq!(batch_root(&[beta]).unwrap(), batch_leaf(&beta));
    }

    #[test]
    fn empty_has_no_root() {
        assert!(batch_root(&[]).is_none());
    }

    /// Permuting the set changes the root (order is part of the commitment).
    #[test]
    fn order_changes_root() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_ne!(batch_root(&[a, b]), batch_root(&[b, a]));
    }

    /// Promotion, not duplication: [a, b] must differ from [a, b, b].
    #[test]
    fn no_duplication_ambiguity() {
        let a = [3u8; 32];
        let b = [4u8; 32];
        assert_ne!(batch_root(&[a, b]), batch_root(&[a, b, b]));
    }
}
