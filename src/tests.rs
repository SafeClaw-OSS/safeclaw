//! Ceremony-level integration tests for SafeClaw v2.
//!
//! **Test layering** (see PROTOCOL-v2.md §11):
//!
//! - **Layer 1: Primitive unit tests** live inside each crypto module
//!   (`aead::tests`, `kdf::tests`, `canonical::tests`, `binding::tests`,
//!   `vault_file::tests`, `wrapped_deks::tests`). They test one function
//!   at a time and do not cross module boundaries.
//!
//! - **Layer 2: Ceremony integration tests** live here, in `src/tests.rs`.
//!   They exercise multiple crypto modules together, emulating the full
//!   setup / unlock / write / add-passkey / remove-passkey / forward-secrecy
//!   ceremonies without going through Axum handlers. This is where the
//!   Option D invariant is verified end-to-end.
//!
//! - **Layer 3: HTTP-level integration tests** (planned, not yet written)
//!   would live in `tests/` (Cargo's integration test directory) and would
//!   boot the full Axum router to send real HTTP requests against a WebAuthn
//!   mock. Deferred until the mock infrastructure is written.
//!
//! Tests here deliberately avoid duplicating what Layer 1 already covers.
//! If you are adding a test for a single-function invariant, add it to the
//! relevant module's `#[cfg(test)] mod tests`, not here.

#[cfg(test)]
mod tests {
    // ── Test helpers ─────────────────────────────────────────────────────────

    /// Tiny temp-directory helper that deletes itself on drop. Avoids pulling
    /// in the `tempfile` crate as a new dependency.
    pub(super) struct TempDir {
        path: std::path::PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let pid = std::process::id();
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let p = std::env::temp_dir().join(format!("safeclaw-test-{}-{}", pid, nanos));
            std::fs::create_dir_all(&p).unwrap();
            Self { path: p }
        }

        pub fn path(&self) -> &std::path::Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    pub(super) fn tempdir() -> TempDir {
        TempDir::new()
    }

    // ── Ceremony-level integration ───────────────────────────────────────────

    mod ceremony {
        use super::{tempdir, TempDir as _TempDir};
        use crate::crypto::{
            generate_dek,
            kdf::{derive_kek, WRAP_VERSION},
            vault_file::{decrypt_vault, encrypt_vault},
            wrapped_deks::{
                unwrap_dek, wrap_dek_for_credential, wrap_dek_with_kek, DekWrapManifest,
            },
        };
        use base64::{engine::general_purpose::STANDARD, Engine};
        use serde_json::json;

        #[test]
        fn option_d_two_credentials() {
            // Two credentials, both initially registered with their own prf_salt.
            // Credential A performs a write: rotates A's salt, rotates DEK,
            // rewraps for both A (new KEK) and B (cached peer KEK from peer_keks).
            // B should still be able to unlock after A's write.

            let cid_a = b"cred-a";
            let cid_b = b"cred-b";

            let user_key_a = [0xAAu8; 32];
            let user_key_b = [0xBBu8; 32];

            let salt_a_0 = [0x01u8; 32];
            let salt_b = [0x02u8; 32];

            let kek_a_0 = derive_kek(&user_key_a, &salt_a_0, WRAP_VERSION, cid_a).unwrap();
            let kek_b = derive_kek(&user_key_b, &salt_b, WRAP_VERSION, cid_b).unwrap();

            // Initial DEK and vault.
            let dek_0 = generate_dek();
            let vault_0 = json!({
                "services": {},
                "files": [],
                "peer_keks": {
                    STANDARD.encode(cid_a): STANDARD.encode(&kek_a_0),
                    STANDARD.encode(cid_b): STANDARD.encode(&kek_b),
                }
            });
            let vault_bytes_0 = serde_json::to_vec(&vault_0).unwrap();
            let enc_0 = encrypt_vault(&dek_0, &vault_bytes_0).unwrap();

            // Initial wrapped_deks manifest.
            let mut manifest = DekWrapManifest::new();
            manifest
                .entries
                .push(wrap_dek_for_credential(&dek_0, &user_key_a, &salt_a_0, cid_a).unwrap());
            manifest
                .entries
                .push(wrap_dek_for_credential(&dek_0, &user_key_b, &salt_b, cid_b).unwrap());

            // --- A performs a write ---
            // A unwraps its entry.
            let entry_a = manifest.find(cid_a).unwrap();
            let dek_from_a = unwrap_dek(entry_a, &user_key_a).unwrap();
            assert_eq!(dek_from_a, dek_0);

            // Decrypt current vault.
            let plain_0 = decrypt_vault(&dek_from_a, &enc_0).unwrap();
            let mut vault_value: serde_json::Value = serde_json::from_slice(&plain_0).unwrap();

            // Mutate.
            vault_value["services"]["openai"] = json!({"auth": "sk-xxx"});

            // Rotate A's salt, derive new KEK.
            let salt_a_1 = [0x11u8; 32];
            let user_key_a_next = [0xCCu8; 32]; // simulating PRF with new salt
            let kek_a_1 =
                derive_kek(&user_key_a_next, &salt_a_1, WRAP_VERSION, cid_a).unwrap();

            // Update peer_keks in vault plaintext.
            vault_value["peer_keks"][STANDARD.encode(cid_a)] =
                json!(STANDARD.encode(&kek_a_1));

            // New DEK.
            let dek_1 = generate_dek();

            // Re-encrypt vault.
            let new_plain = serde_json::to_vec(&vault_value).unwrap();
            let enc_1 = encrypt_vault(&dek_1, &new_plain).unwrap();

            // Re-wrap both entries.
            let mut new_manifest = DekWrapManifest::new();
            new_manifest.entries.push(
                wrap_dek_with_kek(&dek_1, &kek_a_1, &salt_a_1, cid_a).unwrap(),
            );
            // For B, use the cached peer KEK from peer_keks (which equals kek_b).
            new_manifest
                .entries
                .push(wrap_dek_with_kek(&dek_1, &kek_b, &salt_b, cid_b).unwrap());

            // --- B later unlocks ---
            let entry_b = new_manifest.find(cid_b).unwrap();
            let dek_from_b = unwrap_dek(entry_b, &user_key_b).unwrap();
            assert_eq!(dek_from_b, dek_1);
            let plain_from_b = decrypt_vault(&dek_from_b, &enc_1).unwrap();
            let v: serde_json::Value = serde_json::from_slice(&plain_from_b).unwrap();
            assert_eq!(
                v["services"]["openai"]["auth"].as_str().unwrap(),
                "sk-xxx"
            );

            // --- A's old rawPRF (for salt_a_0) should NOT unwrap A's new entry ---
            let entry_a_new = new_manifest.find(cid_a).unwrap();
            assert!(unwrap_dek(entry_a_new, &user_key_a).is_err());
        }

        #[test]
        fn forward_secrecy_past_backup_current_rawprf() {
            // Scenario: attacker has a past backup of dek_wraps.bin for
            // credential A (taken at time T0) and somehow obtains A's CURRENT
            // rawPRF (at time T1, after A has done a write and rotated its salt).
            // Attacker should NOT be able to unwrap the past wrapped entry.
            //
            // This verifies the narrow-window forward secrecy that v2 provides
            // via per-credential prf_salt rotation.

            let cid = b"cred";
            let user_key_t0 = [0xAAu8; 32];
            let salt_t0 = [0x01u8; 32];
            let dek_t0 = generate_dek();

            let entry_t0 =
                wrap_dek_for_credential(&dek_t0, &user_key_t0, &salt_t0, cid).unwrap();

            // Time passes, A performs a write, rotates salt.
            let user_key_t1 = [0xBBu8; 32]; // new PRF output under new salt
            let salt_t1 = [0x02u8; 32];
            let dek_t1 = generate_dek();
            let entry_t1 =
                wrap_dek_for_credential(&dek_t1, &user_key_t1, &salt_t1, cid).unwrap();

            // Attacker has: past wrapped entry `entry_t0` + current rawPRF `user_key_t1`.
            //   - Current rawPRF does not match past salt; entry_t0 should not unwrap.
            assert!(
                unwrap_dek(&entry_t0, &user_key_t1).is_err(),
                "current rawPRF must not unwrap past wrapped entry"
            );

            // Sanity: past rawPRF does unwrap the past entry (the scenario we
            // explicitly cannot protect against is past disk + past rawPRF).
            assert!(unwrap_dek(&entry_t0, &user_key_t0).is_ok());
            // And current rawPRF unwraps the current entry (expected).
            assert!(unwrap_dek(&entry_t1, &user_key_t1).is_ok());
        }

        #[test]
        fn full_write_path_e2e_on_disk() {
            // End-to-end ceremony: set up a v2 vault on a temporary directory,
            // unlock it, perform a write, and verify disk state is consistent
            // after the atomic commit.

            use crate::crypto::vault_file::save_atomic as save_vault;
            use crate::crypto::dek_wraps::{wrap_dek_with_kek, DekWrapManifest};

            let tmp = tempdir();
            let data_dir = tmp.path();

            // --- Setup: one credential, one vault ---
            let cid = b"setup-cred";
            let user_key = [0x77u8; 32];
            let salt_0 = [0x11u8; 32];

            let dek_0 = generate_dek();
            let kek_0 =
                derive_kek(&user_key, &salt_0, WRAP_VERSION, cid).unwrap();

            // Build initial plaintext with peer_keks.
            let plaintext_0 = json!({
                "services": {},
                "peer_keks": {
                    STANDARD.encode(cid): STANDARD.encode(&kek_0),
                }
            });
            let plain_bytes = serde_json::to_vec(&plaintext_0).unwrap();

            save_vault(&data_dir.join("vault.enc"), &dek_0, &plain_bytes).unwrap();

            let mut manifest = DekWrapManifest::new();
            manifest
                .entries
                .push(wrap_dek_for_credential(&dek_0, &user_key, &salt_0, cid).unwrap());
            manifest
                .save_atomic(&data_dir.join("dek_wraps.bin"))
                .unwrap();

            // --- Unlock: read files from disk and decrypt ---
            let loaded = DekWrapManifest::load(&data_dir.join("dek_wraps.bin")).unwrap();
            assert_eq!(loaded.entries.len(), 1);
            assert_eq!(loaded.entries[0].credential_id, cid);

            let dek = unwrap_dek(loaded.find(cid).unwrap(), &user_key).unwrap();
            assert_eq!(dek, dek_0);

            let enc_on_disk = std::fs::read(data_dir.join("vault.enc")).unwrap();
            let plain = decrypt_vault(&dek, &enc_on_disk).unwrap();
            let v: serde_json::Value = serde_json::from_slice(&plain).unwrap();
            assert!(v.get("peer_keks").is_some());

            // --- Write: rotate credential, install new DEK, atomic commit ---
            let salt_1 = [0x22u8; 32];
            let user_key_1 = [0x88u8; 32];
            let kek_1 = derive_kek(&user_key_1, &salt_1, WRAP_VERSION, cid).unwrap();
            let dek_1 = generate_dek();

            let mut v2_plain = v.clone();
            v2_plain["services"]["openai"] = json!({"auth": "sk-new"});
            v2_plain["peer_keks"][STANDARD.encode(cid)] = json!(STANDARD.encode(&kek_1));
            let v2_bytes = serde_json::to_vec(&v2_plain).unwrap();

            save_vault(&data_dir.join("vault.enc"), &dek_1, &v2_bytes).unwrap();

            let mut new_manifest = DekWrapManifest::new();
            new_manifest
                .entries
                .push(wrap_dek_with_kek(&dek_1, &kek_1, &salt_1, cid).unwrap());
            new_manifest
                .save_atomic(&data_dir.join("dek_wraps.bin"))
                .unwrap();

            // --- Unlock with new credentials, verify services mutation ---
            let loaded2 = DekWrapManifest::load(&data_dir.join("dek_wraps.bin")).unwrap();
            let dek2 = unwrap_dek(loaded2.find(cid).unwrap(), &user_key_1).unwrap();
            assert_eq!(dek2, dek_1);
            let enc2 = std::fs::read(data_dir.join("vault.enc")).unwrap();
            let plain2 = decrypt_vault(&dek2, &enc2).unwrap();
            let v2: serde_json::Value = serde_json::from_slice(&plain2).unwrap();
            assert_eq!(
                v2["services"]["openai"]["auth"].as_str().unwrap(),
                "sk-new"
            );

            // Old user_key must NOT unlock the new vault.
            assert!(unwrap_dek(loaded2.find(cid).unwrap(), &user_key).is_err());
        }

        #[test]
        fn add_passkey_ceremony() {
            // Register credential A initially, then add credential B.
            // Verify both can unlock the (same) DEK.

            let cid_a = b"a";
            let cid_b = b"new-b";
            let uk_a = [0x11u8; 32];
            let uk_b = [0x22u8; 32];
            let salt_a = [0xAAu8; 32];
            let salt_b = [0xBBu8; 32];

            let dek = generate_dek();

            // A's initial manifest.
            let mut manifest = DekWrapManifest::new();
            manifest
                .entries
                .push(wrap_dek_for_credential(&dek, &uk_a, &salt_a, cid_a).unwrap());

            // --- Add B: compute B's KEK, wrap DEK for B, append entry ---
            let kek_b = derive_kek(&uk_b, &salt_b, WRAP_VERSION, cid_b).unwrap();
            manifest
                .entries
                .push(wrap_dek_with_kek(&dek, &kek_b, &salt_b, cid_b).unwrap());

            // Both credentials should unwrap the same DEK.
            let dek_via_a = unwrap_dek(manifest.find(cid_a).unwrap(), &uk_a).unwrap();
            let dek_via_b = unwrap_dek(manifest.find(cid_b).unwrap(), &uk_b).unwrap();
            assert_eq!(dek_via_a, dek);
            assert_eq!(dek_via_b, dek);
        }

        #[test]
        fn remove_passkey_ceremony() {
            // Register two credentials; remove one; verify the removed
            // credential no longer appears in the manifest and the remaining
            // one still unlocks.

            let cid_a = b"keep";
            let cid_b = b"remove";
            let uk_a = [0x11u8; 32];
            let uk_b = [0x22u8; 32];
            let salt_a = [0xAAu8; 32];
            let salt_b = [0xBBu8; 32];

            let dek = generate_dek();
            let mut manifest = DekWrapManifest::new();
            manifest
                .entries
                .push(wrap_dek_for_credential(&dek, &uk_a, &salt_a, cid_a).unwrap());
            manifest
                .entries
                .push(wrap_dek_for_credential(&dek, &uk_b, &salt_b, cid_b).unwrap());
            assert_eq!(manifest.entries.len(), 2);

            // Remove B.
            let removed = manifest.remove(cid_b);
            assert!(removed);
            assert_eq!(manifest.entries.len(), 1);
            assert!(manifest.find(cid_a).is_some());
            assert!(manifest.find(cid_b).is_none());

            // A still unlocks.
            let got = unwrap_dek(manifest.find(cid_a).unwrap(), &uk_a).unwrap();
            assert_eq!(got, dek);
        }
    }

}
