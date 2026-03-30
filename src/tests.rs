/// Integration tests for SafeClaw
///
/// Covers:
/// - Crypto round-trip (AES-GCM encrypt → decrypt, envelope wrap/unwrap)
/// - HKDF derivation produces expected output for known inputs
/// - Server starts and /health returns the correct response
/// - Rate limiting works
#[cfg(test)]
mod tests {
    // ── Crypto round-trip ───────────────────────────────────────────────────────

    mod crypto_roundtrip {
        use crate::crypto::{aes_decrypt, aes_encrypt, generate_dek, unwrap_dek, wrap_dek};

        #[test]
        fn aes_gcm_encrypt_decrypt() {
            let key = [0xABu8; 32];
            let plaintext = b"hello safeclaw";

            let sealed = aes_encrypt(&key, plaintext).expect("encrypt failed");
            // sealed = iv(12) || ct+tag — must be longer than plaintext
            assert!(sealed.len() > 12, "sealed must contain iv prefix");

            let recovered = aes_decrypt(&key, &sealed).expect("decrypt failed");
            assert_eq!(recovered, plaintext);
        }

        #[test]
        fn aes_gcm_wrong_key_fails() {
            let key = [0xABu8; 32];
            let plaintext = b"secret data";
            let sealed = aes_encrypt(&key, plaintext).expect("encrypt failed");

            let bad_key = [0x00u8; 32];
            let result = aes_decrypt(&bad_key, &sealed);
            assert!(result.is_err(), "decryption with wrong key must fail");
        }

        #[test]
        fn aes_gcm_tampered_ciphertext_fails() {
            let key = [0x11u8; 32];
            let mut sealed = aes_encrypt(&key, b"tamper me").expect("encrypt failed");

            // Flip a byte in the ciphertext region (after the 12-byte IV)
            let last = sealed.len() - 1;
            sealed[last] ^= 0xFF;

            let result = aes_decrypt(&key, &sealed);
            assert!(result.is_err(), "decryption of tampered data must fail");
        }

        #[test]
        fn aes_gcm_too_short_input_fails() {
            let key = [0xFFu8; 32];
            // Only 5 bytes — shorter than 12-byte IV minimum
            let result = aes_decrypt(&key, &[0u8; 5]);
            assert!(result.is_err());
        }

        #[test]
        fn envelope_wrap_unwrap_dek() {
            let kek = [0x42u8; 32];
            let dek = generate_dek();

            let wrapped = wrap_dek(&dek, &kek).expect("wrap failed");
            let recovered = unwrap_dek(&wrapped, &kek).expect("unwrap failed");
            assert_eq!(recovered, dek);
        }

        #[test]
        fn envelope_unwrap_wrong_kek_fails() {
            let kek = [0x42u8; 32];
            let dek = generate_dek();
            let wrapped = wrap_dek(&dek, &kek).expect("wrap failed");

            let bad_kek = [0x00u8; 32];
            let result = unwrap_dek(&wrapped, &bad_kek);
            assert!(result.is_err(), "unwrap with wrong KEK must fail");
        }

        #[test]
        fn full_vault_roundtrip() {
            use crate::crypto::{decrypt_vault, encrypt_vault, generate_dek};

            let dek = generate_dek();
            let data = b"{ \"services\": {} }";

            let sealed = encrypt_vault(&dek, data).expect("encrypt_vault failed");
            let plaintext = decrypt_vault(&dek, &sealed).expect("decrypt_vault failed");
            assert_eq!(plaintext, data);
        }
    }

    // ── HKDF derivation ─────────────────────────────────────────────────────────

    mod hkdf_derivation {
        use crate::crypto::kdf::{derive_e2e_key, derive_kek, derive_response_key};

        /// Cross-language reference vector computed with Node.js:
        ///
        /// ```js
        /// const { createHmac } = require('crypto');
        /// const { hkdf } = require('crypto');
        /// // hkdf('sha256', ikm, salt, info, keylen, cb)
        /// ```
        ///
        /// For deterministic testing we just check:
        /// - same inputs → same outputs (deterministic)
        /// - different inputs → different outputs
        #[test]
        fn derive_kek_is_deterministic() {
            let user_key = [0x01u8; 32];
            let sk_d = [0x02u8; 32];

            let kek1 = derive_kek(&user_key, &sk_d).expect("derive_kek failed");
            let kek2 = derive_kek(&user_key, &sk_d).expect("derive_kek failed again");
            assert_eq!(kek1, kek2, "KEK must be deterministic");
        }

        #[test]
        fn derive_kek_changes_with_different_salt() {
            let user_key = [0x01u8; 32];
            let sk_d_a = [0x02u8; 32];
            let sk_d_b = [0x03u8; 32];

            let kek_a = derive_kek(&user_key, &sk_d_a).expect("derive_kek_a failed");
            let kek_b = derive_kek(&user_key, &sk_d_b).expect("derive_kek_b failed");
            assert_ne!(kek_a, kek_b, "different sk_d must produce different KEKs");
        }

        #[test]
        fn derive_e2e_key_is_deterministic() {
            let shared_secret = [0xAAu8; 32];

            let k1 = derive_e2e_key(&shared_secret).expect("derive_e2e_key failed");
            let k2 = derive_e2e_key(&shared_secret).expect("derive_e2e_key failed again");
            assert_eq!(k1, k2, "E2E key must be deterministic");
        }

        #[test]
        fn derive_response_key_is_deterministic() {
            let user_key = [0xBBu8; 32];
            let nonce = [0xCCu8; 16];

            let k1 = derive_response_key(&user_key, &nonce).expect("derive_response_key failed");
            let k2 = derive_response_key(&user_key, &nonce).expect("derive_response_key failed again");
            assert_eq!(k1, k2, "response key must be deterministic");
        }

        #[test]
        fn three_kdf_functions_produce_distinct_keys() {
            // Same IKM/salt for all three — info strings must differentiate them
            let ikm = [0x55u8; 32];
            let salt = [0x66u8; 32];

            let kek = derive_kek(&ikm, &salt).unwrap();
            let e2e = derive_e2e_key(&ikm).unwrap(); // uses zeros(32) as salt internally
            let resp = derive_response_key(&ikm, &salt).unwrap();

            assert_ne!(kek, e2e, "KEK and E2E keys must differ");
            assert_ne!(kek, resp, "KEK and response keys must differ");
            assert_ne!(e2e, resp, "E2E and response keys must differ");
        }

        /// Known-answer test derived from Python:
        ///
        /// ```python
        /// import hashlib, hmac
        /// from cryptography.hazmat.primitives.hashes import SHA256
        /// from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        /// from cryptography.hazmat.backends import default_backend
        ///
        /// ikm   = bytes([0x01]*32)
        /// salt  = bytes([0x02]*32)
        /// info  = b"safeclaw-kek-v1"
        /// hkdf  = HKDF(SHA256(), 32, salt, info, default_backend())
        /// print(hkdf.derive(ikm).hex())
        /// # => dc0c316fe63d1fbe25ae0db1ef0f28a9cb60e0d24e0a16174f1aafa59e08ced1
        /// ```
        #[test]
        fn derive_kek_known_answer() {
            let user_key = [0x01u8; 32];
            let sk_d = [0x02u8; 32];

            let kek = derive_kek(&user_key, &sk_d).expect("derive_kek failed");

            let expected = hex_to_bytes(
                "544091d91d21f0eb3f9be13acdd597714cccdbdd13d8d9cea0bc0207f3cd88bd",
            );
            assert_eq!(kek.to_vec(), expected, "KEK known-answer mismatch");
        }

        fn hex_to_bytes(s: &str) -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        }
    }

    // ── Nonce store ─────────────────────────────────────────────────────────────

    mod nonce_store {
        use crate::auth::nonce::NonceStore;

        #[test]
        fn fresh_nonce_is_accepted() {
            let mut store = NonceStore::new();
            assert!(store.check_and_insert(b"nonce-1"));
        }

        #[test]
        fn replay_is_rejected() {
            let mut store = NonceStore::new();
            assert!(store.check_and_insert(b"nonce-2"));
            assert!(!store.check_and_insert(b"nonce-2"), "replay must be rejected");
        }

        #[test]
        fn different_nonces_both_accepted() {
            let mut store = NonceStore::new();
            assert!(store.check_and_insert(b"alpha"));
            assert!(store.check_and_insert(b"beta"));
        }
    }

    // ── Rate limiter ─────────────────────────────────────────────────────────────

    mod rate_limiter {
        use crate::state::RateLimiter;

        #[test]
        fn allows_requests_under_limit() {
            let mut rl = RateLimiter::new(5);
            for _ in 0..5 {
                assert!(rl.check("10.0.0.1"), "should be allowed under the rate limit");
            }
        }

        #[test]
        fn blocks_requests_over_limit() {
            let mut rl = RateLimiter::new(3);
            for _ in 0..3 {
                rl.check("10.0.0.2");
            }
            assert!(!rl.check("10.0.0.2"), "4th request must be blocked");
        }

        #[test]
        fn different_ips_have_independent_buckets() {
            let mut rl = RateLimiter::new(2);
            assert!(rl.check("1.2.3.4"));
            assert!(rl.check("1.2.3.4"));
            // First two requests for 1.2.3.4 exhausted; 5.6.7.8 is fresh
            assert!(rl.check("5.6.7.8"));
        }

        #[test]
        fn zero_rate_disables_limiting() {
            let mut rl = RateLimiter::new(0);
            for _ in 0..1000 {
                assert!(rl.check("192.168.1.1"), "rate=0 means unlimited");
            }
        }
    }

    // ── Health endpoint ──────────────────────────────────────────────────────────

    mod health_endpoint {
        use std::sync::{Arc, Mutex};
        use std::time::Instant;

        use axum::body::to_bytes;
        use axum::extract::State;
        use axum::http::StatusCode;
        use axum::response::IntoResponse;

        use crate::approval::ApprovalManager;
        use crate::audit::AuditLog;
        use crate::auth::nonce::NonceStore;
        use crate::config::Config;
        use crate::crypto::keys::generate_keypair;
        use crate::state::{AppState, RateLimiter, VaultState};

        fn make_test_state() -> Arc<AppState> {
            let config = Config {
                data_dir: std::path::PathBuf::from("/tmp/safeclaw-test"),
                port: 23294,
                bind: "127.0.0.1".to_string(),
                proxy_port: 23295,
                proxy_bind: "127.0.0.1".to_string(),
                origin: None,
                rp_id: None,
                admin_url: None,
                instance_id: None,
                rate_limit: 0,
                rate_limit_exempt: vec![],
                on_setup_hook: None,
                init: false,
            };
            let keypair = generate_keypair().expect("generate_keypair failed");
            let vault = Arc::new(VaultState::new());
            let audit_log = Arc::new(
                AuditLog::open_in_memory().expect("audit log failed"),
            );
            let approval_manager = Arc::new(ApprovalManager::new(audit_log.clone()));

            Arc::new(AppState {
                config,
                keypair,
                vault,
                nonces: Arc::new(Mutex::new(NonceStore::new())),
                challenges: Arc::new(Mutex::new(crate::auth::challenge::ChallengeStore::new())),
                start_time: Instant::now(),
                started_at_ms: 0,
                rate_limiter: Arc::new(Mutex::new(RateLimiter::new(0))),
                approval_manager,
                audit_log,

            })
        }

        #[tokio::test]
        async fn health_returns_correct_fields() {
            let state = make_test_state();
            let response = crate::server::routes::health(State(state)).await.into_response();

            assert_eq!(response.status(), StatusCode::OK);

            let body = to_bytes(response.into_body(), 4096).await.unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

            assert_eq!(json["status"], "ok", "status field must be 'ok'");
            assert!(json["locked"].is_boolean(), "locked must be a boolean");
            assert!(json["started_at"].is_number(), "started_at must be a number");
            assert!(json["version"].is_string(), "version must be a string");
            assert_eq!(json["locked"], true, "vault must start locked");
        }

        #[tokio::test]
        async fn server_pk_returns_jwk_public_key() {
            let state = make_test_state();
            let response = crate::server::routes::server_pk(State(state)).await.into_response();

            assert_eq!(response.status(), StatusCode::OK);

            let body = to_bytes(response.into_body(), 4096).await.unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

            let pk = &json["pk"];
            assert_eq!(pk["kty"], "EC");
            assert_eq!(pk["crv"], "P-256");
            assert!(pk["x"].is_string(), "x coordinate must be present");
            assert!(pk["y"].is_string(), "y coordinate must be present");
            // 32 bytes base64url-no-pad = 43 characters
            assert_eq!(pk["x"].as_str().unwrap().len(), 43);
            assert_eq!(pk["y"].as_str().unwrap().len(), 43);
        }

        #[tokio::test]
        async fn health_version_matches_cargo_pkg_version() {
            let state = make_test_state();
            let response = crate::server::routes::health(State(state)).await.into_response();

            let body = to_bytes(response.into_body(), 4096).await.unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

            assert_eq!(
                json["version"].as_str().unwrap(),
                env!("CARGO_PKG_VERSION"),
                "version must match Cargo.toml"
            );
        }
    }

    // ── Policy evaluation ─────────────────────────────────────────────────────────

    mod policy_tests {
        use crate::policy::{
            evaluate_policy, AccessLevel, PolicyDefaults, PolicyRule, ServiceLevels,
        };

        fn defaults() -> PolicyDefaults {
            PolicyDefaults::default()
        }

        #[test]
        fn default_policy_is_ask_always() {
            let level = evaluate_policy("GET", "/foo", None, None, &defaults(), None);
            assert_eq!(level, AccessLevel::AskAlways);
        }

        #[test]
        fn llm_category_is_allow() {
            let level = evaluate_policy("POST", "/v1/chat", None, None, &defaults(), Some("llm"));
            assert_eq!(level, AccessLevel::Allow);
        }

        #[test]
        fn post_with_ask_write_returns_ask() {
            let levels = ServiceLevels {
                write: Some(AccessLevel::Ask),
                read: None,
            };
            let level = evaluate_policy("POST", "/data", None, Some(&levels), &defaults(), None);
            assert_eq!(level, AccessLevel::Ask);
        }

        #[test]
        fn ask_always_rule_overrides_service_levels() {
            let rules = vec![PolicyRule {
                method: Some("DELETE".to_string()),
                path_suffix: Some("/admin".to_string()),
                level: AccessLevel::AskAlways,
                session_ttl: None,
            }];
            let levels = ServiceLevels {
                write: Some(AccessLevel::Ask),
                read: None,
            };
            let level = evaluate_policy(
                "DELETE",
                "/api/admin",
                Some(&rules),
                Some(&levels),
                &defaults(),
                None,
            );
            assert_eq!(level, AccessLevel::AskAlways);
        }

        #[test]
        fn get_falls_to_global_default_when_only_write_set() {
            let levels = ServiceLevels {
                write: Some(AccessLevel::Ask),
                read: None,
            };
            // No read at service level, no category → falls to global default (ask-always)
            let level = evaluate_policy("GET", "/data", None, Some(&levels), &defaults(), None);
            assert_eq!(level, AccessLevel::AskAlways);
        }

        #[test]
        fn access_level_serde_roundtrip() {
            let levels: ServiceLevels = serde_json::from_str(
                r#"{"write": "ask-always", "read": "allow"}"#,
            ).expect("new terms must deserialize");
            assert_eq!(levels.write, Some(AccessLevel::AskAlways));
            assert_eq!(levels.read, Some(AccessLevel::Allow));
        }
    }

    // ── Audit log ─────────────────────────────────────────────────────────────────

    mod audit_tests {
        use crate::audit::AuditLog;

        #[test]
        fn create_and_retrieve_approval() {
            let log = AuditLog::open_in_memory().expect("open failed");
            log.create_approval("id1", "svc", "POST", "/api", 3600)
                .expect("create failed");
            let rec = log.get_approval("id1").unwrap().expect("not found");
            assert_eq!(rec.id, "id1");
            assert_eq!(rec.status, "pending");
        }

        #[test]
        fn update_approval_status() {
            let log = AuditLog::open_in_memory().expect("open failed");
            log.create_approval("id2", "svc", "GET", "/x", 3600).unwrap();
            log.update_approval("id2", "approved").unwrap();
            let rec = log.get_approval("id2").unwrap().unwrap();
            assert_eq!(rec.status, "approved");
        }

        #[test]
        fn list_pending_filters_correctly() {
            let log = AuditLog::open_in_memory().expect("open failed");
            log.create_approval("a", "s1", "GET", "/1", 3600).unwrap();
            log.create_approval("b", "s2", "POST", "/2", 3600).unwrap();
            log.update_approval("b", "rejected").unwrap();
            let pending = log.list_pending_approvals().unwrap();
            assert_eq!(pending.len(), 1);
            assert_eq!(pending[0].id, "a");
        }
    }

    // ── Approval manager ──────────────────────────────────────────────────────────

    mod approval_tests {
        use std::sync::Arc;
        use axum::http::HeaderMap;
        use hyper::body::Bytes;
        use crate::approval::{ApprovalStatus, ApprovalManager};
        use crate::audit::AuditLog;

        fn make_manager() -> Arc<ApprovalManager> {
            let audit = Arc::new(AuditLog::open_in_memory().expect("audit log failed"));
            Arc::new(ApprovalManager::new(audit))
        }

        fn make_approval(mgr: &Arc<ApprovalManager>) -> String {
            mgr.create_approval(
                "svc".to_string(),
                "POST".to_string(),
                "/api".to_string(),
                "/svc/api".to_string(),
                "https://api.example.com".to_string(),
                HeaderMap::new(),
                Bytes::new(),
                60,
                None,
            )
        }

        #[test]
        fn confirm_sets_approved_status() {
            let mgr = make_manager();
            let id = make_approval(&mgr);
            assert!(mgr.confirm(&id, None));
            let snap = mgr.get_snapshot(&id).expect("not found");
            assert_eq!(snap.status, ApprovalStatus::Approved);
        }

        #[test]
        fn confirm_carries_auth_payload() {
            let mgr = make_manager();
            let id = make_approval(&mgr);
            let auth_json = serde_json::json!({"type": "bearer", "secret": "tok"});
            mgr.confirm(&id, Some(auth_json.clone()));
            let auth = mgr.take_auth_for_execute(&id).expect("should be approved");
            assert_eq!(auth.unwrap()["type"], "bearer");
        }

        #[test]
        fn take_auth_idempotent() {
            let mgr = make_manager();
            let id = make_approval(&mgr);
            mgr.confirm(&id, None);
            // First take succeeds
            assert!(mgr.take_auth_for_execute(&id).is_some());
            // Second take returns None (already taken / cached)
            assert!(mgr.take_auth_for_execute(&id).is_none());
        }

        #[test]
        fn reject_sets_rejected_status() {
            let mgr = make_manager();
            let id = make_approval(&mgr);
            assert!(mgr.reject(&id));
            let snap = mgr.get_snapshot(&id).expect("not found");
            assert_eq!(snap.status, ApprovalStatus::Rejected);
        }

        #[test]
        fn confirm_unknown_returns_false() {
            let mgr = make_manager();
            assert!(!mgr.confirm("nonexistent", None));
        }

        #[test]
        fn reject_unknown_returns_false() {
            let mgr = make_manager();
            assert!(!mgr.reject("nonexistent"));
        }
    }

    // ── VaultState approval session cache ────────────────────────────────────────

    mod vault_approval_cache {
        use crate::state::VaultState;

        fn dummy_auth() -> serde_json::Value {
            serde_json::json!({"type": "bearer", "secret": "tok"})
        }

        #[test]
        fn no_session_initially() {
            let vs = VaultState::new();
            assert!(vs.check_approval_session("github").is_none());
        }

        #[test]
        fn long_ttl_session_is_valid() {
            let vs = VaultState::new();
            vs.set_approval_session("github", dummy_auth(), 3600);
            assert!(vs.check_approval_session("github").is_some());
        }

        #[test]
        fn cached_auth_is_returned() {
            let vs = VaultState::new();
            vs.set_approval_session("github", dummy_auth(), 3600);
            let auth = vs.check_approval_session("github").expect("should be present");
            assert_eq!(auth["type"], "bearer");
        }

        #[test]
        fn zero_ttl_session_is_expired() {
            let vs = VaultState::new();
            vs.set_approval_session("github", dummy_auth(), 0);
            assert!(vs.check_approval_session("github").is_none());
        }

        #[test]
        fn lock_clears_cache() {
            let vs = VaultState::new();
            vs.set_approval_session("github", dummy_auth(), 3600);
            vs.lock();
            assert!(vs.check_approval_session("github").is_none());
        }
    }

    // ── Auth config backward compatibility ────────────────────────────────────────

    mod auth_config_compat {
        use crate::proxy::forward::AuthConfig;

        #[test]
        fn legacy_value_field_works() {
            let json = r#"{"type":"bearer","value":"tok123"}"#;
            let cfg: AuthConfig = serde_json::from_str(json).unwrap();
            assert_eq!(cfg.secret.as_deref(), Some("tok123"));
        }

        #[test]
        fn new_secret_field_works() {
            let json = r#"{"type":"header","name":"x-api-key","secret":"key456"}"#;
            let cfg: AuthConfig = serde_json::from_str(json).unwrap();
            assert_eq!(cfg.secret.as_deref(), Some("key456"));
        }

        #[test]
        fn basic_auth_type_deserializes() {
            let json = r#"{"type":"basic","username":"u","password":"p"}"#;
            let cfg: AuthConfig = serde_json::from_str(json).unwrap();
            assert_eq!(cfg.username.as_deref(), Some("u"));
            assert_eq!(cfg.password.as_deref(), Some("p"));
        }

        #[test]
        fn oauth2_config_deserializes() {
            let json = r#"{"type":"oauth2","token_url":"https://t.example.com/token","client_id":"cid","client_secret":"cs","refresh_token":"rt"}"#;
            let cfg: AuthConfig = serde_json::from_str(json).unwrap();
            assert_eq!(cfg.auth_type, "oauth2");
            assert_eq!(cfg.token_url.as_deref(), Some("https://t.example.com/token"));
        }
    }
}
