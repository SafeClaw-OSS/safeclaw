//! Resident certificate authority for the local credential proxy.
//!
//! The proxy is an HTTPS MITM: to decrypt a brokered connection it mints a leaf
//! certificate per destination host, signed by a CA the child process trusts
//! (via the `*_CA_*` env bundle `sc run` pastes). That CA is **resident** — a
//! keypair + self-signed cert generated once at `<state_dir>/ca.pem` (+ `ca.key`,
//! `chmod 600`), reused across daemon restarts, and NEVER installed into any
//! system trust store. The private key never leaves the machine.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use hudsucker::certificate_authority::RcgenAuthority;
use hudsucker::rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use hudsucker::rustls::crypto::aws_lc_rs;

/// The loaded resident CA plus the on-disk path of its public cert (the anchor
/// the env bundle points tools at).
pub struct ResidentCa {
    pub authority: RcgenAuthority,
    pub cert_path: PathBuf,
}

/// Load the CA from `<state_dir>/ca.pem` + `ca.key`, generating both on first
/// start. The generated key is written `chmod 600`. Errors are stringly-typed to
/// match the daemon bootstrap's error surface.
pub fn load_or_generate(state_dir: &Path) -> Result<ResidentCa, String> {
    let cert_path = state_dir.join("ca.pem");
    let key_path = state_dir.join("ca.key");

    let (cert_pem, key_pem) = if cert_path.exists() && key_path.exists() {
        let cert = fs::read_to_string(&cert_path)
            .map_err(|e| format!("read {}: {}", cert_path.display(), e))?;
        let key = fs::read_to_string(&key_path)
            .map_err(|e| format!("read {}: {}", key_path.display(), e))?;
        (cert, key)
    } else {
        let (cert, key) = generate()?;
        fs::write(&cert_path, &cert)
            .map_err(|e| format!("write {}: {}", cert_path.display(), e))?;
        fs::write(&key_path, &key).map_err(|e| format!("write {}: {}", key_path.display(), e))?;
        // The private key is a local secret — owner-read/write only.
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("chmod 600 {}: {}", key_path.display(), e))?;
        tracing::info!(ca = %cert_path.display(), "generated resident broker CA");
        (cert, key)
    };

    let key = KeyPair::from_pem(&key_pem).map_err(|e| format!("parse ca key: {}", e))?;
    let issuer =
        Issuer::from_ca_cert_pem(&cert_pem, key).map_err(|e| format!("parse ca cert: {}", e))?;
    // 1000 cached leaf configs is ample for the handful of hosts a machine's
    // agents talk to; the provider is our own aws-lc-rs (never OpenSSL).
    let authority = RcgenAuthority::new(issuer, 1000, aws_lc_rs::default_provider());
    Ok(ResidentCa {
        authority,
        cert_path,
    })
}

/// Generate a fresh self-signed CA (ECDSA P-256), returning `(cert_pem, key_pem)`.
fn generate() -> Result<(String, String), String> {
    let key = KeyPair::generate().map_err(|e| format!("generate ca key: {}", e))?;

    let mut params =
        CertificateParams::new(Vec::<String>::new()).map_err(|e| format!("ca params: {}", e))?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "SafeClaw Local Broker CA");
    dn.push(DnType::OrganizationName, "SafeClaw");
    params.distinguished_name = dn;
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];

    let cert = params
        .self_signed(&key)
        .map_err(|e| format!("self-sign ca: {}", e))?;
    Ok((cert.pem(), key.serialize_pem()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_parseable_pems() {
        let (cert, key) = generate().unwrap();
        assert!(cert.contains("BEGIN CERTIFICATE"));
        assert!(key.contains("PRIVATE KEY"));
        // Round-trips into an issuer without error.
        let kp = KeyPair::from_pem(&key).unwrap();
        Issuer::from_ca_cert_pem(&cert, kp).unwrap();
    }

    #[test]
    fn load_or_generate_is_idempotent_and_key_is_0600() {
        let dir = tempfile::tempdir().unwrap();
        let first = load_or_generate(dir.path()).unwrap();
        let cert1 = fs::read_to_string(&first.cert_path).unwrap();
        // Second call reuses the same files (no regeneration).
        let _second = load_or_generate(dir.path()).unwrap();
        let cert2 = fs::read_to_string(dir.path().join("ca.pem")).unwrap();
        assert_eq!(
            cert1, cert2,
            "CA must be reused across calls, not regenerated"
        );

        let mode = fs::metadata(dir.path().join("ca.key"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "ca.key must be owner-only");
    }
}
