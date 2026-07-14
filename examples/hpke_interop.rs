//! HPKE JS↔Rust interop harness (not shipped; for validating the browser
//! seal against the daemon `open`).
//!
//!   cargo run --example hpke_interop -- gen
//!     → prints  SK=<hex>  PK=<base64url-no-pad>
//!
//!   cargo run --example hpke_interop -- open <sk_hex> <enc_b64url> <ct_b64url> <op_id>
//!     → prints  OPENED=<hex>   (the recovered plaintext)
//!
//! A node script seals a known W_c to PK with info = grant_seal_info(op_id)
//! using @hpke/core; this opens it. If OPENED matches, the suites are
//! byte-compatible and the frontend can seal grants the daemon will accept.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hpke::{Deserializable, Kem, Serializable};
use safeclaw::crypto::envelope::{grant_seal_info, ScKeyPair, SuiteKem};

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}
fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("gen") => {
            let (sk, pk) = <SuiteKem as Kem>::gen_keypair(&mut rand::rngs::OsRng);
            println!("SK={}", hex_encode(&sk.to_bytes()));
            println!("PK={}", URL_SAFE_NO_PAD.encode(pk.to_bytes()));
        }
        Some("open") => {
            let sk_hex = &args[2];
            let enc = URL_SAFE_NO_PAD.decode(&args[3]).expect("enc b64url");
            let ct = URL_SAFE_NO_PAD.decode(&args[4]).expect("ct b64url");
            let op_id = &args[5];
            let sk =
                <<SuiteKem as Kem>::PrivateKey as Deserializable>::from_bytes(&hex_decode(sk_hex))
                    .expect("sk");
            let pk = <SuiteKem as Kem>::sk_to_pk(&sk);
            let kp = ScKeyPair { sk, pk };
            let info = grant_seal_info(op_id);
            match kp.open(&enc, &ct, &info, b"") {
                Ok(pt) => println!("OPENED={}", hex_encode(&pt)),
                Err(e) => {
                    eprintln!("OPEN FAILED: {}", e);
                    std::process::exit(1);
                }
            }
        }
        _ => {
            eprintln!("usage: hpke_interop gen | open <sk_hex> <enc_b64url> <ct_b64url> <op_id>");
            std::process::exit(2);
        }
    }
}
