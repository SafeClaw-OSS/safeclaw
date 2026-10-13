//! Fuzz target: the one gate that turns untrusted definition text into a
//! `ServiceDef`. Any input must be admitted or rejected, never panic or hang.
//! A NUL byte splits the input into service.toml and policy.toml, so both
//! files and their cross-checks are exercised.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = match text.split_once('\0') {
        Some((service, policy)) => safeclaw::service::gate::admit(None, service, Some(policy)),
        None => safeclaw::service::gate::admit(None, &text, None),
    };
});
