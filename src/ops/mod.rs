//! Ops transport (trust-reset contract 8.4): how a zero-inbound localhost
//! daemon gets a human approval from the web.
//!
//! On op creation the daemon DIALS OUT: it registers the pending op with
//! `POST /device/vaults/{vid}/ops` (DIK-signed; the backend stamps this device's
//! `dv_` and takes its enc key from the ledger), then polls
//! `GET /device/vaults/{vid}/ops/{op_id}` for the console-deposited grant and
//! applies it through the daemon's own `/op/{id}/approve` endpoint.
//!
//! The backend is blind to K: the grant carries the vault's K bundle
//! HPKE-sealed (`k_enc`/`k_ct`) to THIS device's admitted enc key, with
//! `info = grant_seal_info(op_id)`; it opens only here. A machine without a
//! device identity registers nothing.

pub mod client;

use crate::protocol::operation::OpRequester;
use crate::state::AppState;

/// The requester every op this daemon mints carries (contract 1.6): this
/// device's `dv_` and its person's `us_`. The person comes from the verified own
/// ledger, else the anchor pinned at `sc login`. `None` when this machine is not
/// paired: such a daemon cannot get an approval, so it mints no op.
pub fn own_requester(state: &AppState) -> Option<OpRequester> {
    let device = state.cloud()?.device().id().to_string();
    let member = state
        .trust
        .own_ledger()
        .map(|l| l.us().to_string())
        .or_else(|| crate::trust::own_anchor().map(|a| a.us))?;
    Some(OpRequester { device, member })
}

/// Stamp [`own_requester`] onto `op`, or refuse with the "pair first" message.
pub fn stamp_own_requester(
    state: &AppState,
    op: &mut crate::protocol::Operation,
) -> crate::error::Result<()> {
    let requester = own_requester(state)
        .ok_or_else(|| crate::error::AppError::Forbidden(crate::device::NOT_PAIRED.into()))?;
    crate::protocol::operation::stamp_requester(&mut op.act, &requester)
}

/// Pair an in-memory [`AppState`] for tests: this device (`[device_seed; 32]`
/// DIK) admitted by a person (`[person_seed; 32]` UIK) whose folded ledger is
/// the own ledger. The backend URL is a closed loopback port, so a spawned
/// register/poll fails fast and touches nothing.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::crypto::ledger::{KIND_DEVICE, OP_ADMIT};
    use crate::trust::test_support::Person;

    pub fn pair(state: &AppState, device_seed: u8, person_seed: u8) -> Person {
        pair_person(state, device_seed, Person::new(person_seed))
    }

    /// [`pair`] with a given person (e.g. a vault owner fixture).
    pub fn pair_person(state: &AppState, device_seed: u8, mut person: Person) -> Person {
        let device = crate::device::tests_support::device(device_seed);
        person.push(
            OP_ADMIT,
            KIND_DEVICE,
            device.id().to_string(),
            device.sig_pub().to_vec(),
            device.enc_pub().to_vec(),
        );
        state.trust.set_own_ledger(person.fold());
        state.set_cloud(Some(crate::cloud::DeviceClient::new(
            "http://127.0.0.1:9",
            device,
        )));
        person
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bare_state() -> AppState {
        AppState::new(crate::config::Config {
            state_dir: std::path::PathBuf::from(format!(
                "/tmp/safeclaw-test-ops-{}",
                std::process::id()
            )),
            port: 0,
            proxy_port: 0,
            listen: "127.0.0.1".into(),
            origin: "http://localhost".into(),
            rp_id: "localhost".into(),
            body_cap: crate::config::DEFAULT_BODY_CAP,
        })
    }

    /// Every minted op names this device and its person; an unpaired daemon
    /// mints none (it could never get an approval).
    #[test]
    fn ops_are_stamped_with_own_device_and_person_or_refused_unpaired() {
        use crate::protocol::operation::{op_requester, Act, ActType, Bind, Operation, Valid};
        let mk = || Operation {
            act: Act {
                kind: ActType::Export,
                target: "K".into(),
                scope: serde_json::Value::Null,
            },
            bind: Bind {
                redeemer: "v1".into(),
                recipient: None,
            },
            valid: Valid::single_use(0, Some(60)),
        };
        let state = bare_state();
        let mut op = mk();
        assert!(matches!(
            stamp_own_requester(&state, &mut op),
            Err(crate::error::AppError::Forbidden(m)) if m.contains("sc login")
        ));
        let person = test_support::pair(&state, 0x31, 0x32);
        let mut op = mk();
        stamp_own_requester(&state, &mut op).unwrap();
        let r = op_requester(&op.act).expect("stamped");
        assert_eq!(r.device, crate::device::tests_support::device(0x31).id());
        assert_eq!(r.member, person.us());
        assert!(op.act.scope.is_object(), "Export scope becomes an object");
    }
}
