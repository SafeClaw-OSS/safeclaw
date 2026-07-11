//! `-v` / `-vv` / `-vvv` verbosity for the short-lived CLI verbs (curl-style).
//!
//! Off by default so a command's normal output stays clean. When asked, install
//! a stderr tracing subscriber; the `tracing-log` bridge is on, so reqwest's and
//! hyper's own `log` records surface too (which is where the useful "using proxy
//! X / connecting to Y" detail lives when debugging egress). `serve` installs its
//! OWN subscriber (long-running, different defaults), so this is CLI-only. An
//! explicit `RUST_LOG` still wins over the `-v` level.

/// `-v` count → env-filter directive. `None` at 0 = no subscriber (quiet).
fn filter_for(verbose: u8) -> Option<&'static str> {
    match verbose {
        0 => None,
        1 => Some("info"),
        2 => Some("debug"),
        _ => Some("trace"),
    }
}

/// Install the stderr subscriber for a CLI verb per the `-v` count. No-op at 0.
/// Best-effort: a double init (shouldn't happen off the CLI path) is ignored.
pub fn init_cli(verbose: u8) {
    let Some(default) = filter_for(verbose) else {
        return;
    };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default));
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(filter)
        // Module targets are noise at low verbosity; show them only at -vvv.
        .with_target(verbose >= 3)
        .try_init();
}

/// The env-filter `serve` should use given a `-v` count (0 = the daemon's normal
/// default). Lets `sc serve -vv` raise the daemon's own logging.
pub fn serve_filter(verbose: u8) -> String {
    match verbose {
        0 => "info,safeclaw=debug,tower_http=info".into(),
        1 => "info,safeclaw=debug,tower_http=debug".into(),
        2 => "debug".into(),
        _ => "trace".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_ladder() {
        assert_eq!(filter_for(0), None);
        assert_eq!(filter_for(1), Some("info"));
        assert_eq!(filter_for(2), Some("debug"));
        assert_eq!(filter_for(9), Some("trace"));
    }
}
