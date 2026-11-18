//! `WireGuard`.
//!
//! Wraps `wg-quick` for lifecycle and owns machine-readable `wg show` status
//! parsing. Scanner and control code consume typed observations only.

#![allow(clippy::missing_errors_doc)]

pub mod ownership;
pub mod parser;
pub mod receipt;
pub mod tunnel;

pub use tunnel::WgTunnel;

/// A new key pair, private then public, by `wg genkey` and `wg pubkey`.
pub fn generate_keypair() -> Result<(String, String), String> {
    use crate::process::CommandSpec;
    let run = |args: &[&str], stdin: Option<Vec<u8>>| {
        let mut spec = CommandSpec::oneshot("wg", args.iter().map(|a| (*a).into()).collect())
            .timeout(std::time::Duration::from_secs(5));
        if let Some(bytes) = stdin {
            spec = spec.stdin(bytes);
        }
        match crate::process::run(spec) {
            Ok(out) if out.success() => Ok(String::from_utf8_lossy(&out.stdout).trim().to_string()),
            _ => Err("WireGuard could not make a key (wg genkey)".to_string()),
        }
    };
    let private = run(&["genkey"], None)?;
    let public = run(&["pubkey"], Some(private.clone().into_bytes()))?;
    Ok((private, public))
}
