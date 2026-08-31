//! Privileged-helper entrypoint. Before enrollment it serves only the staged
//! handshake and rejects every operation.

fn main() {
    let mut args = std::env::args_os();
    let _program = args.next();
    match (args.next().as_deref(), args.next()) {
        (Some(arg), None) if arg == "--version" => {
            println!(
                "vortix-helper {} (staged, unenrolled)",
                env!("CARGO_PKG_VERSION")
            );
        }
        (Some(arg), None) if arg == "--serve" => {
            if let Err(error) = vortix::helper::serve_staged_helper() {
                eprintln!("vortix-helper refused service startup: {error}");
                std::process::exit(78);
            }
        }
        _ => {
            eprintln!("usage: vortix-helper --version|--serve");
            std::process::exit(78);
        }
    }
}
