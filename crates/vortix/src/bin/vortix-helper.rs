//! Staged privileged-helper artifact. U11 intentionally exposes no server or
//! privileged operation entrypoint.

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
        _ => {
            eprintln!(
                "vortix-helper is staged but not enrolled; it cannot serve or execute operations"
            );
            std::process::exit(78);
        }
    }
}
