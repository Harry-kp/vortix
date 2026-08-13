//! Package-supplied root bootstrap for staged Background-mode enrollment.

use std::io::Write as _;

fn main() {
    let mut args = std::env::args_os();
    let _program = args.next();
    match (args.next().as_deref(), args.next()) {
        (Some(arg), None) if arg == "--version" => {
            println!("vortix-bootstrap {}", env!("CARGO_PKG_VERSION"));
        }
        (Some(arg), None) if arg == "stage" => {
            match vortix::helper::stage_package_from_reader(std::io::stdin().lock()) {
                Ok(receipt) => {
                    let mut output = std::io::stdout().lock();
                    if serde_json::to_writer(&mut output, &receipt).is_err()
                        || output.write_all(b"\n").is_err()
                    {
                        eprintln!("vortix-bootstrap could not write its staged receipt");
                        std::process::exit(74);
                    }
                }
                Err(error) => {
                    eprintln!("vortix-bootstrap refused staging: {error}");
                    std::process::exit(77);
                }
            }
        }
        _ => {
            eprintln!("usage: vortix-bootstrap --version|stage");
            std::process::exit(64);
        }
    }
}
