//! Package-supplied root bootstrap for staged Background-mode enrollment.

use std::io::Write as _;

fn main() {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        [arg] if arg == "--version" => {
            println!("vortix-bootstrap {}", env!("CARGO_PKG_VERSION"));
        }
        [arg] if arg == "stage" => {
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
        [arg] if arg == "reserve" => {
            match vortix::helper::reserve_package_from_reader(std::io::stdin().lock()) {
                Ok(receipt) => {
                    let mut output = std::io::stdout().lock();
                    if serde_json::to_writer(&mut output, &receipt).is_err()
                        || output.write_all(b"\n").is_err()
                    {
                        eprintln!("vortix-bootstrap could not write its candidate receipt");
                        std::process::exit(74);
                    }
                }
                Err(error) => {
                    eprintln!("vortix-bootstrap refused reservation: {error}");
                    std::process::exit(77);
                }
            }
        }
        [arg, epoch] if arg == "commit" => {
            let epoch = epoch
                .to_str()
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|epoch| *epoch != 0);
            let Some(epoch) = epoch else {
                eprintln!("vortix-bootstrap refused commit: authority epoch must be non-zero");
                std::process::exit(64);
            };
            match vortix::helper::commit_package_from_reader(std::io::stdin().lock(), epoch) {
                Ok(receipt) => {
                    let mut output = std::io::stdout().lock();
                    if serde_json::to_writer(&mut output, &receipt).is_err()
                        || output.write_all(b"\n").is_err()
                    {
                        eprintln!("vortix-bootstrap could not write its enrollment receipt");
                        std::process::exit(74);
                    }
                }
                Err(error) => {
                    eprintln!("vortix-bootstrap refused commit: {error}");
                    std::process::exit(77);
                }
            }
        }
        _ => {
            eprintln!("usage: vortix-bootstrap --version|stage|reserve|commit EPOCH");
            std::process::exit(64);
        }
    }
}
