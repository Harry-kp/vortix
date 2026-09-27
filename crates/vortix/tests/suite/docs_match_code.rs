//! The user docs name every command, flag and config key the code has.
//! Boundary runs this on docs-only PRs too.

use clap::CommandFactory;
use vortix::cli::args::Args;
use vortix::config::settings::{HookSpec, Settings};
use vortix::config::AppConfig;

const USAGE: &str = include_str!("../../../../docs/usage.md");
const CONFIGURATION: &str = include_str!("../../../../docs/configuration.md");

fn keys(value: &serde_json::Value) -> Vec<String> {
    value
        .as_object()
        .expect("a config struct serializes to an object")
        .keys()
        .cloned()
        .collect()
}

#[test]
fn usage_names_every_command_and_flag() {
    let cli = Args::command();
    let commands = cli
        .get_subcommands()
        .filter(|command| !command.is_hide_set())
        .map(|command| format!("vortix {}", command.get_name()));
    let flags = std::iter::once(&cli)
        .chain(cli.get_subcommands())
        .flat_map(clap::Command::get_arguments)
        .filter(|arg| !arg.is_hide_set())
        .filter_map(clap::Arg::get_long)
        .map(|long| format!("--{long}"));
    let mut missing: Vec<String> = commands
        .chain(flags)
        .filter(|name| !USAGE.contains(name.as_str()))
        .collect();
    missing.dedup();
    assert!(
        missing.is_empty(),
        "docs/usage.md does not mention {missing:?}"
    );
}

#[test]
fn configuration_names_every_config_key() {
    let settings = serde_json::to_value(Settings::default()).unwrap();
    let hook: HookSpec =
        toml::from_str("event = \"connected\"\nexecutable = \"/bin/true\"").unwrap();
    let mut all = keys(&serde_json::to_value(AppConfig::default()).unwrap());
    all.extend(keys(&settings["engine"]));
    all.extend(keys(&settings["journal"]));
    all.extend(keys(&serde_json::to_value(hook).unwrap()));
    let missing: Vec<String> = all
        .into_iter()
        .filter(|key| {
            let assignment = format!("{key} =");
            !CONFIGURATION
                .lines()
                .any(|line| line.trim_start_matches(['#', ' ']).starts_with(&assignment))
        })
        .collect();
    assert!(
        missing.is_empty(),
        "docs/configuration.md does not document {missing:?}"
    );
}
