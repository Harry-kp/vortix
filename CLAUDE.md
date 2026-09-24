# Vortix — context for Claude Code

Vortix is a terminal VPN manager (TUI + CLI) for WireGuard and OpenVPN on macOS
and Linux. One Rust crate, `crates/vortix`, plus `crates/xtask` for boundary
lints. It runs as root (`sudo vortix`); there is no helper or daemon.

**Read [`STOPOVERENGINEERING.md`](STOPOVERENGINEERING.md) before writing code.**

To fix a reported bug end to end (reproduce → fix → CI → PR → review → merge),
run `/fix-bug <issue number, URL or description>`.

## How we work here

- **Less code, fewer files, fewer bugs.** Deleting is the best change. Before
  adding a helper, search: it probably exists (`rg "fn name"`). One owner per
  concept; a second copy of a rule is a future bug.
- **Fix the root, not the symptom.** Grep every caller of what you touch and fix
  it once where all paths meet. No per-caller guards, no layered patches.
- **User-visible behaviour does not change unless asked.** Refactors keep every
  CLI flag, JSON field, TUI label and exit code.
- **Remove stale code** instead of working around it. Before calling something
  dead, read the *full* grep output — truncated output has fooled us twice.
- **Comments:** default none; one short line when the *why* is not obvious.
  No plan IDs, ticket codes or phase names in code, help text or logs.
- **No new dependencies, traits with one impl, builders, or Cargo features**
  without asking.

## Commands

```bash
cargo build -p vortix                 # debug build → target/debug/vortix (use this for testing)
cargo test -p vortix <filter>         # focused tests while iterating
scripts/ci-local.sh --quick           # what CI runs (fmt, clippy, test, doc, xtask, Linux cross-clippy)
scripts/ci-local.sh                   # same + release build; run before every push
```

`ci-local.sh` is the only pre-push check that counts; see
[`docs/ci-parity.md`](docs/ci-parity.md) for why each step exists. Linux-only
code (`linux/`, `cfg(target_os = "linux")`) is only compiled by its Linux
cross-clippy step and only *run* by CI's Docker integration tests. Release
builds only when asked.

## Where things live

| Symptom / area | Look in |
|---|---|
| Connect, disconnect, switch, reconnect, retries | `control/engine.rs` (one thread), `control/state.rs` (tunnel state, route-conflict rule) |
| Which routes / DNS / firewall the host should have | `control/plan.rs` (pure), applied by `control/net.rs` |
| Kill switch modes and persisted state | `control/killswitch.rs`; firewalls in `macos/firewall.rs` (pf), `linux/firewall.rs` (nftables) |
| DNS | `control/dns.rs` (policy), `control/dns_policy.rs` (receipt), `macos/dns.rs`, `linux/dns.rs` |
| Detecting running tunnels | `control/scanner.rs` |
| Starting protocol processes | `control/tunnels.rs` → `wireguard/tunnel.rs`, `openvpn/tunnel.rs`; supervision in `process/custodian.rs` |
| Config parsing | `wireguard/parser.rs`, `openvpn/parser.rs` (the only readers of profile files) |
| Profiles on disk, import, rename, delete | `config/profiles.rs`, `config/profile_store.rs`, `config/import.rs` |
| Settings, config dir, file ownership under sudo | `config/settings.rs`, `config/mod.rs`, `config/owned_file.rs`, `config/secret.rs` |
| TUI state and keys | `app/` (`input.rs` keys, `update.rs` messages, `connection.rs` engine snapshot → render view) |
| TUI rendering | `ui/dashboard/*`, `ui/overlays.rs`, `ui/theme.rs`, `ui/helpers.rs` (formatting) |
| CLI | `cli/args.rs` (clap), `cli/commands.rs` (dispatch), `cli/tunnel.rs`, `cli/status.rs`, `cli/profiles.rs`, `cli/output.rs` (JSON envelope) |
| Public IP, ISP, latency | `telemetry/` |
| Every subprocess | `process/` (`process::run`, `CommandSpec`) |
| OS differences | `platform.rs` re-exports the per-OS type (`platform::Firewall`, `platform::Dns`, …) |
| Shared tunnel types | `tunnel.rs`; profile ids in `profile.rs`; CIDR math in `cidr.rs` |

## How a connection works

`control/` owns every VPN connection. One engine thread (`engine.rs`) holds the
tunnel list (`state.rs`), starts and stops protocol processes (`tunnels.rs`),
and after every change asks the pure planner (`plan.rs`) what routes, DNS and
firewall the host should carry, then applies the difference (`net.rs`). The plan
depends only on which tunnels are up and the kill switch mode — never on command
order — so every path to the same tunnel set lands on the same host state. The
newest full tunnel owns the default route and DNS; a switch brings the new
tunnel up before stopping the ones it conflicts with.

TUI and CLI send `control::Command`s and read `control::Snapshot`s; nothing else
touches routes, DNS or the firewall. The dashboard renders straight from the
snapshot (`App::tunnels`, `App::tunnel`, `App::primary_id`). New behaviour goes
into the planner or a state transition, with a test in `plan.rs`/`state.rs` —
not into a caller.

## Kill switch vocabulary

One vocabulary on every surface (CLI verbs, CLI output, TUI, JSON, logs). Enum
variants never leak into output; route every string through the helpers on
`control::killswitch` — `KillSwitchMode::display_name`, `cli_verb`,
`from_cli_verb`, `one_liner`, `behavior_lines`, `KillSwitchState::display_status`.

| Enum | Slug | Behaviour |
|---|---|---|
| `Off` | `off` | No firewall rules. Real IP exposed if the VPN drops. |
| `Auto` | `block-on-drop` | Armed while a VPN is up; blocks egress only on an unexpected drop. |
| `AlwaysOn` | `vpn-only` | Firewall always engaged: default-drop plus per-tunnel allow rules. State is always `Blocking`, never `Armed`. |

No aliases: `auto`/`always` are rejected with "Use: off, block-on-drop, vpn-only".
The header uses short forms (`KS:Off` / `KS:Watch` / `KS:VPN-only` / `KS:DROPPED`)
for the 80-column budget.

## Boundaries (enforced by `cargo xtask`, run in CI)

- `cfg(target_os)` only in `macos/`, `linux/`, `platform.rs` (`check-platform-leak`).
- `Command::new` only in `process/` (`check-subprocess`).
- `wg`/`wg-quick` only in `wireguard/`, `openvpn` only in `openvpn/` (`check-protocol-leak`).

Exceptions take `// xtask:allow-*: <reason>`. If you reach for one, move the
code instead.

## TUI density

Density via signalling, not duplication. Never add a panel per tunnel; one-line
summaries and overflow ladders fit the existing layout at 80×24 (see
[`docs/manual-testing/multi-connection.md`](docs/manual-testing/multi-connection.md)).

## Tests

- Engine behaviour: unit tests in `control/plan.rs` and `control/state.rs`.
- Rendering: `App::new_test()`, seed tunnels with `App::set_tunnels_for_test`
  and `app::connection::test_view`, render into a `TestBackend`.
- Integration tests live in `crates/vortix/tests/suite/` behind one `main.rs`.
  **A new file there needs a `mod` line or it silently never runs.** Suites that
  mutate process-global state or time wall-clock stay top-level `tests/*.rs`.
- Things only a real kernel, terminal or VPN server can show go in
  [`docs/manual-testing/P0.md`](docs/manual-testing/P0.md), with a pass signal
  visible in a captured frame — only if no automated test can answer it.

## Live testing (macOS)

Claude never runs `sudo` on the Mac. The user keeps a tmux session `vxrun` with two root
panes: window 0 for the TUI, window 1 for a root shell (both started with
`sudo -s` and `export SUDO_UID=502 SUDO_GID=20 SUDO_USER=harshitchaudhary`).
Drive them with `tmux send-keys -t vxrun:0 …` and read frames with
`tmux capture-pane -p -t vxrun:0`. If the session is missing, ask the user to
create it. In the TUI: digits quick-connect a profile; with the sidebar
focused, `D` disconnects all (and asks `y`/`n` only when 2+ tunnels are up —
with one tunnel a following `y` copies the IP); `K` cycles the kill switch;
`q` quits. Window 1 is a root shell and `tmux send-keys` into it is allowed
without a prompt: treat it as root access. Verify host state from
window 1 (`netstat -rn -f inet`, `scutil --dns`, `pfctl -a com.apple/vortix.killswitch -sr`).

## Live testing (Linux)

An Ubuntu lab laptop is on the LAN: `ssh -i ~/.ssh/vortix_lab_ed25519
harrykp@192.168.1.97`, checkout at `~/vortix`, profiles already imported. It
has passwordless sudo and the user allows using it **there** (never on the
Mac). Sync with `git fetch origin <branch> && git checkout -B lab FETCH_HEAD`
(or `scp` a changed file), build with `cargo build -p vortix`, and run as
`sudo -n env SUDO_UID=1000 SUDO_GID=1000 SUDO_USER=harrykp ./target/debug/vortix …`.
tmux session `vxlinux` has root windows 1 and 2 for the TUI. Check host state
with `ip -4 route`, `resolvectl dns`, `nft list table inet vortix_killswitch`.
Anything verified live on macOS should be verified here too.

## Secrets

Profiles contain private keys and passwords, on both machines: never print,
copy or commit them. Credentials are typed by the user.

## Git and PRs

- Branch from `main`; one branch per fix; conventional commit subjects
  (`fix:`, `refactor:`, `perf:`, `test:`, `docs:`). Commit with the configured
  identity — never pass `-c user.*`.
- End commit messages with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- The pre-commit hook (`scripts/install-hooks.sh`) runs fmt, clippy, gitleaks
  (secret scan of staged changes) and tests. `.DS_Store` is ignored.
- PRs squash-merge into `main`. `main` has no branch protection, so the green
  check is ours to enforce: merge only when every `gh pr checks` row is `pass`
  or `skipping` (release jobs always skip) and none is failing or pending.
- Push only when asked, or as part of `/fix-bug`.

## Build budget

`[profile.release]` uses `opt-level = "z"`. **Never set `panic = "abort"`**:
`catch_unwind` isolates panics in tunnels, hooks and background tasks. Size and
build-time numbers live in [`docs/performance.md`](docs/performance.md).

## Removed on purpose — do not reintroduce

- Background mode, the privileged helper and the daemon (archived on branch
  `archive/background-mode`; needs a product decision to revive).
- The `vortix secrets` command, `metadata.json`, the iptables backend (nftables
  only; legacy chains are just cleaned up), `core/`, `utils.rs`, the TUI's
  separate tunnel registry and its `Connection`/`TunnelSnapshot` render model.

## Lessons that cost a CI cycle or a bug

- Blanket regex renames hit enum variants and foreign imports. Let the
  compiler find call sites and review the diff.
- Linux-only code broke only in Linux cross-clippy; macOS builds never see it.
- `cargo clippy` skips rustdoc lints; broken intra-doc links fail only in
  `cargo doc` with `-D warnings`.
- pf rules for `vpn-only` need `flags any`, or existing flows lose connectivity.
- Async results that arrive after the state they describe must be dropped: the
  telemetry worker tags results with an epoch so a pre-disconnect lookup cannot
  overwrite the real IP.
- `process::run` returns `Ok` for a command that exits non-zero; check
  `CommandOutcome::success()`. Treating `Ok` as success shipped a DNS flush
  that silently ignored failures.
