# Migrating to Vortix v0.3.0

This release lands a large architectural refactor (six internal plans, 28
commits). For users, the day-to-day surface barely changes. This document
covers what's automatic, what's optional, and how to roll back if you need
to.

## TL;DR

- **Upgrade is automatic.** Existing `.conf` and `.ovpn` profiles keep
  working. No flags to change. `vortix up <profile>`, `down`, `status`,
  `list`, `import`, `show` all behave exactly as before.
- **Two new optional features:** an encrypted secret store and a JSON
  event journal. Both have safe defaults; you only opt into the
  encrypted store explicitly.
- **One new top-level subcommand:** `vortix secrets {set,get,delete}`
  for the encrypted credential store. Everything else is internal
  architecture.
- **One new flag** on existing commands: `vortix show <p> --raw
  --inline-secrets` appends a stored secret as a trailing comment for
  sharing.
- **One-line rollback** if you hit trouble: `cargo install vortix
  --version 0.2.2 --force`.

---

## What auto-migrates

The first time v0.3.0 runs, it walks `${XDG_CONFIG_HOME}/vortix/profiles/`
and creates a sibling `.meta.toml` next to each existing `.conf` /
`.ovpn`:

```
~/.config/vortix/profiles/
├── corp.conf
├── corp.meta.toml            ← new sidecar, generated automatically
├── home.ovpn
└── home.meta.toml            ← new sidecar
```

Each sidecar carries a stable `profile_id` (SHA-256 of the name + first
4 KiB of the config), the original `display_name`, and the protocol.
v0.2.x ignores `.meta.toml` files entirely, so rollback is safe.

The migration is **idempotent** — it re-runs at every startup and only
touches profiles that don't have a sidecar yet. There is no explicit
`vortix migrate` command; if you need to re-trigger after fixing
something (e.g., a permissions issue), just restart vortix.

If migration ever fails (read-only profile dir, unusual perms, etc.),
startup continues and the warning is logged to stderr. No panic, no
data loss.

### Override

If you need to skip the startup backfill — typically while debugging a
filesystem permission issue — set `VORTIX_SKIP_MIGRATION` in your
environment:

```sh
export VORTIX_SKIP_MIGRATION=1
vortix up corp
```

Unset it to restore the implicit migration.

---

## What needs manual opt-in

### Encrypted secret store (opt-in)

v0.3.0 adds `vortix secrets {set,get,delete}` backed by a layered store:
the OS keyring first (Keychain on macOS, Secret Service on Linux), with
an AES-256-GCM + argon2id encrypted file as fallback when no keyring is
available.

By default the store is empty and the rest of vortix doesn't touch it.
Use it if you want to:

- Keep OpenVPN auth credentials out of plain `.auth` files (see below)
- Store a passphrase or token alongside a profile without inlining it
  into the `.conf`

Examples:

```sh
echo -n 'username:password' | vortix secrets set creds/corp
vortix secrets get creds/corp        # echoes the value
vortix secrets delete creds/corp
```

The encrypted-file fallback lives at `${XDG_CONFIG_HOME}/vortix/secrets.enc`.
You don't need a passphrase if the keyring works — but on headless Linux
without `libsecret`, the encrypted-file path needs one (the binary will
prompt the first time).

### Session event journal (default on, opt-out)

v0.3.0 writes a JSON-lines event journal at
`${XDG_DATA_HOME}/vortix/sessions/<ISO>-<pid>.jsonl` for every run.
Retention is 30 days / 30 files (whichever cap hits first). Each line
is an `EngineEvent` record: connection state transitions, tunnel
up/down, IP changes, telemetry samples, and so on.

Find the current session's path via `vortix info`:

```
  Session journal: /Users/you/Library/Application Support/vortix/sessions/2026-...-66210.jsonl
```

Tail it with standard shell tools:

```sh
tail -f "$(vortix info --json | jq -r '.data.journal_session')" | jq '.event'
```

If you don't want disk persistence, set in
`~/.config/vortix/settings.toml`:

```toml
[journal]
disk = false
```

The broadcast bus still works (so the TUI's live event stream is
unaffected); only the on-disk JSONL file is suppressed.

### Layered settings (opt-in if you want overrides)

A new `settings.toml` is read with figment-style layering: built-in
defaults → `/etc/vortix/config.toml` (system) →
`${XDG_CONFIG_HOME}/vortix/settings.toml` (user) → `VORTIX_*` env vars
(highest precedence). You don't need to create the file; the
out-of-the-box defaults match v0.2.x behavior. To see what you've
configured, read your own `settings.toml`.

---

## OpenVPN auth: nothing changes unless you want it to

Existing `${XDG_CONFIG_HOME}/vortix/auth/<profile>.auth` files keep
working exactly as before. The `OvpnTunnel` honors them on every
`vortix up`.

To optionally move credentials into the encrypted store:

```sh
echo -n 'username:password' | vortix secrets set creds/corp
rm ~/.config/vortix/auth/corp.auth
vortix up corp                # tunnel pulls from the secret store now
```

When both exist, the secret store takes precedence; the legacy `.auth`
file is the fallback.

To share a profile with credentials inlined for one-shot use (be
careful — this writes the password into the export):

```sh
vortix show corp --raw --inline-secrets > corp-with-creds.ovpn
# Recipient: cat corp-with-creds.ovpn | vortix import - && vortix up corp
```

The inlined form appears as a `# vortix-secret:<base64>` trailing
comment that v0.3.x picks up on import. v0.2.x silently ignores it as
a comment, so the file is forward-compatible.

---

## New CLI surface at a glance

Everything here is additive. Pre-v0.3.0 commands are unchanged.

| Command | What it does |
|---|---|
| `vortix secrets {set,get,delete} <id>` | Manage the layered encrypted secret store (new top-level subcommand) |
| `vortix show <profile> --raw --inline-secrets` | Streams the profile config with stored credentials appended as a `# vortix-secret:<base64>` comment (new flag on existing `show`) |
| `vortix info` | Output now includes a `Session journal:` line pointing at the current session's JSONL file |

`vortix --json` envelopes now carry a top-level `schema_version: 1`
field for forward-compatibility detection. Everything else is
internal architecture — engine FSM, layered settings, sidecar
migration logic — none of which you interact with through new CLI
verbs.

---

## Rollback

If anything breaks, downgrade to v0.2.2:

```sh
# crates.io
cargo install vortix --version 0.2.2 --force

# Homebrew
brew uninstall vortix && brew install vortix@0.2.2  # if pinned tap exists
# (otherwise: brew install with explicit version via tap revision)

# npm
npm install -g @harry-kp/vortix@0.2.2
```

What rollback does to your data:

- `.meta.toml` sidecars left behind are inert to v0.2.x — they're
  ignored, not parsed. Leave them in place or delete them; either
  works.
- `secrets.enc` in `${XDG_CONFIG_HOME}/vortix/` is untouched by v0.2.x.
  Either keep it for the next upgrade attempt or delete it.
- `sessions/*.jsonl` under `${XDG_DATA_HOME}/vortix/` are pure
  observability data; delete the directory if you want.
- `settings.toml` is ignored by v0.2.x. Your old `config.toml` (if any)
  is untouched.

There's no data destructively rewritten by v0.3.0 — every change is
read-then-write-new-file.

---

## V2 → V1 Downgrade (v0.4.x → v0.3.x)

The multi-connection release ("V2", v0.4.0+) introduces a richer
killswitch persisted-state shape, additional journal event variants,
and a multi-tunnel `TunnelRegistry`. If you need to roll back to
v0.3.x ("V1"), follow this procedure.

1. **Revert the binary to v0.3.x.**

   ```sh
   # crates.io
   cargo install vortix --version 0.3.1 --force

   # Homebrew
   brew uninstall vortix && brew install vortix@0.3.1

   # npm
   npm install -g @harry-kp/vortix@0.3.1
   ```

2. **Check whether V1 read-tolerance was backported.** If your
   v0.3.x build received the backport from plan 015 (which makes V1
   silently ignore the V2 killswitch state shape and re-arm fresh),
   you are done — no manual cleanup is needed. The backport is
   indicated by the presence of a `killswitch_state.compat = "v2-tolerant"`
   marker line in `vortix --version` extended output.

3. **Otherwise, remove the V2-only killswitch state file.** V2 persists
   killswitch state in a new JSON shape that V1 cannot parse and will
   refuse to load:

   ```sh
   rm ~/.config/vortix/killswitch-state.json
   ```

   Re-arm the killswitch on first run after downgrade:

   ```sh
   sudo vortix killswitch block-on-drop   # or "vpn-only", to taste
   ```

4. **Profile configs are unchanged.** No migration is needed for your
   `.conf` or `.ovpn` files. The `.meta.toml` sidecars introduced in
   v0.3.0 are V1-compatible and remain in place.

5. **Journal JSONL is compatible.** V2 introduces new `EngineEvent`
   variants (multi-tunnel state transitions, registry conflicts), but
   the enum is `#[non_exhaustive]`-additive on the wire — V1 readers
   skip unknown variants rather than erroring. You can keep your
   `${XDG_DATA_HOME}/vortix/sessions/*.jsonl` files in place; they
   stay readable by both V1 and V2 tooling.

No data destructively rewritten by V2 — every change is
read-then-write-new-file, so the worst-case rollback is "delete
`killswitch-state.json` and re-arm."

---

## Got stuck?

Run `vortix bug-report` — v0.3.0 attaches the current session's
journal path and the last 10 event kinds, so the report carries the
state you'd otherwise need to recreate by hand. Paste the output into
a new issue.

Linux-specific issues are tracked in
[discussion #184](https://github.com/Harry-kp/vortix/discussions/184).
If you tested an RC build, drop a note in that thread before opening a
fresh issue — odds are good a fellow tester already saw it.
