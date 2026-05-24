---
date: 2026-05-24
topic: config-profile-secret-stack
---

# Config + Profile Store + Secret Store (file-based)

## Summary

Three crisp concerns in the new `crates/vortix-config/` workspace member, replacing today's 751-line `src/config.rs` monolith:

- **`Settings`** via the `figment` crate — layered defaults < `/etc/vortix/config.toml` < `<XDG_CONFIG_HOME>/vortix/config.toml` < `VORTIX_*` env vars < CLI flags, with the existing SUDO_USER home resolution preserved so `sudo vortix` still reads the invoking user's config (not root's).
- **`ProfileStore`** as a trait, with day-one impl `FsProfileStore` keeping today's `.conf`/`.ovpn` files as the source of truth and adding per-profile sidecar metadata at `<profile>.meta.toml` (group, imported_at, last_used, source, content-identity hash). No database; profiles are still readable with `cat`, shareable with `scp`, debuggable with any text editor. The trait exists so that *when* team management or v1.0 audit needs an indexed backend, swapping it in is one impl change without touching engine, tunnel, or TUI code.
- **`SecretStore`** backed by `keyring` v3 (Keychain on macOS / Secret Service on Linux / Credential Manager on future Windows) with an encrypted-file fallback for headless Linux (`<config>/secrets.enc`, AES-256-GCM, passphrase from `VORTIX_PASSPHRASE` env var or interactive prompt). Returns `Secret(Vec<u8>)` newtypes that zeroize on drop. **This is the real security win** — inline `PrivateKey = ...` lines in `.conf` files become `SecretRef` references; secret material moves out of the user's config directory.

Migration is automatic on first startup post-upgrade: scan the existing `.conf`/`.ovpn` directory, write a sidecar `<profile>.meta.toml` for each, extract inline secrets into the SecretStore, rewrite the `.conf`/`.ovpn` to reference the SecretStore instead of carrying inline keys. Original files are modified in place (with a one-time backup at `<profile>.conf.pre-migrate`) so existing `vortix up corp` invocations and any third-party tooling that reads `.conf` files keep working. Pure infrastructure migration — no user-facing feature changes — but it delivers the v0.3.0 group infrastructure and the security win up front, while keeping the door open for an indexed backend later.

---

## Problem Frame

Today's `src/config.rs` (751 lines) conflates three distinct concerns into one module: hierarchical settings resolution, profile path/metadata helpers, and inline credential storage. The pains stack:

**Inline secrets in plain text are a real security smell.** WireGuard `.conf` files contain `PrivateKey = <base64>` inline. OpenVPN `.ovpn` files contain `<cert>...<key>...</key></cert>` blocks inline. These files sit in the user's config directory at default umask. A read-only-to-user file with a long-lived private key is what a security review would flag without thinking. v1.0 ROADMAP names "config encryption (credentials at rest)" — this is the work it points at, and the right shape is "credentials don't live in the config file; they live in OS keychain or an encrypted blob; the config file holds opaque references."

**Profile metadata has no persistent home.** `VpnProfile.last_used: Option<SystemTime>` exists in the type but how it's persisted across runs is unclear — likely scanned at startup or simply lost on restart. v0.3.0 ROADMAP commits to profile groups, but there's no `group` field anywhere. New metadata (imported_at, source URL when downloaded via `src/core/downloader.rs`) has no obvious place to live.

**Configuration precedence is partial.** Today's resolution order is CLI flag > SUDO_USER-aware home > XDG > default, plus a `VORTIX_CONFIG_DIR` env var. But there's no system file (`/etc/vortix/config.toml` for daemon-mode policy), no explicit field-level precedence (the whole file wins or loses), no schema validation. The figment crate solves these without inventing new patterns.

The compounding cost is that every roadmap item touching configuration — profile groups (v0.3.0), config encryption (v1.0), team management (v1.0), Windows support (v1.0) — would otherwise have to pick its way through the existing 751-line file and the existing inline-secret pattern. Each item would either invent a side-store or contort the existing file.

The simplest fix that pays the real bills:
- **Settings:** `figment`-layered with `vortix-config::settings::Settings` (preserves SUDO_USER home resolution).
- **Profile metadata:** sidecar `<profile>.meta.toml` files. v0.3.0 groups become a field in the sidecar. Future team management becomes an additional field in the same sidecar.
- **Secrets:** `keyring` v3 + encrypted-file fallback. Inline `PrivateKey =` lines become `PrivateKey = secret://wg_private_key_<id>` references; the runtime resolves the secret via the SecretStore at the moment the tunnel needs it.

This is YAGNI applied correctly. We're not adding SQLite, MVCC, or fleet sync that we don't need today. We're solving the actual smells (inline secrets, no metadata home, partial config precedence) with mechanisms that scale to the v0.3.0 features without locking us out of an indexed backend if team-mgmt later demands one.

---

## Actors

- A1. **End user upgrading vortix from v0.2.x to v0.3.x** — runs `cargo install vortix` (or `brew upgrade vortix`), starts vortix, expects their existing profiles to keep working without manual intervention. After the upgrade, can still `cat ~/.config/vortix/profiles/corp.conf` and see a recognizable WireGuard config (minus the inline private key, which now references the SecretStore).
- A2. **End user on a headless Linux server** — runs vortix as a daemon (Phase B of idea 4) on a server with no `gnome-keyring`, no `KeePassXC`, no desktop session. Needs vortix to store secrets without OS keyring.
- A3. **Contributor implementing v0.3.0 profile groups** — adds a `group: String` field to the `.meta.toml` sidecar and a UI for setting/filtering on it. No backend changes required; the trait already accommodates the field.
- A4. **Contributor implementing v1.0 team management** — adds a new `ProfileSource::HttpFleet { fleet_url, fetched_at }` variant; the `.meta.toml` schema already accommodates `source`. If query performance becomes a concern at scale, replaces `FsProfileStore` with a new `IndexedProfileStore` (e.g., SQLite-backed) — the engine and TUI consume the trait and don't notice.
- A5. **Security reviewer** — verifies that no plain-text WireGuard private keys live on disk under default umask. After migration, the `.conf` file has `PrivateKey = secret://...` references; actual secret material lives in keyring or in AES-256-GCM-encrypted `secrets.enc`.
- A6. **Engine (idea 3)** — calls `settings.engine.retry_budget_secs` for retry config; calls `profile_store.get(profile_id)` to load a profile during connect; calls `secret_store.get(secret_ref)` to materialize a private key for the tunnel impl.
- A7. **Tunnel impls (idea 5)** — consume `Profile` and `SecretStore` to assemble the right config for `wg-quick up` / `openvpn`. Secrets are passed to subprocesses via stdin or a per-invocation temp file (not as command args — for redaction in idea 1's `tracing` logs and to avoid leaving secrets in `/proc/<pid>/cmdline`).
- A8. **Third-party tooling** (a homemade backup script, a config-sync rsync job, a profile-share over `scp`) — keeps working unchanged. Profiles are still `.conf`/`.ovpn` files in a directory; sidecars are TOML files anyone can read.

---

## Key Flows

- F1. **First startup after upgrade — automatic profile migration**
  - **Trigger:** User runs `vortix up corp` after upgrading.
  - **Actors:** A1, A5
  - **Steps:**
    1. vortix detects that `<config>/profiles/*.conf` or `*.ovpn` files exist without corresponding `.meta.toml` sidecars (or with sidecars but a `schema_version` older than current).
    2. For each profile file, vortix:
       a. Parses the file via the appropriate `Tunnel::parse_profile` (idea 5) to extract cryptographic identity (WG pubkey or OVPN cert fingerprint).
       b. Computes `profile_id = hex(SHA-256(identity))`.
       c. Writes a backup `<profile>.conf.pre-migrate` (one-time, kept until v0.4.0).
       d. Extracts inline secrets: `[Interface] PrivateKey = ...` for WG, `<cert>...</cert>` / `<key>...</key>` blocks for OVPN, plus any `auth-user-pass` external file. Inserts each into the `SecretStore` under a derived name (`<profile_id>:wg_private_key`, etc.).
       e. Rewrites the `.conf`/`.ovpn` in place: inline secrets replaced with `PrivateKey = secret://<profile_id>:wg_private_key` (a vortix-recognized placeholder syntax; the file is no longer valid input to `wg-quick`/`openvpn` directly, but vortix materializes it before invoking those tools).
       f. Writes a `<profile>.meta.toml` sidecar with `schema_version = 1`, `profile_id`, `display_name` (from filename), `protocol`, `imported_at = now`, `source = "local-fs"`, `group = ""` (empty).
    3. Migration emits a `ProfileMigrationCompleted { count, secrets_extracted }` event into idea 3's journal. Per-file failures emit `ProfileMigrationFileSkipped { path, reason }` and migration continues with the rest.
    4. Vortix proceeds with the connect normally.
  - **Outcome:** User observes no behavior change; the connect succeeds; from now on, `cat corp.conf` shows a config with `secret://` placeholders, and `cat corp.meta.toml` shows the metadata. The original is at `corp.conf.pre-migrate` until cleanup.
  - **Covered by:** R7, R8, R10, R14, R15, R16

- F2. **Engine consumes a profile for connect**
  - **Trigger:** FSM transitioning `Disconnected → Connecting` for `profile_id`.
  - **Actors:** A6, A7
  - **Steps:**
    1. Engine calls `profile_store.get(profile_id)` → `Result<Profile, ProfileStoreError>`. The `FsProfileStore` reads `<profile>.conf` plus `<profile>.meta.toml`, merges them into a `Profile { id, display_name, protocol, group, source, imported_at, last_used, parsed: Box<dyn ParsedProfile>, secrets: HashMap<SecretName, SecretRef> }`.
    2. Tunnel impl (e.g., `WgTunnel::up`) consults `profile.secrets["wg_private_key"]` → `SecretRef` → `secret_store.get(secret_ref).await` → `Secret(Vec<u8>)`.
    3. The Tunnel impl writes a transient WireGuard config to a temp file with the secret inlined (or pipes it via `wg setconf <iface> /dev/stdin`), then deletes the temp file immediately. `CommandSpec` marks the temp-file argument as `redact_in_audit` (idea 1 reserved field).
    4. Tunnel proceeds; engine emits events.
  - **Outcome:** Secret never appears in logs; never lives in `<profile>.conf` on disk; zeroizes on drop after the subprocess starts.
  - **Covered by:** R3, R11, R12, R17

- F3. **Headless Linux server uses encrypted-file fallback**
  - **Trigger:** vortix starts on a Docker container with no `gnome-keyring`/`KeePassXC` and no `DBUS_SESSION_BUS_ADDRESS`. First import of a profile.
  - **Actors:** A2, A5
  - **Steps:**
    1. SecretStore tries `keyring::Entry::new(...).set_password(...)`, which fails with `keyring::Error::NoStorageAccess` or platform-specific equivalent.
    2. SecretStore falls back to encrypted-file backend. If `<config>/secrets.enc` doesn't exist and no `VORTIX_PASSPHRASE` env var is set, vortix exits with `Err(SecretStoreError::PassphraseRequired)` and `next_actions: [{"action": "set_passphrase_env", "hint": "Set VORTIX_PASSPHRASE or run interactively to be prompted"}]`.
    3. With `VORTIX_PASSPHRASE` set: SecretStore derives a key from the passphrase (via `argon2id`), encrypts the secret blob with AES-256-GCM, writes `secrets.enc` with the encrypted payload and a header containing salt + nonce.
    4. Subsequent `secret_store.get(ref)` calls decrypt the file in-memory, return the requested secret, zeroize the in-memory copy on drop.
  - **Outcome:** vortix works on headless Linux. Secrets are encrypted on disk. User UX is a one-time setup of `VORTIX_PASSPHRASE`.
  - **Covered by:** R12, R13, R18

- F4. **Layered settings resolution at startup**
  - **Trigger:** vortix CLI invoked with `--engine-retry-budget-secs 600`, user file has `[engine] retry_budget_secs = 60`, system file has `[engine] retry_budget_secs = 30`, and the user ran `sudo vortix`.
  - **Actors:** A6
  - **Steps:**
    1. main() builds a figment stack: `defaults()` < `Toml::file("/etc/vortix/config.toml")` < `Toml::file("<user-home-via-SUDO_USER>/.config/vortix/config.toml")` < `Env::prefixed("VORTIX_")` < `Serialized::defaults(cli_args)`.
    2. SUDO_USER-aware home resolution honors the invoking user's home for the user file.
    3. `figment.extract::<Settings>()` produces an immutable `Settings` value with `engine.retry_budget_secs == 600` (CLI wins).
  - **Outcome:** Precedence is explicit and field-level.
  - **Covered by:** R4, R5

- F5. **Adding a profile group (v0.3.0)**
  - **Trigger:** User runs `vortix profile set-group corp work`.
  - **Actors:** A3
  - **Steps:**
    1. CLI calls `profile_store.update(profile_id, |p| p.group = "work")`.
    2. `FsProfileStore::update` reads `<profile>.meta.toml`, mutates the `group` field, writes it back atomically (write to `<profile>.meta.toml.tmp`, rename).
    3. `<profile>.conf` is unchanged. Only the sidecar moves.
  - **Outcome:** Profile is now in the "work" group. `vortix profile list --group work` returns it.
  - **Covered by:** R8, R9

---

## Requirements

**Settings (figment-backed)**

- R1. `Settings` is a single serde-deserializable struct in `vortix-config::settings`. Day-one fields are only the subset that other ideas have already committed to consuming:
  - `[engine] retry_budget_secs: u64 = 300`, `[engine] retry_initial_backoff_ms: u64 = 2000` (idea 3 R8)
  - `[journal] disk: bool = true`, `[journal] retention_days: u32 = 30`, `[journal] retention_count: u32 = 30` (idea 3 R12, R14)
  - `[ui] start_mode: StartMode = Tui` (replaces today's implicit default-to-TUI; `Headless` is the CLI-only alternative)
- R2. The struct is `#[non_exhaustive]`-via-sealed (matching idea 6 R3) and `Clone + Send + Sync`. Constructed once at startup, immutable thereafter.
- R3. Day-one settings deliberately omit `[theme]`, `[telemetry]`, and other sections. They are added as their driving features land (v0.1.8 theming, v0.3.0 telemetry expansion).
- R4. Precedence order (lowest to highest):
  1. Hardcoded defaults in code
  2. System file at `/etc/vortix/config.toml` (if present; useful for daemon-mode policy)
  3. User file at `<XDG_CONFIG_HOME>/vortix/config.toml` (Linux) / `~/Library/Application Support/vortix/config.toml` (macOS) / `%APPDATA%\vortix\config.toml` (Windows)
  4. Environment variables `VORTIX_*` (e.g., `VORTIX_ENGINE_RETRY_BUDGET_SECS=600`)
  5. CLI flags
- R5. **SUDO_USER home resolution is preserved.** When `sudo vortix` runs, the user file is resolved at the invoking user's home directory, not root's. Today's `src/config.rs` already does this; the figment migration must continue to do so via a custom `figment::Provider` or pre-resolution step.
- R6. Settings load failure (invalid TOML, type mismatch) returns a typed `SettingsError` that the CLI surfaces with the same JSON envelope `next_actions` pattern as idea 1.

**ProfileStore (file-based)**

- R7. `ProfileStore` is a trait in `vortix-config::profile_store`. The day-one impl is `FsProfileStore`: profiles live as `<config>/profiles/<display_name>.{conf,ovpn}` with per-profile sidecars at `<config>/profiles/<display_name>.meta.toml`. The trait is `#[non_exhaustive]`-sealed (matching idea 6 R3) so future backends (`SqliteProfileStore` for team-mgmt scale, `RemoteProfileStore` for fleet sync) can replace `FsProfileStore` without touching engine/tunnel/TUI callers.
- R8. The `.meta.toml` sidecar schema (day one):
  ```toml
  schema_version = 1
  profile_id = "hex-encoded-sha256-of-cryptographic-identity"
  display_name = "corp"
  protocol = "wireguard"  # or "openvpn"
  group = ""              # empty by default; v0.3.0 UI fills this in
  source = "local-fs"     # or "url:<original_url>", or "imported-from-text"
  imported_at = 1684857600
  last_used = 1684860000   # may be absent
  ```
- R9. `ProfileSource` is encoded as a single string field in the sidecar (`"local-fs"`, `"url:<url>"`, `"imported-from-text"`) for v1 simplicity. Three variants today; future team-mgmt sources (`"http-fleet:<fleet_url>"`, `"git:<repo>"`, `"s3:<bucket>"`) are additive new prefix conventions. Parsing is a simple match in the deserializer.
- R10. `ProfileId` is `hex(SHA-256(cryptographic_identity))`: WireGuard's public key for WG profiles, OpenVPN's cert fingerprint for OVPN profiles. This matches idea 3's R3 (stable identity) and idea 5's R8 (per-protocol identity contract). Recorded in the sidecar so re-imports detect duplicates by comparing identity hashes.
- R11. `ProfileStore` methods (async, all `FsProfileStore` impls are thin wrappers over file I/O on a `tokio::task::spawn_blocking` thread):
  - `list() -> Vec<ProfileSummary>` — scan the directory, parse each `.meta.toml`, return summaries. With ≤200 profiles, the scan is fast enough; if and when we hit thousands, the trait swap to an indexed backend handles it.
  - `get(id_or_name) -> Option<Profile>` — load `.conf` + `.meta.toml`, parse via `Tunnel::parse_profile`, resolve `SecretRef` references.
  - `insert(profile) -> Result<()>` — atomic write of both files (write `.tmp`, rename); collision on `profile_id` is an idempotent no-op (updates `last_used`).
  - `update(id, mut_fn) -> Result<()>` — load, mutate sidecar fields, atomic-rename back. The `.conf` file is touched only when the user explicitly edits protocol content.
  - `delete(id) -> Result<()>` — delete `.conf`, `.meta.toml`, and any backup file. Also instructs `SecretStore` to delete associated secrets.
  - `find_by_display_name(name) -> Option<Profile>` — sidecar scan with name filter.
- R12. Atomic writes use the standard `<file>.tmp` + `rename` pattern. Concurrent vortix invocations on the same profile dir are not supported in v1 (single-user, single-instance assumption); a future daemon-only mode (Phase B of idea 4) handles concurrency by being the sole writer.
- R13. The `ProfileStore` trait operates on protocol-agnostic `Profile` values (per idea 5 R8). Per-protocol parsing happens inside the impl via injected `Tunnel::parse_profile`. Engine and TUI consume `Profile` values without knowing whether the backend is files or SQL.

**SecretStore (keyring + encrypted-file fallback)**

- R14. `SecretStore` is a trait in `vortix-config::secret_store`. Day-one impl is `LayeredSecretStore` which tries `KeyringSecretStore` first, then falls back to `EncryptedFileSecretStore`. The choice is made at startup by probing keyring availability; the chosen backend is recorded so subsequent runs go straight to it.
- R15. `KeyringSecretStore` uses the `keyring` v3 crate. Each secret is stored at service `vortix`, account `<secret_id>`.
- R16. `EncryptedFileSecretStore` stores all secrets in `<config>/secrets.enc`. Encryption: AES-256-GCM. Key derivation: argon2id with a per-file salt. Passphrase source: `VORTIX_PASSPHRASE` env var (preferred for daemons/CI), interactive prompt (TTY available, no env var), or `--passphrase-file <path>` CLI flag (advanced).
- R17. `LayeredSecretStore` writes go to whichever backend was selected at construction. Failure modes:
  - No keyring AND no TTY AND no `VORTIX_PASSPHRASE` AND `secrets.enc` doesn't exist → `Err(SecretStoreError::PassphraseRequired)` with structured `next_actions`.
  - Incorrect passphrase → `Err(SecretStoreError::DecryptionFailed)` with `next_actions: [{"action": "verify_passphrase"}, {"action": "reset_with_loss", "hint": "deletes secrets.enc; users must re-import secrets"}]`.
- R18. `SecretRef` is an opaque struct `SecretRef { backend: SecretBackendTag, id: String }` where `SecretBackendTag = Keyring | EncryptedFile`. The ref is `Clone + Send + Sync + Serialize/Deserialize` — safe to store in `.meta.toml` and in idea 3's journal because it contains no secret material.
- R19. `Secret(Vec<u8>)` is a newtype wrapping secret bytes; uses the `zeroize` crate to zero memory on drop. `Secret` derefs to `&[u8]` for reading but has no `Display` / standard `Debug` impl (its `Debug` redacts).
- R20. `SecretStore::get(secret_ref) -> Result<Secret>` is `async`. Failure modes: `NotFound { ref }`, `KeyringLocked` (Linux Secret Service is locked), `DecryptionFailed`, `BackendUnavailable`.
- R21. Subprocess args containing secrets use idea 1's `CommandSpec.redact_in_audit: Vec<ArgIndex>` (reserved field). Preferred mechanism: write the secret to a per-invocation temp file (mode 0600), pass the *path* as the arg, delete the temp file after the subprocess exits or detaches. `tracing` events record the temp-file path; the secret material is never logged.

**Migration from existing `.conf`/`.ovpn` files**

- R22. On startup, `vortix-config` scans `<config>/profiles/*` and detects profiles lacking a `.meta.toml` sidecar (or with `schema_version < current`). Migration runs automatically for those.
- R23. Migration extracts inline secrets:
  - WireGuard `.conf`: `[Interface] PrivateKey = <base64>` → SecretStore under `<profile_id>:wg_private_key` → replaced inline with `PrivateKey = secret://<profile_id>:wg_private_key`.
  - OpenVPN `.ovpn`: inline `<cert>...</cert>` and `<key>...</key>` blocks → SecretStore as `<profile_id>:ovpn_cert`, `<profile_id>:ovpn_key` → replaced with `<cert>secret://...</cert>` style placeholders. External `auth-user-pass <file>` references → file contents loaded into SecretStore, `auth-user-pass` directive removed from the rewritten `.ovpn` (engine reassembles it via temp-file at connect time).
- R24. Migration writes a one-time backup at `<profile>.conf.pre-migrate` (or `.ovpn.pre-migrate`) before rewriting. The backup is deleted by `vortix migrate-profiles --cleanup` (not run automatically; ships in v0.4.0 with release notes).
- R25. Migration is **idempotent**: re-running on already-migrated files (those whose contents already contain `secret://` placeholders OR whose `.meta.toml` is at current `schema_version`) is a no-op.
- R26. Migration emits journal events (per idea 3): `ProfileMigrationCompleted { count, secrets_extracted }`, `ProfileMigrationFileSkipped { path, reason }`. Failures don't abort migration of the rest.

**Cross-cutting**

- R27. The new `crates/vortix-config/` workspace member (per idea 2) carries all three subsystems (`settings`, `profile_store`, `secret_store`). Public API: `Settings`, `ProfileStore` (trait + `FsProfileStore`), `SecretStore` (trait + `LayeredSecretStore`), and the relevant error / ID / secret-handle types.
- R28. `vortix-config` depends on `vortix-core` (for `Profile`, `Protocol`, shared error types) and `vortix-process` (only for keyring impl which may use platform tools on Linux). The encrypted-file backend uses pure-Rust crypto via `aes-gcm` and `argon2`.

---

## Acceptance Examples

- AE1. **Covers R1, R4, R5.** When a user runs `sudo vortix --engine-retry-budget-secs 600`, and the user's `~/.config/vortix/config.toml` contains `[engine] retry_budget_secs = 60`, and `/etc/vortix/config.toml` contains `[engine] retry_budget_secs = 30`, then the resolved `Settings.engine.retry_budget_secs == 600` (CLI wins). The user file is resolved at the invoking user's home, not root's.

- AE2. **Covers R7, R8, R10.** When migration imports a WireGuard `.conf` with public key `pub_xyz`, then `<config>/profiles/corp.meta.toml` exists with `profile_id = hex(sha256(pub_xyz))`, `protocol = "wireguard"`, `group = ""`, `source = "local-fs"`. A subsequent re-import of the same `.conf` is a no-op (same identity hash).

- AE3. **Covers R9, R11.** Given `<config>/profiles/corp.meta.toml` has `group = ""`, when `vortix profile set-group corp work` is invoked, then only `corp.meta.toml` is modified (atomically), `corp.conf` is untouched, `vortix profile list --group work` returns the profile.

- AE4. **Covers R14, R15, R17.** When vortix runs on macOS with Keychain available, then `SecretStore::set("wg_private_key_<id>", secret)` writes to `Keychain` under service `vortix`, account `wg_private_key_<id>`. When the system has no keyring, the same call writes to `<config>/secrets.enc`.

- AE5. **Covers R16, R17.** When vortix runs on a headless Docker container with no `DBUS_SESSION_BUS_ADDRESS` and no `VORTIX_PASSPHRASE`, then on the first secret store operation, vortix exits with `Err(SecretStoreError::PassphraseRequired)` and JSON envelope `next_actions` includes a hint to set `VORTIX_PASSPHRASE`. With `VORTIX_PASSPHRASE=xyz` set, the same operation succeeds; `secrets.enc` is created with AES-256-GCM-encrypted content.

- AE6. **Covers R19, R21.** When a `Secret` value is dropped, then a memory inspection (in `--release` with the `zeroize` derive applied) shows zero bytes where the secret was. When a subprocess is invoked with a secret-bearing temp file, the `tracing` span records the temp-file path but the file is deleted before the span emits, and the secret bytes never appear in any log.

- AE7. **Covers R22, R23, R24.** When a user upgrades from v0.2.x to v0.3.x, and their `~/.config/vortix/profiles/corp.conf` contains an inline WG private key, then the next `vortix` invocation: (a) writes `corp.conf.pre-migrate` (full backup), (b) rewrites `corp.conf` with `PrivateKey = secret://<id>:wg_private_key`, (c) creates `corp.meta.toml` with schema_version 1, (d) inserts the WG private key into SecretStore, (e) emits a `ProfileMigrationCompleted` event into the journal. The user runs `vortix up corp` and the connection succeeds.

- AE8. **Covers R25.** When migration is re-run (e.g., after a downgrade-then-upgrade), files already containing `secret://` placeholders AND with `schema_version == current` in their sidecar are skipped silently. No double-extraction.

- AE9. **Covers R27.** When a downstream consumer imports `vortix_config::{Settings, ProfileStore, SecretStore}`, then they can construct a `LayeredSecretStore` and a `FsProfileStore` against a custom config path, useful for tests and for Tauri/MCP embedding contexts.

- AE10. **Covers R8.** When the user runs `cat ~/.config/vortix/profiles/corp.meta.toml`, then they see a human-readable TOML file with the schema fields and can edit them manually if needed (then `vortix profile list` reflects the change without restart, or after a re-scan).

---

## Success Criteria

- An end user upgrading from v0.2.x to v0.3.x runs `vortix up corp` after the upgrade and observes no behavior change: same connect latency, same profile, same kill switch. The migration is silent. The `.conf` file still exists in `~/.config/vortix/profiles/`; only its `PrivateKey =` line is replaced with a `secret://` reference, and a sidecar `.meta.toml` is now alongside it.
- A user can still share a profile with `scp corp.conf user@host:` (the secret has to be re-imported on the destination, but the protocol-config portion is portable; `vortix profile export` can produce a self-contained shareable file with secrets re-inlined for cross-machine transfer).
- A user on a headless Linux server (Docker, Pi without GUI) sets `VORTIX_PASSPHRASE` once and uses vortix normally; secrets are encrypted on disk.
- A v0.3.0 contributor implementing profile groups writes UI for grouping; the schema already has the `group` field.
- A v1.0 contributor implementing team management adds a `ProfileSource = "http-fleet:..."` variant + a refresh path; if query performance suffers at scale, replaces `FsProfileStore` with an indexed backend behind the same trait without touching engine, tunnel, or TUI code.
- A security review of vortix v0.3.x verifies that no plain-text WireGuard private keys live in any file in the config directory (`.conf` files contain `secret://` references; actual material lives in keyring or `secrets.enc`).
- The 751-line `src/config.rs` becomes a thin `Settings` struct (~150 lines) plus two focused modules in `crates/vortix-config/`.

---

## Scope Boundaries

- **SQLite or other indexed-DB profile backend** is out of scope. The trait exists; a future `SqliteProfileStore` replaces `FsProfileStore` if and when team-management or fleet-sync needs indexed query performance at scale (1000+ profiles). YAGNI for v0.3.0.
- **Profile versioning (Postgres-MVCC immutable versions + HEAD pointer)** is out of scope. Future store extension; rejected for v1.
- **`ProfileSource` variants beyond v1's three (`local-fs`, `url:...`, `imported-from-text`)** are out of scope. HTTP fleet, Git, S3, KeyringSealed sources land with team-management work (v1.0). Today's `src/core/downloader.rs` (306 lines) folds into the `url:...` source variant.
- **`[theme]` settings section** is out of scope. Added when ROADMAP v0.1.8 theming work begins.
- **`[telemetry]` settings section beyond what idea 3 requires** is out of scope. Future expansion as features need them.
- **Automatic deletion of `.pre-migrate` backup files** is out of scope. They remain until `vortix migrate-profiles --cleanup` is run explicitly. v0.4.0 ships the cleanup command with release notes.
- **Per-secret access-control** (e.g., "this secret can only be read by this UID") is out of scope. SecretStore enforces process-level access via OS keyring permissions and file permissions on `secrets.enc` (mode 0600).
- **GUI-prompt passphrase entry** (e.g., spawning a Cocoa dialog on macOS for the passphrase) is out of scope. Env var, TTY prompt, or `--passphrase-file` flag only.
- **Concurrent multi-instance vortix on the same config dir** is out of scope for v1. Single-user, single-instance assumption; daemon mode (Phase B of idea 4) handles concurrency by being the sole writer.
- **`secret://` placeholder syntax inside `.conf` files breaking compatibility with `wg-quick`/`openvpn` directly** is an intentional consequence — vortix materializes the secret to a temp file before invoking those tools, but `wg-quick up corp.conf` outside of vortix will fail to parse the placeholder. This is the security trade-off: secrets are no longer accidentally readable by tools that don't know about the SecretStore. `vortix profile export --inline-secrets corp > corp-shareable.conf` is the supported way to produce a fully-self-contained file.

---

## Key Decisions

- **Three concerns, one crate (`crates/vortix-config/`).** Settings, ProfileStore, SecretStore are three distinct types/traits/modules but co-located in one workspace member per idea 2. They share enough infrastructure (path resolution, error types, the config dir) to live together; their API surfaces are still cleanly separated.
- **`FsProfileStore` as day-one impl, not SQLite.** YAGNI applied correctly. Today's pain (inline secrets, no metadata home, no group field) is solved by sidecars + secret extraction. SQLite's wins (indexed queries, MVCC, transactional updates) are speculative for v0.3.0 and can land behind the trait if team-mgmt later needs them. Keeps the binary leaner (~500 KB saved), the migration smaller, and profiles still directly readable (`cat corp.conf`, `cat corp.meta.toml`).
- **`ProfileStore` is a trait from day one.** Even though the only impl is file-based, codifying the trait now means a future swap to an indexed backend is a single impl swap, not an engine-wide refactor.
- **Sidecar `.meta.toml` per profile** for metadata (group, imported_at, last_used, source, content-identity hash). Atomic-rename for writes. Human-readable, hand-editable, scriptable.
- **`secret://<id>:<name>` placeholder syntax inside `.conf`/`.ovpn` files** is vortix-internal. The rewritten files are no longer valid input to `wg-quick`/`openvpn` directly — vortix materializes them at connect time. Trade-off: secrets stop accidentally being readable by tools that don't know about SecretStore; cost: `wg-quick up corp.conf` outside vortix doesn't work. `vortix profile export --inline-secrets` covers the share-a-config use case.
- **`Profile` content-address by cryptographic identity** (`SHA-256(WG_pubkey)` for WG, `SHA-256(OVPN_cert_fingerprint)` for OVPN). Matches idea 3 R3 and idea 5 R8.
- **SecretStore: keyring with encrypted-file fallback.** The real security win. Inline secrets stop existing in the config directory. AES-256-GCM with argon2id is standard, conservative.
- **`SecretRef` is opaque and serializable; never carries secret material.** `Secret(Vec<u8>)` zeroizes on drop. Subprocess invocations use temp files for secrets (not args), with the path marked `redact_in_audit`.
- **Migration is automatic, non-destructive, idempotent.** Users observe a one-time silent migration; `.conf.pre-migrate` backups remain for one minor version; failures don't corrupt state.
- **Big-bang single PR.** Matches the user's pattern through ideas 1-6. The three subsystems are small enough individually to land coherently in one diff.
- **`vortix-config` doesn't depend on `vortix-process`** (or only depends for keyring's Linux Secret Service backend which is internal to the keyring crate, not a direct dep). The encrypted-file backend uses pure-Rust crypto (`aes-gcm`, `argon2`), not subprocess crypto tools.

---

## Dependencies / Assumptions

- **Idea 2 (workspace split) lands before this PR.** `crates/vortix-config/` is a workspace member.
- **Idea 5 (`Tunnel` trait) lands before or alongside this PR.** Migration uses `Tunnel::parse_profile` to extract identity; without it, migration code would duplicate per-protocol parsing.
- **Idea 3 (FSM + journal) lands before or alongside this PR.** Settings supplies the journal config; migration emits journal events.
- **New deps in `Cargo.toml`:** `figment`, `keyring` v3, `aes-gcm`, `argon2`, `zeroize`, `directories` (replacing `dirs = "6"`). No `rusqlite` (saved binary weight). Each new dep is well-maintained and widely used.
- **`keyring` v3 on Linux** depends on Secret Service via DBus. Requires `gnome-keyring`, `KeePassXC`, or another Secret Service implementation. On systems without one, the encrypted-file fallback takes over.
- **`argon2id` parameters** for the encrypted-file passphrase are conservative: 64 MB memory, 3 iterations. Tunable in `Settings` if needed; default sized for laptops and small servers.
- **`VORTIX_PASSPHRASE` env var** is the recommended way to supply the passphrase in daemon contexts (systemd `EnvironmentFile=`, Docker `--env-file`).
- **Migration runs at startup before any engine work**, so a botched migration prevents the engine from starting and is visible immediately.
- **Existing `dirs = "6"` dep** is replaced by `directories`. The two crates resolve to the same paths on the major desktop platforms.
- **`.meta.toml` sidecar files are TOML for readability**; users can `cat` them and `vim` them. TOML is already a dep (`toml = "1.1"`).

---

## Outstanding Questions

### Resolve Before Planning

(None — all material decisions resolved in the synthesis.)

### Deferred to Planning

- [Affects R7, R11][Technical] Whether `FsProfileStore` should cache the result of `list()` in memory (refresh on directory mtime change) or re-scan every call. For ≤200 profiles re-scan is trivial; cache is an easy optimization. Planner picks.
- [Affects R8][Technical] Whether the sidecar should be named `.meta.toml` (sibling) or stored as a single combined `corp.toml` that embeds both the protocol config and metadata. Sibling is recommended (keeps `.conf` directly readable + parseable separately); planner verifies.
- [Affects R21][Technical] Per-protocol detail: how each protocol's tunnel impl materializes secrets at connect time (stdin to `wg setconf` vs temp file for `openvpn --config`). Mechanical detail; idea 5's tunnel impls own it.
- [Affects R14, R15, R17][Technical] How `LayeredSecretStore` records the chosen backend for subsequent invocations — a small `<config>/secret_backend.toml` file, or a field in `Settings`, or runtime re-probe each startup. Re-probe each startup is simplest; planner picks.
- [Affects R12][Technical] How to handle race between `vortix up` writing `last_used` and `vortix profile list` reading sidecars. Atomic-rename + retry-on-EEXIST is the standard pattern; planner verifies edge cases.
- [Affects R23][Technical] How to handle OpenVPN's `auth-user-pass <file>` directive: import the file contents into SecretStore and remove the directive from the rewritten `.ovpn` (engine re-materializes), OR leave the directive and migrate the file separately. The first is recommended.
- [Affects R5][Technical] Whether SUDO_USER home resolution should also apply to the system file at `/etc/vortix/config.toml`. Probably not — `/etc` is system-wide regardless of `sudo`. Planner verifies edge cases.
- [Affects R26][Technical] Exact event-name and fields for migration journal events. Mechanical.
