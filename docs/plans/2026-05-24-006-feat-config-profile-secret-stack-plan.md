---
date: 2026-05-24
title: "feat: Config + Profile + Secret stack (file-based ProfileStore + keyring)"
status: active
type: feat
origin: docs/brainstorms/2026-05-24-config-profile-secret-stack-requirements.md
prerequisite: docs/plans/2026-05-24-005-feat-engine-fsm-event-journal-plan.md
---

# feat: Config + Profile + Secret stack (file-based ProfileStore + keyring)

## Summary

The final architectural PR of the 6-PR migration. Replace today's 751-line `crates/vortix-config/src/lib.rs` (relocated there from `src/config.rs` by plan #001) with three crisp concerns inside the same crate:
- **`Settings`** via `figment` — layered defaults < `/etc/vortix/config.toml` < `<XDG_CONFIG_HOME>/vortix/config.toml` < `VORTIX_*` env vars < CLI flags, with SUDO_USER home resolution preserved.
- **`ProfileStore`** as a trait with day-one **file-based impl** (`FsProfileStore`): keeps `.conf`/`.ovpn` files as source of truth; adds per-profile sidecar metadata at `<profile>.meta.toml` (group, imported_at, last_used, source, content-identity hash). **Not SQLite** — file-based per user redirect during brainstorm. The trait exists so future indexed backends can replace it without touching engine, tunnel, or TUI code.
- **`SecretStore`** backed by `keyring` v3 (Keychain / Secret Service / Credential Manager) with an encrypted-file fallback for headless Linux (`<config>/secrets.enc`, AES-256-GCM, passphrase from `VORTIX_PASSPHRASE` env var or interactive prompt).

Migration is automatic + idempotent + non-destructive on first startup post-upgrade. Inline `PrivateKey =` lines in `.conf` files become `PrivateKey = secret://<id>:wg_private_key` placeholder references; secret material moves to keyring (or `secrets.enc`). The real security win.

---

## Problem Frame

After plans #001–#005 land:
- The workspace is fully refactored: engine FSM + EngineHandle in `vortix-core`, capability ports per-OS in `vortix-platform-*`, tunnel trait + WG/OVPN crates, CommandRunner everywhere.
- BUT: `crates/vortix-config/src/lib.rs` is still the 751-line monolith that plan #001 relocated as-is. Config dir resolution, the `Settings` struct, profile path helpers, OpenVPN auth-file path management, and killswitch state file location all conflate in one module. Profile metadata has no persistent home; profile groups (v0.3.0) can't land cleanly; profiles store secrets inline in `.conf`/`.ovpn` files at default umask.
- The engine consumes `vortix_config::get_config_dir()` and other process-globals via `OnceLock`; this works but doesn't scale to v1.0 team management or config encryption.

This PR finishes the architecture story. After it lands, every v0.3.0 and v1.0 ROADMAP item (profile groups, daemon mode, lifecycle hooks, audit logging, config encryption, team management) sits on top of cleanly separated layers.

---

## System-Wide Impact

- **End users (security win):** Inline plaintext WireGuard private keys stop existing in the config directory. Same connect/disconnect UX; same connect latency; behind the scenes, secrets live in keyring (or AES-256-GCM-encrypted `secrets.enc`).
- **End users on headless Linux:** With `VORTIX_PASSPHRASE` set (one-time), vortix works as a daemon on Docker / Pi / server contexts where Secret Service isn't available.
- **End users post-upgrade:** First `vortix up corp` after the upgrade triggers a silent automatic migration. Original `.conf` files are kept as `.pre-migrate` backups for one minor version. Behavior is identical.
- **Future v0.3.0 profile groups:** Adds a UI for setting/filtering `group`; the field is already in the `.meta.toml` schema.
- **Future v1.0 team management:** Adds a `ProfileSource::HttpFleet { fleet_url, fetched_at }` variant + a refresh path; schema accommodates.
- **Future indexed backend (if team-mgmt demands):** Replaces `FsProfileStore` with `SqliteProfileStore` behind the trait. Zero changes to engine, tunnel, or TUI code.
- **Trade-off:** Rewritten `.conf` files (with `secret://` placeholders) are no longer valid input to `wg-quick` directly. `vortix profile export --inline-secrets <name>` produces a self-contained shareable file when needed.
- **Dependency footprint:** Adds `figment`, `keyring` (v3), `aes-gcm`, `argon2`, `zeroize`, `directories`. Drops `dirs = "6"` (replaced by `directories`). No new top-level binary deps.

---

## Key Technical Decisions

- **Three concerns, one crate.** Settings, ProfileStore, SecretStore co-located in `vortix-config` with separate modules + APIs. (Origin: brainstorm Key Decisions.)
- **`FsProfileStore` as day-one impl, NOT SQLite.** Per user redirect during brainstorm: "I mean what's the issue with existing storage of profile files." The real wins are secret extraction + sidecar metadata; SQLite is speculative for v0.3.0. (Origin: brainstorm Key Decisions, user redirect.)
- **`ProfileStore` is a trait from day one** even though only one impl ships. Codifies the abstraction so a future SQLite-backed swap is one impl change. (Origin: brainstorm R7.)
- **Sidecar `<profile>.meta.toml` per profile** for metadata (`group`, `imported_at`, `last_used`, `source`, `profile_id`). Atomic-rename writes. Human-readable, hand-editable. (Origin: brainstorm R8.)
- **`secret://<id>:<name>` placeholder syntax inside `.conf`/`.ovpn` files.** Vortix-internal; vortix materializes secrets to temp files at connect time. Trade-off: `wg-quick up corp.conf` outside vortix doesn't work. `vortix profile export --inline-secrets` covers the share use case. (Origin: brainstorm Key Decisions.)
- **`SecretStore`: keyring with encrypted-file fallback** (AES-256-GCM, argon2id key derivation). (Origin: brainstorm R12, R14, R15.)
- **`Profile` content-address by cryptographic identity** (SHA-256 of WG pubkey / OVPN cert fingerprint). Matches plan #005's R3 (stable identity) and plan #004's R8. (Origin: brainstorm R10.)
- **`SecretRef` is opaque and serializable; never carries secret material.** `Secret(Vec<u8>)` zeroizes on drop. (Origin: brainstorm R17, R18.)
- **Migration is automatic, non-destructive, idempotent.** One-time silent migration; `.pre-migrate` backups for one minor version. (Origin: brainstorm R21-R26.)
- **Big-bang single PR.** (Origin: brainstorm Key Decisions.)
- **`vortix-config` doesn't depend on `vortix-process`.** Encrypted-file backend uses pure-Rust crypto. (Origin: brainstorm R28.)
- **Day-one Settings schema is only what plan #005 needs.** `[engine]`, `[journal]`, `[ui]`. No `[theme]` (waits for v0.1.8). (Origin: brainstorm R1, R3.)

---

## Implementation Units

### U1. Define `Settings` struct + `figment`-layered resolution

**Goal:** Replace the bespoke config loading with figment.

**Requirements:** R1, R2, R3, R4, R5, R6

**Dependencies:** Plans #001–#005 complete.

**Files (new):**
- `crates/vortix-config/src/settings.rs`: `pub struct Settings { engine: EngineSettings, journal: JournalSettings, ui: UiSettings }`, with nested struct for each section. Each field has a serde default.
- `crates/vortix-config/src/sudo_user.rs`: helper that resolves the user file path honoring SUDO_USER (preserves today's behavior from the existing 751-line config.rs).
- `crates/vortix-config/src/error.rs`: `SettingsError`, `ConfigError`.

**Files (modifications):**
- `crates/vortix-config/Cargo.toml`: replace `dirs = "6"` with `directories = { workspace = true }`. Add `figment = { workspace = true, features = ["toml", "env"] }`, `serde = { workspace = true, features = ["derive"] }`, `thiserror = { workspace = true }`.
- `crates/vortix-config/src/lib.rs`: replace the relocated 751-line file content with module declarations: `pub mod settings; pub mod profile_store; pub mod secret_store; mod sudo_user;`.

**Approach:**
- `Settings::load() -> Result<Settings, SettingsError>` constructs the figment stack: `Figment::new().merge(defaults()).merge(Toml::file("/etc/vortix/config.toml")).merge(Toml::file(sudo_user::user_config_path()?)).merge(Env::prefixed("VORTIX_")).merge(Serialized::defaults(cli_args))`. Extract to `Settings`.
- `EngineSettings { retry_budget_secs: u64 = 300, retry_initial_backoff_ms: u64 = 2000 }` — consumed by plan #005's FSM.
- `JournalSettings { disk: bool = true, retention_days: u32 = 30, retention_count: u32 = 30 }` — consumed by plan #005's journal.
- `UiSettings { start_mode: StartMode = Tui }` — consumed by main.rs (default mode picker).
- Preserve the existing `set_config_dir(PathBuf)` and `get_config_dir() -> Result<PathBuf>` API from today's config.rs as a backwards-compat shim during the migration; remove in a future PR.

**Test scenarios:**
- `crates/vortix-config/tests/settings.rs`:
  - **Happy path — CLI wins (AE1):** Mock `figment` with defaults < user file (retry_budget_secs=60) < env (`VORTIX_ENGINE_RETRY_BUDGET_SECS=90`) < CLI (600). Extract. Assert `engine.retry_budget_secs == 600`.
  - **SUDO_USER resolution:** Mock `sudo_user::user_config_path` to return the invoking user's path (not root's) when SUDO_USER env var is set. Assert the user file from that path is read.
  - **Default fallthrough:** No system file, no user file, no env, no CLI. Assert all defaults applied.
  - **Error path — invalid TOML:** User file has `retry_budget_secs = "abc"`. Assert `Err(SettingsError::TypeMismatch { .. })`.

**Verification:** `Settings::load()` produces an immutable settings value with correct precedence. The `OnceLock`-based config-dir resolution is preserved.

---

### U2. Define `ProfileStore` trait + implement `FsProfileStore`

**Goal:** Filesystem-backed profile storage with sidecar metadata.

**Requirements:** R7, R8, R9, R10, R11, R12, R13

**Dependencies:** U1; plan #004 (Profile / ParsedProfile types in `vortix-core`).

**Files (new):**
- `crates/vortix-config/src/profile_store/mod.rs`: `pub trait ProfileStore` with the methods enumerated in brainstorm R11 (`list`, `get`, `insert`, `update`, `delete`, `find_by_display_name`). Async. `#[non_exhaustive]`-sealed.
- `crates/vortix-config/src/profile_store/fs.rs`: `FsProfileStore { profiles_dir: PathBuf, tunnel_factory: Arc<dyn TunnelFactory> }`. Implements the trait.
- `crates/vortix-config/src/profile_store/sidecar.rs`: `Sidecar { schema_version: u32, profile_id: String, display_name: String, protocol: Protocol, group: String, source: String, imported_at: i64, last_used: Option<i64> }`. Serde-(de)serialize via TOML.
- `crates/vortix-config/src/profile_store/error.rs`: `ProfileStoreError`.

**Files (modifications):**
- `crates/vortix-config/Cargo.toml`: add `vortix-core = { path = "../vortix-core" }, tokio = { workspace = true, features = ["fs"] }, toml = { workspace = true }, time = { workspace = true }`.

**Approach:**
- `FsProfileStore::list()`:
  1. Async-walk `<profiles_dir>/*.{conf,ovpn}` files.
  2. For each, read sibling `<name>.meta.toml`. Parse via `toml::from_str`.
  3. Return `Vec<ProfileSummary>` — the cheap-list-view (id, display_name, protocol, group, last_used). Does NOT materialize parsed-profile blobs.
- `FsProfileStore::get(id_or_name)`:
  1. Find the matching `.conf`/`.ovpn` file (via sidecar `profile_id` match if id-form, or filename match if name-form).
  2. Read the raw file bytes; pass to `tunnel.parse_profile(raw)` to get the `ParsedProfile`.
  3. Read sidecar metadata; merge into `Profile { id, display_name, protocol, group, source, imported_at, last_used, parsed: ParsedProfile, secrets: HashMap<SecretName, SecretRef> }`.
- `FsProfileStore::insert(profile)`:
  1. Compute file path: `<profiles_dir>/<display_name>.<ext>`.
  2. Atomic-rename write of both files (`.tmp` + rename for each).
  3. Collision on `profile_id` (sidecar match elsewhere in dir) is idempotent: update `last_used` and `display_name` only.
- `FsProfileStore::update(id, mut_fn)`:
  1. Load sidecar, apply mutation closure, atomic-write back. `.conf`/`.ovpn` file untouched.
- `FsProfileStore::delete(id)`:
  1. Delete `.conf`/`.ovpn`, `.meta.toml`, `.pre-migrate` (if present).
  2. Call `SecretStore::delete_for_profile(id)` to remove all associated secrets.

**Test scenarios:**
- `crates/vortix-config/tests/profile_store_fs.rs`:
  - **Happy path — list:** Pre-populate a temp dir with 3 profiles (each with `.conf` + `.meta.toml`). Call `list()`. Assert 3 summaries returned with correct IDs and groups.
  - **Happy path — get:** Pre-populated profile. Call `get("corp")`. Assert returned `Profile` carries correct fields, the parsed-profile body is parseable.
  - **Insert idempotency (AE2):** Insert a profile with id `H1`. Insert again with same id but different `last_used`. Assert single sidecar; `last_used` updated.
  - **Update group (AE3):** Insert profile. Call `update(id, |p| p.group = "work")`. Assert sidecar's `group` field updated to "work"; `.conf` untouched.
  - **Delete:** Insert profile. Delete it. Assert no files for that profile remain; assert `SecretStore::delete_for_profile` was called.
  - **Concurrent insert race:** Two concurrent inserts of profiles with same `display_name` but different IDs (corner case). Atomic-rename should resolve; one wins, the other gets a clear error.
  - **Sidecar absent edge case:** Profile `.conf` exists with no `.meta.toml` (i.e., user dropped a fresh `.conf`). `list()` either: (a) emits a `MigrationRequired` event and returns the profile with default metadata, OR (b) blocks and tells the user to run migration. Recommend (a).

**Verification:** Profile store tests pass. Sidecar files are human-readable TOML.

---

### U3. Implement `SecretStore` trait + `LayeredSecretStore` (keyring + encrypted-file fallback)

**Goal:** OS-keyring-backed secrets with encrypted-file fallback for headless.

**Requirements:** R12, R13, R14, R15, R16, R17, R18, R19, R20, R21

**Dependencies:** U1

**Files (new):**
- `crates/vortix-config/src/secret_store/mod.rs`: `pub trait SecretStore` with async methods `get(ref)`, `set(name, secret)`, `delete(ref)`, `delete_for_profile(profile_id)`. `SecretRef` and `Secret` types.
- `crates/vortix-config/src/secret_store/keyring.rs`: `KeyringSecretStore` impl using `keyring` v3 crate.
- `crates/vortix-config/src/secret_store/encrypted_file.rs`: `EncryptedFileSecretStore` impl. AES-256-GCM + argon2id.
- `crates/vortix-config/src/secret_store/layered.rs`: `LayeredSecretStore { backend: SecretBackend }`. At construction, probes for keyring availability; stores chosen backend.
- `crates/vortix-config/src/secret_store/error.rs`: `SecretStoreError`.

**Files (modifications):**
- `crates/vortix-config/Cargo.toml`: add `keyring = { version = "3", features = ["default"] }, aes-gcm = "0.10", argon2 = "0.5", zeroize = { version = "1", features = ["derive"] }`.

**Approach:**
- `Secret(Vec<u8>)` newtype with `#[derive(Zeroize, ZeroizeOnDrop)]`. Deref to `&[u8]`. No `Display`/standard `Debug` — implement redacting `Debug` manually.
- `SecretRef { backend: SecretBackendTag, id: String }` where `SecretBackendTag` is `Keyring | EncryptedFile`. Serde-serializable for storage in sidecars and journal events.
- `LayeredSecretStore::new(config: &SecretStoreConfig)`:
  1. Try `KeyringSecretStore::probe()` — attempt to read a known sentinel key. If success → keyring chosen.
  2. If keyring fails → fall back to `EncryptedFileSecretStore::new(passphrase_source)`. Passphrase source: `VORTIX_PASSPHRASE` env, TTY prompt (when interactive), or `--passphrase-file <path>`. If no source and `secrets.enc` doesn't exist → `Err(SecretStoreError::PassphraseRequired)`.
- `KeyringSecretStore::set(name, secret)`: `Entry::new("vortix", &name)?.set_password(base64_encode(secret.as_bytes()))?`. (Or use `set_secret` if keyring v3 supports binary directly — verify during implementation.)
- `EncryptedFileSecretStore::set(name, secret)`:
  1. Decrypt the existing `secrets.enc` (if present) into an in-memory `HashMap<String, Vec<u8>>`.
  2. Insert/update the entry.
  3. Re-encrypt: generate new nonce, AES-256-GCM-encrypt the serialized HashMap, write with `<salt><nonce><ciphertext>` header.
  4. Atomic rename `.tmp` → `secrets.enc`.
- `EncryptedFileSecretStore::get(ref)`: decrypt file, look up by `ref.id`, return `Secret(Vec<u8>)`. The in-memory HashMap is dropped on function exit (zeroized).
- `argon2id` parameters: 64 MB memory, 3 iterations, salt is 16 random bytes stored in the file header.

**Test scenarios:**
- `crates/vortix-config/tests/secret_store.rs`:
  - **Happy path — keyring (AE4):** Mock the `keyring` crate to succeed. `LayeredSecretStore::new(...)` selects keyring. `set("test_key", secret_bytes)` succeeds. `get(ref)` returns the same bytes.
  - **Fallback — encrypted file (AE5):** Mock keyring to fail with `NoStorageAccess`. Set `VORTIX_PASSPHRASE=test123`. Construct `LayeredSecretStore`. Assert backend is `EncryptedFile`. `set` + `get` round-trip succeeds.
  - **Error — no passphrase, no TTY:** Mock keyring fail; clear `VORTIX_PASSPHRASE`; non-TTY env. `set` call returns `Err(SecretStoreError::PassphraseRequired)`.
  - **Error — wrong passphrase:** Pre-create `secrets.enc` with one passphrase; reconstruct `LayeredSecretStore` with a different `VORTIX_PASSPHRASE`. `get` returns `Err(SecretStoreError::DecryptionFailed)`.
  - **Zeroize verification (AE6):** Get a `Secret`, drop it explicitly, manually peek at the memory — verify zero bytes. (Requires `--release` mode with `zeroize::derive`.)
  - **`delete_for_profile`:** Set 3 secrets for `profile_id = H1`. Call `delete_for_profile(H1)`. Assert all 3 gone.

**Verification:** Secret store tests pass. Both backends round-trip correctly. Zeroize works.

---

### U4. Implement automatic migration from existing `.conf`/`.ovpn` files

**Goal:** First-startup migration: extract inline secrets, write sidecars, preserve backups.

**Requirements:** R22, R23, R24, R25, R26

**Dependencies:** U1, U2, U3; plan #004 (Tunnel::parse_profile per protocol); plan #005 (journal events).

**Files (new):**
- `crates/vortix-config/src/migration/mod.rs`: `migrate_if_needed(profiles_dir, profile_store, secret_store, tunnel_factory, journal) -> Result<MigrationReport, MigrationError>`.
- `crates/vortix-config/src/migration/wireguard.rs`: WG-specific migration. Reads `.conf`, extracts `[Interface] PrivateKey = <base64>`, rewrites the file with `PrivateKey = secret://<id>:wg_private_key`. Inserts the secret into SecretStore.
- `crates/vortix-config/src/migration/openvpn.rs`: OVPN-specific migration. Reads `.ovpn`, extracts inline `<key>` blocks and external `auth-user-pass` file references, rewrites with placeholders.

**Files (modifications):**
- `crates/vortix/src/main.rs`: at startup (after `Settings::load()`, before constructing engine), call `migrate_if_needed(...)`. If migration runs, log a one-line summary to stderr and emit a journal event (plan #005's `ProfileMigrationCompleted`).

**Approach:**
- Detect migration: scan `<profiles_dir>/*.{conf,ovpn}`. For each, check if a `.meta.toml` sibling exists OR if the file content contains `secret://` placeholders. If both absent → migration target.
- Per-file migration sequence:
  1. Write `<profile>.conf.pre-migrate` (full content backup).
  2. Parse via `tunnel.parse_profile(raw)` (plan #004) to extract cryptographic identity.
  3. Compute `profile_id = hex(SHA-256(identity))`.
  4. Extract inline secrets:
     - WG: regex `(?m)^PrivateKey\s*=\s*(\S+)$` — capture base64 key.
     - OVPN: regex for `<key>...</key>` blocks; the `<cert>...</cert>` blocks may be considered non-secret (public cert) and left inline — verify during impl.
     - OVPN `auth-user-pass <file>` references: load file contents, extract username + password.
  5. Insert each secret into `SecretStore` under derived name (`<profile_id>:wg_private_key`, `<profile_id>:ovpn_auth_user_pass`).
  6. Rewrite the `.conf`/`.ovpn`: replace inline secrets with `secret://<id>:<name>` placeholders.
  7. Write `<profile>.meta.toml` sidecar with `schema_version = 1`, `profile_id`, `display_name` (from filename without extension), `protocol`, `imported_at = now`, `source = "local-fs"`, `group = ""`.
- Idempotent: re-running on already-migrated files (sidecars present AND schema_version current AND `secret://` placeholders present) is a no-op.
- Per-file failures emit `ProfileMigrationFileSkipped { path, reason }` events but don't abort the rest.

**Test scenarios:**
- `crates/vortix-config/tests/migration.rs`:
  - **Happy path — WG migration (AE7):** Pre-populate temp dir with `corp.conf` containing inline `PrivateKey = base64xyz`. Run migration. Assert: `corp.conf.pre-migrate` exists with original content; `corp.conf` contains `PrivateKey = secret://<id>:wg_private_key`; `corp.meta.toml` exists with `schema_version = 1`; `SecretStore::get` returns the base64-decoded key.
  - **OVPN migration:** Similar with `.ovpn` file containing inline `<key>` block + external `auth-user-pass corp.auth` file.
  - **Idempotency (AE8):** Run migration twice. Second run: zero changes (no new `.pre-migrate` file, no new sidecar overwrites).
  - **Partial failure:** Two `.conf` files; one is malformed (parse_profile fails). Assert: malformed one emits `ProfileMigrationFileSkipped`, other completes normally; both `ProfileMigrationCompleted` event has `count: 1, secrets_extracted: 1`.
  - **Re-run after partial:** First run skips the malformed one. User fixes the malformed file. Second run successfully migrates it.

**Verification:** Migration tests pass. Original files preserved as backups.

---

### U5. Integrate `Tunnel` impls (plan #004) with `SecretStore` for secret materialization

**Goal:** When a tunnel runs, materialize secrets from SecretStore into temp files (or stdin) for the subprocess.

**Requirements:** R21

**Dependencies:** U3; plan #004 (Tunnel impls).

**Files (modifications):**
- `crates/vortix-protocol-wireguard/src/tunnel.rs::WgTunnel::up`:
  1. Before invoking `wg-quick up`, materialize the `[Interface] PrivateKey` from the `Profile.secrets["wg_private_key"]` `SecretRef`: `let secret = secret_store.get(ref).await?;`.
  2. Write a transient WG config to a temp file at `<runtime_dir>/wg-<pid>-<rand>.conf` (mode 0600) with the secret inlined. Mark the file path as `redact_in_audit` on the subprocess spec.
  3. Invoke `wg-quick up <temp_file_path>`.
  4. Delete the temp file immediately after the subprocess returns (success or failure — `Drop` guard or explicit cleanup).
- `crates/vortix-protocol-openvpn/src/tunnel.rs::OvpnTunnel::up`: similar pattern for OVPN auth file. Materialize `wg_private_key` equivalent (cert/key blocks) into temp files; `--config <temp>.ovpn` and `--auth-user-pass <temp>.auth`.

**Approach:**
- The temp file lifecycle is critical for security: written at 0600, deleted on success/failure. RAII guard pattern.
- `runtime_dir` resolved via `directories::ProjectDirs::runtime_dir()` (typically `$XDG_RUNTIME_DIR/vortix/`) on Linux; on macOS, `~/Library/Caches/vortix/runtime/`.

**Test scenarios:**
- `crates/vortix-protocol-wireguard/tests/tunnel_secret_materialization.rs`:
  - **Happy path:** Mock `SecretStore::get` to return known bytes. Mock `runner.run("wg-quick", ...)` to capture the spec. Run `up`. Assert the spec's temp-file argument exists during invocation, contains the secret. After return: assert temp file deleted.
  - **Secret-fetch failure:** Mock `SecretStore::get` to return `NotFound`. Assert `up` returns `Err(TunnelError::SecretUnavailable { ref })` without running `wg-quick`.
  - **Subprocess failure with cleanup:** Mock `runner.run` to return `NonZeroExit`. Assert temp file is still deleted (RAII).
  - **`redact_in_audit` is set:** Mock the runner; capture the CommandSpec. Assert `redact_in_audit` contains the index of the temp-file arg.

**Verification:** Tunnel impls fetch secrets via SecretStore; temp files cleaned up; subprocess args marked for redaction.

---

### U6. `vortix profile export --inline-secrets` command

**Goal:** Support the share-a-config use case — produce a self-contained `.conf` with secrets inlined.

**Requirements:** Brainstorm Scope Boundaries (the `secret://` placeholder syntax trade-off)

**Dependencies:** U2, U3, U5

**Files (modifications):**
- `crates/vortix/src/cli/args.rs`: add `Profile::Export { name: String, inline_secrets: bool, output: Option<PathBuf> }` to the Profile subcommand enum.
- `crates/vortix/src/cli/commands.rs`: handle the Export command. Load profile from `ProfileStore`, fetch secrets via `SecretStore::get` for each `SecretRef`, write the resulting fully-inlined `.conf` to stdout or the given output path.
- `crates/vortix/src/cli/output.rs`: ensure the export JSON envelope notes that secrets are inlined (security note in the response).

**Approach:**
- Without `--inline-secrets`, the export emits the `.conf` with `secret://` placeholders (useful for sharing the *structure* without secrets).
- With `--inline-secrets`, secrets are materialized inline. The output is a normal `wg-quick`-readable `.conf` file. Document in CLI help that this file contains secrets and should be deleted after use.

**Test scenarios:**
- `crates/vortix/src/cli/tests/export.rs`:
  - **Happy path:** Pre-populate ProfileStore + SecretStore with `corp` profile. Run `vortix profile export --inline-secrets corp`. Capture stdout. Assert it's a valid `wg-quick`-readable file with the WG private key inlined.
  - **Without `--inline-secrets`:** Stdout contains `secret://` placeholders.

**Verification:** Export command works.

---

### U7. Wire it all up in `main.rs`; remove the existing `OnceLock` config-dir global

**Goal:** Replace the process-wide globals with explicit dependency injection through the EngineHandle's construction.

**Requirements:** Brainstorm R27 (single public API surface)

**Dependencies:** U1, U2, U3, U4

**Files (modifications):**
- `crates/vortix/src/main.rs`:
  1. Replace `vortix_config::set_config_dir(...)` + `get_config_dir()` global calls with: `let settings = Settings::load(cli_args)?; let profile_store = FsProfileStore::new(&settings)?; let secret_store = LayeredSecretStore::new(&settings)?;`.
  2. Call `migration::migrate_if_needed(&profiles_dir, &profile_store, &secret_store, &tunnel_factory, &journal).await?` before constructing the engine.
  3. Construct `EngineHandle` (plan #005) with the new stores injected: `EngineHandle::Local::new(engine_config, profile_store, secret_store, journal, runner, platform)`.
- `crates/vortix-config/src/lib.rs`: deprecate the `OnceLock<PathBuf>`-based `set_config_dir`/`get_config_dir` API. Keep as a thin shim for one minor version; remove in v0.4.0.

**Approach:**
- The Engine, Tunnel impls, and migrators all receive their `Arc<dyn ProfileStore>` and `Arc<dyn SecretStore>` via constructor injection. No more process-globals for these.
- `Settings`-derived constants (retry budget, journal retention) flow into the relevant components via their constructors.

**Test scenarios:**
- *Integration verification via existing `tests/cli_integration.rs` — should pass unchanged.*

**Verification:** `cargo build --workspace` succeeds. Existing CLI integration tests pass.

---

### U8. Docs + post-migration release notes

**Goal:** Document the migration for users.

**Requirements:** Brainstorm Scope Boundaries (`.pre-migrate` cleanup for v0.4.0)

**Dependencies:** All prior units.

**Files (modifications):**
- `README.md`: add a "Secrets" section noting that vortix stores secrets in OS keyring by default with an encrypted-file fallback.
- `ROADMAP.md`: update to reflect that the architectural migration is complete (all 6 PRs landed).
- `RELEASING.md`: add a note about the `.pre-migrate` cleanup command shipping in v0.4.0.
- `docs/MIGRATION.md` (new): user-facing migration guide. Covers:
  - "What changed in v0.3.0": secrets moved to keyring, profiles get sidecars, original files backed up as `.pre-migrate`.
  - "Headless Linux setup": one-time `VORTIX_PASSPHRASE` env var setup.
  - "Sharing profiles": use `vortix profile export --inline-secrets`.
  - "Cleaning up backups": `vortix migrate-profiles --cleanup` ships in v0.4.0.

**Test scenarios:**
- *Test expectation: none — documentation.*

**Verification:** User-facing docs reflect the new layer.

---

## Verification Strategy

- `cargo build --workspace --all-targets --locked` succeeds.
- `cargo test --workspace --all-targets` passes — all new tests + all existing tests.
- All four `xtask` lints pass (`check-subprocess`, `check-platform-leak`, `check-protocol-leak`, plus a new `check-config-leak` if useful).
- Manual smoke test on the maintainer's machine: connect to existing WG profile; observe identical behavior. Verify `~/.config/vortix/profiles/corp.conf` now contains `PrivateKey = secret://...` placeholder, and the original is at `corp.conf.pre-migrate`. Verify `corp.meta.toml` exists with the metadata.
- Verify secret storage:
  - macOS: `security find-generic-password -s "vortix" -a "<profile_id>:wg_private_key"` returns the entry.
  - Linux: `secret-tool lookup service vortix account "<profile_id>:wg_private_key"` returns it (requires gnome-keyring).
  - Headless: set `VORTIX_PASSPHRASE=test`, verify `secrets.enc` is created with AES-256-GCM-encrypted content.
- Verify the security win: `cat ~/.config/vortix/profiles/corp.conf` shows no plaintext private key.
- Run `vortix profile export --inline-secrets corp` and verify the output is a valid `wg-quick`-readable file.
- Run `vortix list --json` and verify the output structure includes group, last_used, source fields.

---

## Risks & Mitigations

- **Migration data loss.** If migration fails mid-write, the user could end up with a half-rewritten `.conf` and a `.pre-migrate` backup. Mitigation: write `.pre-migrate` FIRST (full backup) before any other operation; per-file atomic-rename writes; emit per-file events to the journal so failures are recoverable.
- **`keyring` v3 on Linux is unreliable on some distros.** Mitigation: explicit probe at startup; encrypted-file fallback. Document the probe behavior.
- **`argon2id` memory cost (64 MB) may be too high for some systems.** Mitigation: configurable via `[secret_store] argon2_memory_mb` setting; default conservative for laptops.
- **`secret://` placeholder syntax breaks `wg-quick`-direct usage.** Mitigation: `vortix profile export --inline-secrets` for the share use case; document in MIGRATION.md.
- **OpenVPN inline `<cert>` vs `<key>` distinction.** Certs are public; keys are secret. Migration must distinguish. Mitigation: extract only `<key>` blocks (and `<tls-auth>` keys); leave `<cert>` blocks inline.
- **`auth-user-pass <file>` external file migration.** Today's code reads this file at connect time; migration must read it, store in SecretStore, and remove the `auth-user-pass` line from the rewritten `.ovpn`. Mitigation: explicit handling in U4; tests for this edge case.
- **Concurrent multi-instance vortix could race on sidecar writes.** Mitigation: documented as out-of-scope for v1; single-user, single-instance assumption. Phase B daemon mode handles concurrency by being the sole writer.

---

## Scope Boundaries

- **SQLite or other indexed-DB ProfileStore backend** — out of scope. Trait exists; replacement happens when team-mgmt demands.
- **Profile versioning (MVCC immutable versions + HEAD pointer)** — out of scope.
- **`ProfileSource` variants beyond `local-fs`, `url:...`, `imported-from-text`** — out of scope.
- **`[theme]` and other Settings sections beyond what plan #005 needs** — out of scope.
- **Automatic deletion of `.pre-migrate` backups** — out of scope. `vortix migrate-profiles --cleanup` ships in v0.4.0.
- **Per-secret access-control** — out of scope.
- **GUI-prompt passphrase entry** — out of scope.
- **Concurrent multi-instance vortix on same config dir** — out of scope.
- **Behavior changes beyond the security win** — out of scope.

### Deferred to Follow-Up Work

- `vortix migrate-profiles --cleanup` command (v0.4.0).
- `vortix migrate-secrets` for users on systems that gain keyring support post-install.
- Schema migrations for journal `schema_version` and sidecar `schema_version` increments (when v2 first ships).
- Indexed ProfileStore backend (SQLite or similar) when team-management requires it.
- `ProfileSource::HttpFleet` and other remote source variants (v1.0 team management).

---

## Outstanding Questions

### Resolve Before Planning

(None.)

### Deferred to Implementation

- Exact `Settings::load` precedence behavior under edge cases (env var with mixed-case name, CLI flag overriding only a single field of a nested struct, etc.). Mechanical; ce-work picks consistent with figment's defaults.
- Whether to use `keyring v3`'s sync API with `tokio::task::spawn_blocking` or to wait for a hypothetical async-native keyring crate. Recommend `spawn_blocking` for v1.
- Exact `argon2id` salt + nonce storage format in `secrets.enc`. Recommend a small header: `version: u8, salt: [u8; 16], nonce: [u8; 12], ciphertext_len: u32, ciphertext: [u8; N]`.
- Whether OpenVPN `<tls-auth>` and `<tls-crypt>` blocks count as secrets. Recommend yes for `<tls-auth>` (asymmetric pre-shared key), no for `<tls-crypt>` (similar). Verify during impl.
- Whether the migration should rewrite the `.conf`/`.ovpn` files in place OR move them aside and emit fresh files. Recommend in-place rewrite with the `.pre-migrate` backup; cleaner UX.
- Sidecar file extension: `.meta.toml` (proposed) vs `.toml` vs `.vmeta`. Recommend `.meta.toml` — clear intent + standard TOML tooling support.
- Whether to support `XDG_RUNTIME_DIR` falling back gracefully when not set (e.g., on macOS where it's not standard). Recommend `directories::ProjectDirs::runtime_dir()` with `~/Library/Caches/vortix/runtime/` fallback for macOS.
