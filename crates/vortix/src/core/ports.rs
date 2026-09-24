//! Capability ports: traits that adapter crates implement to provide subprocess execution,
//! per-OS platform operations, VPN protocol drivers, etc.
//!
//! - `process` — `CommandRunner`
//! - `killswitch`, `dns`, `interface`, `network_stats`, `route_table` — capability ports
//! - `tunnel` — `Tunnel` trait

pub mod dns {
    //! DNS inspection and policy ports.
    //!
    //! Protocol adapters report requested resolvers; this module computes one
    //! protocol-neutral policy from the current tunnel roles. Platform adapters
    //! are the only writers of resolver state.

    use std::hash::{Hash, Hasher};
    use std::net::IpAddr;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use serde::{Deserialize, Serialize};

    use crate::core::profile::ProfileId;

    /// Resolver settings requested by one protocol profile or live session.
    #[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
    pub struct DnsRequest {
        pub servers: Vec<IpAddr>,
        #[serde(default)]
        pub search_domains: Vec<String>,
    }

    impl DnsRequest {
        #[must_use]
        pub fn is_empty(&self) -> bool {
            self.servers.is_empty()
        }
    }

    /// The kernel-derived routing role of a connected tunnel.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub enum DnsTunnelRole {
        Primary,
        Secondary,
    }

    /// All policy inputs for one connected tunnel.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct DnsTunnelIntent {
        pub profile_id: ProfileId,
        pub interface: String,
        pub role: DnsTunnelRole,
        pub request: DnsRequest,
    }

    /// Capabilities of the selected platform DNS backend.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct DnsPlatformCapabilities {
        /// The backend can route named DNS suffixes to a secondary tunnel.
        pub scoped_domains: bool,
    }

    /// Effective resolver scope assigned to one tunnel.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub enum DnsScope {
        /// Resolve all names through the primary tunnel.
        CatchAll,
        /// Resolve only the listed suffixes through this secondary tunnel.
        Scoped { domains: Vec<String> },
        /// Do not register this tunnel's requested resolver globally.
        Suppressed,
    }

    /// One entry in a complete desired DNS policy.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct DnsAssignment {
        pub profile_id: ProfileId,
        pub interface: String,
        pub servers: Vec<IpAddr>,
        /// Normalized suffixes the resolver should use for unqualified names.
        /// This is independent of routing scope: a catch-all primary may still
        /// provide search domains, while a secondary uses them as scoped routes.
        #[serde(default)]
        pub search_domains: Vec<String>,
        pub scope: DnsScope,
    }

    /// A complete resolver policy for one monotonic desired generation.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct DnsPolicy {
        pub generation: u64,
        pub assignments: Vec<DnsAssignment>,
    }

    impl DnsPolicy {
        /// Compute a complete policy. At most one tunnel may own catch-all DNS.
        pub fn compute(
            generation: u64,
            intents: &[DnsTunnelIntent],
            capabilities: DnsPlatformCapabilities,
        ) -> Result<Self, DnsPolicyError> {
            let primary_count = intents
                .iter()
                .filter(|intent| intent.role == DnsTunnelRole::Primary)
                .count();
            if primary_count > 1 {
                return Err(DnsPolicyError::MultiplePrimaries);
            }

            let mut assignments = intents
                .iter()
                .filter(|intent| !intent.request.is_empty())
                .map(|intent| {
                    let scope = match intent.role {
                        DnsTunnelRole::Primary => DnsScope::CatchAll,
                        DnsTunnelRole::Secondary if capabilities.scoped_domains => {
                            let domains = normalized_domains(&intent.request.search_domains);
                            if domains.is_empty() {
                                DnsScope::Suppressed
                            } else {
                                DnsScope::Scoped { domains }
                            }
                        }
                        DnsTunnelRole::Secondary => DnsScope::Suppressed,
                    };
                    DnsAssignment {
                        profile_id: intent.profile_id.clone(),
                        interface: intent.interface.clone(),
                        servers: intent.request.servers.clone(),
                        search_domains: normalized_domains(&intent.request.search_domains),
                        scope,
                    }
                })
                .collect::<Vec<_>>();
            assignments.sort_by(|a, b| a.profile_id.as_str().cmp(b.profile_id.as_str()));
            Ok(Self {
                generation,
                assignments,
            })
        }

        /// Compare desired content while ignoring its generation number.
        #[must_use]
        pub fn same_content(&self, other: &Self) -> bool {
            self.assignments == other.assignments
        }
    }

    fn normalized_domains(domains: &[String]) -> Vec<String> {
        let mut domains = domains
            .iter()
            .map(|domain| domain.trim().trim_end_matches('.').to_ascii_lowercase())
            .filter(|domain| !domain.is_empty())
            .collect::<Vec<_>>();
        domains.sort();
        domains.dedup();
        domains
    }

    /// A platform resource created by Vortix for one desired generation.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct DnsOwnedResource {
        pub generation: u64,
        pub id: String,
        pub profile_id: ProfileId,
        pub interface: String,
    }

    /// Truthful result of applying or releasing one desired generation.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub enum DnsEffectiveStatus {
        Released,
        Applied,
        Degraded,
    }

    /// Requested, effective, and ownership truth retained for reconciliation.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct DnsEffectiveState {
        pub requested_generation: u64,
        pub applied_generation: Option<u64>,
        pub status: DnsEffectiveStatus,
        pub owned: Vec<DnsOwnedResource>,
        pub errors: Vec<String>,
    }

    impl Default for DnsEffectiveState {
        fn default() -> Self {
            Self {
                requested_generation: 0,
                applied_generation: None,
                status: DnsEffectiveStatus::Released,
                owned: Vec::new(),
                errors: Vec::new(),
            }
        }
    }

    /// Platform mutation seam consumed by the global policy coordinator.
    pub trait DnsPolicyAdapter {
        fn capabilities(&self) -> DnsPlatformCapabilities;

        fn apply(
            &self,
            desired: &DnsPolicy,
            previous_desired: Option<&DnsPolicy>,
            previous_effective: &DnsEffectiveState,
        ) -> DnsEffectiveState;

        /// Prove that the platform still matches an already-applied policy
        /// without mutating resolver state.
        fn verify(
            &self,
            desired: &DnsPolicy,
            effective: &DnsEffectiveState,
        ) -> Result<(), Vec<String>>;
    }

    const DNS_PROOF_MAX_AGE: Duration = Duration::from_secs(5);

    /// Monotonic coordinator state shared by local CLI/TUI and the later service.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DnsPolicyCoordinator {
        desired: Option<DnsPolicy>,
        effective: DnsEffectiveState,
        #[serde(default)]
        verified_generation: Option<u64>,
        #[serde(default)]
        verified_digest: Option<u64>,
        #[serde(default)]
        verified_at_unix_ms: Option<u64>,
        #[serde(skip)]
        verified_at_monotonic: Option<Instant>,
        /// Persisted user-owned state is useful as advisory intent, but must not
        /// authorize cleanup or rollback of privileged platform resources.
        #[serde(skip)]
        runtime_authority: bool,
    }

    impl Default for DnsPolicyCoordinator {
        fn default() -> Self {
            Self {
                desired: None,
                effective: DnsEffectiveState::default(),
                verified_generation: None,
                verified_digest: None,
                verified_at_unix_ms: None,
                verified_at_monotonic: None,
                runtime_authority: true,
            }
        }
    }

    impl DnsPolicyCoordinator {
        #[must_use]
        pub fn desired(&self) -> Option<&DnsPolicy> {
            self.desired.as_ref()
        }

        #[must_use]
        pub fn effective(&self) -> &DnsEffectiveState {
            &self.effective
        }

        /// Recover the last requested resolver intent for same-boot/process
        /// restart reconciliation. Live protocol evidence replaces this cache.
        #[must_use]
        pub fn request_for(&self, profile_id: &ProfileId) -> Option<DnsRequest> {
            let assignment = self
                .desired
                .as_ref()?
                .assignments
                .iter()
                .find(|assignment| &assignment.profile_id == profile_id)?;
            Some(DnsRequest {
                servers: assignment.servers.clone(),
                search_domains: assignment.search_domains.clone(),
            })
        }

        /// Persisted effective state is recovery evidence, never fresh platform
        /// verification. Force the next reconcile to reapply/read back.
        pub fn invalidate_effective(&mut self, reason: impl Into<String>) {
            self.effective.status = DnsEffectiveStatus::Degraded;
            self.effective.errors = vec![reason.into()];
            self.clear_verification();
        }

        /// Strip all privileged ownership claims after loading user-controlled
        /// persisted state. Desired intent remains advisory for recovery.
        pub fn discard_persisted_authority(&mut self) {
            self.runtime_authority = false;
            self.effective.applied_generation = None;
            self.effective.owned.clear();
            self.invalidate_effective("persisted DNS state requires platform read-back");
        }

        /// Force a read-only platform proof on the next unchanged reconcile.
        pub fn invalidate_verification(&mut self) {
            self.clear_verification();
        }

        /// Read back an already-applied policy without changing resolver state.
        /// The requested intents must still describe the coordinator's exact
        /// current policy; otherwise an old proof cannot be refreshed.
        pub fn verify_current<A: DnsPolicyAdapter>(
            &self,
            intents: &[DnsTunnelIntent],
            adapter: &A,
        ) -> Result<(), Vec<String>> {
            if !self.runtime_authority {
                return Err(vec!["DNS runtime authority is unavailable".into()]);
            }
            let desired = self
                .desired
                .as_ref()
                .ok_or_else(|| vec!["DNS desired policy is unavailable".into()])?;
            let candidate = DnsPolicy::compute(desired.generation, intents, adapter.capabilities())
                .map_err(|error| vec![error.to_string()])?;
            if !desired.same_content(&candidate) {
                return Err(vec![
                    "DNS desired policy no longer matches the applied topology".into(),
                ]);
            }
            adapter.verify(desired, &self.effective)
        }

        /// Recompute and apply the entire policy. Identical effective content is
        /// a no-op; degraded content is retried without inventing a generation.
        pub fn reconcile<A: DnsPolicyAdapter>(
            &mut self,
            intents: &[DnsTunnelIntent],
            adapter: &A,
        ) -> Result<&DnsEffectiveState, DnsPolicyError> {
            self.reconcile_durable(intents, adapter, |_| Ok::<(), std::convert::Infallible>(()))
        }

        /// Reconcile with a write-ahead desired record and a durable effective
        /// receipt. No platform mutation occurs unless the pending generation is
        /// safely persisted first.
        ///
        /// # Panics
        /// Never in practice: the desired record is installed before it is read.
        pub fn reconcile_durable<A, F, E>(
            &mut self,
            intents: &[DnsTunnelIntent],
            adapter: &A,
            mut persist: F,
        ) -> Result<&DnsEffectiveState, DnsPolicyError>
        where
            A: DnsPolicyAdapter,
            F: FnMut(&Self) -> Result<(), E>,
            E: std::fmt::Display,
        {
            let next_generation = self
                .desired
                .as_ref()
                .map_or(1, |policy| policy.generation.saturating_add(1));
            let candidate = DnsPolicy::compute(next_generation, intents, adapter.capabilities())?;

            let unchanged = self
                .desired
                .as_ref()
                .is_some_and(|current| current.same_content(&candidate));
            if unchanged && self.effective.status != DnsEffectiveStatus::Degraded {
                let desired = self.desired.as_ref().expect("unchanged policy exists");
                if self.has_fresh_proof(desired) {
                    return Ok(&self.effective);
                }
                match adapter.verify(desired, &self.effective) {
                    Ok(()) => self.record_verification(),
                    Err(errors) => {
                        self.effective.status = DnsEffectiveStatus::Degraded;
                        self.effective.errors = errors;
                        self.clear_verification();
                    }
                }
                persist(self).map_err(|error| {
                    self.mark_persistence_failure(format!("persist DNS verification: {error}"));
                    DnsPolicyError::Persistence(error.to_string())
                })?;
                return Ok(&self.effective);
            }

            let desired = if unchanged {
                self.desired.clone().expect("unchanged policy exists")
            } else {
                candidate
            };
            let previous_desired = self.desired.clone();
            let previous_effective = self.effective.clone();
            let previous_authority = self.runtime_authority;

            // Write-ahead state is deliberately degraded: it records intent but
            // never claims that a privileged platform mutation completed.
            self.desired = Some(desired);
            self.effective.requested_generation = self
                .desired
                .as_ref()
                .expect("desired policy was installed")
                .generation;
            self.effective.status = DnsEffectiveStatus::Degraded;
            self.effective.errors = vec!["DNS policy generation pending platform apply".into()];
            self.clear_verification();
            if let Err(error) = persist(self) {
                self.mark_persistence_failure(format!("persist DNS write-ahead: {error}"));
                return Err(DnsPolicyError::Persistence(error.to_string()));
            }

            let desired = self.desired.clone().expect("desired policy was installed");
            let trusted_previous = previous_authority
                .then_some(previous_desired.as_ref())
                .flatten();
            let effective = adapter.apply(&desired, trusted_previous, &previous_effective);
            self.effective = effective;
            self.runtime_authority = true;
            if matches!(
                self.effective.status,
                DnsEffectiveStatus::Applied | DnsEffectiveStatus::Released
            ) {
                self.record_verification();
            }

            if let Err(error) = persist(self) {
                let rollback_policy = previous_desired.clone().unwrap_or_else(|| DnsPolicy {
                    generation: desired.generation.saturating_add(1),
                    assignments: Vec::new(),
                });
                let rollback = adapter.apply(&rollback_policy, Some(&desired), &self.effective);
                self.desired = previous_desired;
                self.effective = rollback;
                self.runtime_authority = previous_authority;
                self.mark_persistence_failure(format!(
                    "persist DNS effective receipt: {error}; platform rollback attempted"
                ));
                let _ = persist(self);
                return Err(DnsPolicyError::Persistence(error.to_string()));
            }
            Ok(&self.effective)
        }

        fn has_fresh_proof(&self, desired: &DnsPolicy) -> bool {
            self.verified_generation == Some(desired.generation)
                && self.verified_digest == Some(policy_digest(desired))
                && self.verified_at_unix_ms.is_some()
                && self
                    .verified_at_monotonic
                    .is_some_and(|verified| verified.elapsed() <= DNS_PROOF_MAX_AGE)
        }

        fn record_verification(&mut self) {
            let Some(desired) = self.desired.as_ref() else {
                return;
            };
            self.verified_generation = Some(desired.generation);
            self.verified_digest = Some(policy_digest(desired));
            self.verified_at_unix_ms = Some(now_unix_ms());
            self.verified_at_monotonic = Some(Instant::now());
        }

        fn clear_verification(&mut self) {
            self.verified_generation = None;
            self.verified_digest = None;
            self.verified_at_unix_ms = None;
            self.verified_at_monotonic = None;
        }

        fn mark_persistence_failure(&mut self, error: String) {
            self.effective.status = DnsEffectiveStatus::Degraded;
            self.effective.errors = vec![error];
            self.clear_verification();
        }
    }

    fn now_unix_ms() -> u64 {
        u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
        )
        .unwrap_or(u64::MAX)
    }

    fn policy_digest(policy: &DnsPolicy) -> u64 {
        let bytes = serde_json::to_vec(policy).unwrap_or_default();
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        bytes.hash(&mut hasher);
        hasher.finish()
    }

    /// Pure policy validation error.
    #[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
    pub enum DnsPolicyError {
        #[error("DNS policy has more than one primary tunnel")]
        MultiplePrimaries,
        #[error("DNS policy persistence failed: {0}")]
        Persistence(String),
    }
}
pub mod interface {
    //! `Interface` port — VPN interface detection.
}
pub mod killswitch {
    //! `Killswitch` port — kill-switch firewall control.
    //!
    //! Implementations live in `vortix-platform-{macos,linux,windows}`. The
    //! trait is intentionally sync today; the async engine migration
    //! adds `&CommandRunner` arguments and `async fn` where useful. For now,
    //! impls reach the global runner via `crate::process::run_to_output(...)`.
    //!
    //! The multi-tunnel rework replaced the single-tunnel `enable_blocking`
    //! signature with `enable_blocking_multi`, which accepts a slice of
    //! [`ActiveTunnelInfo`] — one per active tunnel — so the platform can
    //! synthesize a multi-interface ruleset in a single restore call.

    use std::net::IpAddr;

    use thiserror::Error;

    use crate::core::cidr::Cidr;

    /// Result alias for kill-switch operations.
    pub type Result<T> = std::result::Result<T, KillswitchError>;

    /// Errors that can occur during kill-switch operations.
    #[derive(Debug, Error)]
    pub enum KillswitchError {
        /// The normalized policy contains an unsafe or unsupported value.
        #[error("invalid kill-switch policy: {0}")]
        InvalidPolicy(String),
        /// A firewall subprocess returned a non-zero exit or otherwise failed.
        #[error("firewall command failed: {0}")]
        CommandFailed(String),
        /// I/O error (reading/writing pf config, opening sockets, etc.).
        #[error("I/O error: {0}")]
        Io(#[from] std::io::Error),
        /// The caller is not running as root and the operation requires root.
        #[error("kill switch requires root privileges")]
        NotRoot,
        /// No safe firewall backend is available on this host (Linux requires
        /// `nft`; split-family iptables replacement cannot be atomic).
        #[error("no firewall backend available on this host")]
        NoBackendAvailable,
    }

    /// Per-tunnel state needed to synthesise multi-interface killswitch
    /// rules. The platform impl uses the interface name for interface-allow
    /// rules, the server IPs for reconnect-allow rules, and the declared
    /// CIDRs to subtract from the RFC1918 base when this tunnel is a
    /// secondary.
    ///
    /// Primary tunnels (claiming the default route, `is_primary == true`)
    /// do **not** contribute to RFC1918 subtraction — their interface allow
    /// rule covers all egress, and subtracting `0.0.0.0/0` would strip
    /// loopback.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ActiveTunnelInfo {
        /// VPN tunnel interface name, e.g. `"utun3"` (macOS) or `"wg0"` (Linux).
        pub interface: String,
        /// Server IPs to allow for reconnection. May be empty if the tunnel
        /// has no externally observable server endpoint (mock / dev).
        pub server_ips: Vec<IpAddr>,
        /// CIDRs this tunnel declares as its routed scope. Used only for
        /// secondaries: subtracted from the RFC1918 base so traffic to those
        /// nets cannot escape onto the underlay.
        pub declared_cidrs: Vec<Cidr>,
        /// `true` when this tunnel claims the default route (primary).
        /// Primaries are excluded from RFC1918 subtraction.
        pub is_primary: bool,
    }

    impl ActiveTunnelInfo {
        /// Policy-only endpoint allowance used while a tunnel interface does not
        /// exist yet. Platform adapters emit only the destination exceptions and
        /// never an interface allow rule for this value.
        #[must_use]
        pub fn endpoint_allowlist(server_ips: Vec<IpAddr>) -> Self {
            Self {
                interface: String::new(),
                server_ips,
                declared_cidrs: Vec::new(),
                is_primary: false,
            }
        }

        #[must_use]
        pub fn is_endpoint_allowlist(&self) -> bool {
            self.interface.is_empty()
        }
    }
}
pub mod network_stats {
    //! `NetworkStats` port — per-host byte counters.
}
pub mod process {
    //! `CommandRunner` port — the typed seam through which every subprocess flows.
    //!
    //! Concrete impls (`RealRunner`, `MockRunner`) live in `vortix-process`. This module
    //! contains only the trait, the data types, and the error enum. No tokio dependency.
    //!

    use std::collections::HashMap;
    use std::fmt::Write as _;
    use std::fs::File;
    use std::io::Read as _;
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime};

    use serde::{Deserialize, Serialize};
    use thiserror::Error;

    use crate::core::profile::ProfileId;

    /// What privilege level a `CommandSpec` requires.
    ///
    /// `RealRunner` checks the running uid against this requirement and fails fast with
    /// `ProcessError::PrivilegeDenied` when the requirement is unmet — vortix does NOT
    /// auto-escalate. Privilege resolution is the daemon's job (see idea 4 Phase B).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
    pub enum PrivilegeReq {
        /// Runs as the current user. Used for read-only ops (`wg show`, `ps`, `which`, etc.).
        #[default]
        None,
        /// Requires effective uid 0. Used for VPN tool invocation (`wg-quick`, `openvpn`,
        /// `iptables`, `pfctl`, etc.).
        Root,
    }

    /// Explicit non-root identity for an owner-run subprocess.
    ///
    /// Supplying this never grants privilege: a non-root caller may name only
    /// its current identity, while a root caller must drop all three credential
    /// sets before `exec`.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ProcessCredentials {
        pub uid: u32,
        pub gid: u32,
        pub supplementary_groups: Vec<u32>,
    }

    /// The full specification of a subprocess invocation.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct CommandSpec {
        pub program: String,
        pub args: Vec<String>,
        /// Optional environment variables. By default merged into the current process env;
        /// callers who need a clean env should set `env_clear = true`.
        pub env: HashMap<String, String>,
        pub env_clear: bool,
        pub cwd: Option<PathBuf>,
        pub stdin_bytes: Option<Vec<u8>>,
        pub timeout: Option<Duration>,
        /// Maximum bytes retained from each captured output stream. The runner
        /// continues draining the child after the limit so a noisy process cannot
        /// deadlock on a full pipe, then returns a typed overflow error.
        pub output_limit: Option<usize>,
        pub requires_privilege: PrivilegeReq,
        /// Arg indices to redact in `tracing` audit logs. Used by callers that pass
        /// secret material (e.g., file paths in `/tmp/vortix-*.conf`) as args.
        /// No current callsite uses this; the field is reserved for future use.
        pub redact_in_audit: Vec<usize>,
        /// Verified non-root credentials applied before `exec`.
        #[serde(default)]
        pub run_as: Option<ProcessCredentials>,
        /// Put the child in a new process group and contain descendants on
        /// timeout/cancellation. Required for lifecycle hooks.
        #[serde(default)]
        pub terminate_process_group: bool,
    }

    impl CommandSpec {
        /// Construct a default `OneShot` spec running as the current user.
        pub fn oneshot(program: impl Into<String>, args: Vec<String>) -> Self {
            Self {
                program: program.into(),
                args,
                env: HashMap::new(),
                env_clear: false,
                cwd: None,
                stdin_bytes: None,
                timeout: None,
                output_limit: None,
                requires_privilege: PrivilegeReq::None,
                redact_in_audit: Vec::new(),
                run_as: None,
                terminate_process_group: false,
            }
        }

        /// Builder: require root.
        #[must_use]
        pub fn privilege(mut self, req: PrivilegeReq) -> Self {
            self.requires_privilege = req;
            self
        }

        /// Builder: set a timeout for `OneShot` invocations.
        #[must_use]
        pub fn timeout(mut self, duration: Duration) -> Self {
            self.timeout = Some(duration);
            self
        }

        /// Builder: bound each captured stdout/stderr stream.
        #[must_use]
        pub fn output_limit(mut self, bytes: usize) -> Self {
            self.output_limit = Some(bytes);
            self
        }

        /// Builder: feed stdin bytes.
        #[must_use]
        pub fn stdin(mut self, bytes: Vec<u8>) -> Self {
            self.stdin_bytes = Some(bytes);
            self
        }

        /// Builder: mark arg indices as secret (redacted in audit logs).
        #[must_use]
        pub fn redact_args(mut self, indices: impl IntoIterator<Item = usize>) -> Self {
            self.redact_in_audit = indices.into_iter().collect();
            self
        }

        /// Builder: execute under an already-verified non-root identity.
        #[must_use]
        pub fn run_as(mut self, credentials: ProcessCredentials) -> Self {
            self.run_as = Some(credentials);
            self
        }

        /// Builder: contain the child and descendants in a dedicated process group.
        #[must_use]
        pub fn contain_process_group(mut self) -> Self {
            self.terminate_process_group = true;
            self
        }
    }

    /// Subprocess exit status in a serde-friendly form.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ExitStatusInfo {
        pub code: Option<i32>,
        pub signal: Option<i32>,
        pub success: bool,
    }

    /// Outcome of a `OneShot` subprocess invocation.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct CommandOutcome {
        pub stdout: Vec<u8>,
        pub stderr: Vec<u8>,
        pub exit_status: ExitStatusInfo,
        pub duration: Duration,
        pub started_at: SystemTime,
    }

    impl CommandOutcome {
        /// Convenience: was the exit successful?
        #[must_use]
        pub fn success(&self) -> bool {
            self.exit_status.success
        }

        /// Convenience: stdout as a UTF-8 string (lossy).
        #[must_use]
        pub fn stdout_lossy(&self) -> std::borrow::Cow<'_, str> {
            String::from_utf8_lossy(&self.stdout)
        }

        /// Convenience: stderr as a UTF-8 string (lossy).
        #[must_use]
        pub fn stderr_lossy(&self) -> std::borrow::Cow<'_, str> {
            String::from_utf8_lossy(&self.stderr)
        }
    }

    /// Stable ownership key for a foreground protocol child.
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    pub struct ManagedProcessId {
        pub profile_id: ProfileId,
        /// Non-zero per-attempt generation. It is useful for diagnostics, but is
        /// never accepted as authentication on its own.
        pub generation: u64,
        /// Cryptographically opaque ownership capability. A stale handle cannot
        /// address a later child for the same stable profile identity.
        pub ownership_token: String,
    }

    impl ManagedProcessId {
        /// Allocate an identity before spawning the child so every cleanup path,
        /// including partial startup, is bound to the exact attempt.
        ///
        /// # Panics
        /// Never: the 8-byte prefix of a 32-byte buffer always converts.
        pub fn generate(profile_id: ProfileId) -> std::io::Result<Self> {
            let mut bytes = [0_u8; 32];
            File::open("/dev/urandom")?.read_exact(&mut bytes)?;
            let mut ownership_token = String::with_capacity(bytes.len() * 2);
            for byte in bytes {
                let _ = write!(ownership_token, "{byte:02x}");
            }
            let generation =
                u64::from_be_bytes(bytes[..8].try_into().expect("fixed-size prefix")).max(1);
            Ok(Self {
                profile_id,
                generation,
                ownership_token,
            })
        }

        #[must_use]
        pub fn has_valid_token(&self) -> bool {
            self.generation != 0
                && self.ownership_token.len() == 64
                && self
                    .ownership_token
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }
    }

    /// Managed process-group ownership receipt. It contains no command arguments
    /// or credentials. Concrete backends may return a containment guardian PID
    /// rather than the protocol process PID.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ProcessOwnership {
        pub identity: ManagedProcessId,
        pub pid: u32,
    }

    /// Process-lifecycle port used by the Standard-mode custodian. Protocol
    /// adapters build the command specification; only the process layer spawns,
    /// signals, waits for, and reaps the child.
    pub trait ProcessLifecycle: Send + 'static {
        fn spawn_foreground(
            &mut self,
            identity: ManagedProcessId,
            spec: CommandSpec,
        ) -> Result<ProcessOwnership, ProcessError>;
        fn is_alive(&mut self, identity: &ManagedProcessId) -> Result<bool, ProcessError>;
        fn graceful_stop(&mut self, identity: &ManagedProcessId) -> Result<(), ProcessError>;
        fn wait_for_exit(
            &mut self,
            identity: &ManagedProcessId,
            timeout: Duration,
        ) -> Result<bool, ProcessError>;
        fn force_kill(&mut self, identity: &ManagedProcessId) -> Result<(), ProcessError>;
        fn reap(&mut self, identity: &ManagedProcessId) -> Result<(), ProcessError>;
    }

    /// What failed when invoking a subprocess.
    ///
    /// Each variant carries enough context to populate the JSON envelope's `next_actions`
    /// field at the CLI edge.
    #[derive(Debug, Error)]
    pub enum ProcessError {
        /// The spec required root but the running uid is not zero.
        #[error("subprocess `{program}` requires root but current uid is not 0")]
        PrivilegeDenied { program: String },
        /// Requested credential transition is unsafe or unavailable.
        #[error("subprocess `{program}` has invalid owner credentials: {reason}")]
        InvalidCredentials { program: String, reason: String },
        /// The program could not be found on PATH (`exec` returned ENOENT).
        #[error("subprocess `{program}` not found on PATH")]
        ProgramNotFound { program: String },
        /// The subprocess did not complete within the configured timeout.
        #[error("subprocess `{program}` timed out after {duration:?}")]
        Timeout { program: String, duration: Duration },
        /// A captured stream exceeded the caller's explicit memory bound.
        #[error("subprocess `{program}` output exceeded {limit} bytes")]
        OutputLimitExceeded { program: String, limit: usize },
        /// The subprocess exited non-zero.
        #[error("subprocess `{program}` exited with code {code:?}")]
        NonZeroExit {
            program: String,
            code: Option<i32>,
            stderr: Vec<u8>,
        },
        /// The subprocess was killed by a signal.
        #[error("subprocess `{program}` killed by signal {signal}")]
        Killed { program: String, signal: i32 },
        /// I/O error during spawn / stdin write / output read.
        #[error("subprocess `{program}` I/O error: {source}")]
        IoError {
            program: String,
            #[source]
            source: std::io::Error,
        },
    }
}
pub mod route_table {
    //! `RouteTable` port — system route inspection and exact scoped writes.

    /// Result of probing the route used for public-internet traffic.
    ///
    /// `NoDefaultRoute` is an observed kernel state. `ProbeFailed` means the
    /// observation is unknown and consumers must retain their last known route
    /// instead of interpreting the failure as a topology change.
    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub enum DefaultRouteObservation {
        Interface(String),
        NoDefaultRoute,
        #[default]
        ProbeFailed,
    }

    impl DefaultRouteObservation {
        #[must_use]
        pub fn interface(&self) -> Option<&str> {
            match self {
                Self::Interface(interface) => Some(interface),
                Self::NoDefaultRoute | Self::ProbeFailed => None,
            }
        }
    }
}
pub mod socket_audit {
    //! `SocketAudit` capability port.
    //!
    //! Pull-based per-process socket inventory. Implementations live in
    //! `vortix-platform-{linux,macos,windows}`. Consumers query via the
    //! `Platform` aggregate (`vortix/src/platform/aggregate.rs`).

    use std::net::SocketAddr;

    use serde::{Deserialize, Serialize};
    use thiserror::Error;

    /// The IP transport protocol of a socket.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[non_exhaustive]
    #[serde(rename_all = "snake_case")]
    pub enum SocketProtocol {
        Tcp,
        Udp,
        Tcp6,
        Udp6,
    }

    impl std::fmt::Display for SocketProtocol {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let s = match self {
                Self::Tcp => "tcp",
                Self::Udp => "udp",
                Self::Tcp6 => "tcp6",
                Self::Udp6 => "udp6",
            };
            f.write_str(s)
        }
    }

    /// One socket as observed at snapshot time.
    ///
    /// The vortix engine and audit CLI consume `Vec<SocketSnapshot>` from
    /// the `SocketAudit::snapshot()` call. The shape is intentionally
    /// simple — no continuous streaming, no diffing; future requirements
    /// can extend the port.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SocketSnapshot {
        /// Owning process id (or `0` when the impl can't resolve it,
        /// e.g. without root on Linux or when the socket belongs to
        /// another user).
        pub pid: u32,
        /// `comm` (Linux) or process name (macOS). Empty string when
        /// unknown.
        pub command: String,
        /// Local endpoint.
        pub local: SocketAddr,
        /// Remote endpoint. `None` for listening sockets.
        pub remote: Option<SocketAddr>,
        /// Transport protocol.
        pub protocol: SocketProtocol,
        /// Routing interface (e.g. `en0`, `wg0`, `tun0`). `None` when the
        /// platform impl can't resolve it for this socket; the audit CLI
        /// renders this as a useful hint for "is this traffic going
        /// through the tunnel?"
        pub interface: Option<String>,
    }

    /// Errors produced by a socket-audit snapshot.
    #[derive(Debug, Error)]
    #[non_exhaustive]
    pub enum SocketAuditError {
        /// The platform impl is a stub (Windows in v0.3.0). The CLI
        /// surfaces this as "socket audit not available on this platform"
        /// without a panic.
        #[error("socket audit is not available on this platform")]
        Unsupported,
        /// The underlying tool (`ps`, `lsof`, file read) failed.
        #[error("socket audit command failed: {0}")]
        CommandFailed(String),
        /// Parsing the tool's output failed midway. The CLI surfaces this
        /// with the parser's diagnostic so a future contributor can
        /// reproduce.
        #[error("socket audit parse failed: {0}")]
        ParseFailed(String),
        /// I/O error reading `/proc` or running a command.
        #[error("socket audit I/O: {0}")]
        Io(#[from] std::io::Error),
    }

    /// Result alias for socket-audit operations.
    pub type SocketAuditResult<T> = std::result::Result<T, SocketAuditError>;

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn socket_protocol_round_trips_through_json() {
            for proto in [
                SocketProtocol::Tcp,
                SocketProtocol::Udp,
                SocketProtocol::Tcp6,
                SocketProtocol::Udp6,
            ] {
                let json = serde_json::to_string(&proto).unwrap();
                let back: SocketProtocol = serde_json::from_str(&json).unwrap();
                assert_eq!(proto, back);
            }
        }

        #[test]
        fn socket_protocol_display() {
            assert_eq!(format!("{}", SocketProtocol::Tcp), "tcp");
            assert_eq!(format!("{}", SocketProtocol::Udp6), "udp6");
        }

        #[test]
        fn socket_snapshot_round_trips() {
            let snap = SocketSnapshot {
                pid: 1234,
                command: "curl".into(),
                local: "127.0.0.1:54321".parse().unwrap(),
                remote: Some("8.8.8.8:443".parse().unwrap()),
                protocol: SocketProtocol::Tcp,
                interface: Some("en0".into()),
            };
            let json = serde_json::to_string(&snap).unwrap();
            let back: SocketSnapshot = serde_json::from_str(&json).unwrap();
            assert_eq!(snap, back);
        }

        #[test]
        fn listening_socket_has_no_remote() {
            let snap = SocketSnapshot {
                pid: 5678,
                command: "nc".into(),
                local: "0.0.0.0:8080".parse().unwrap(),
                remote: None,
                protocol: SocketProtocol::Tcp,
                interface: None,
            };
            let json = serde_json::to_string(&snap).unwrap();
            // Listening sockets serialize remote as null
            assert!(json.contains("\"remote\":null"));
        }
    }
}
pub mod tunnel {
    //! `Tunnel` port — the per-protocol adapter the engine drives.
    //!
    //! Each protocol (`WireGuard`, `OpenVPN`, future `IKEv2`) implements this
    //! trait in its own crate. The engine never branches on protocol after
    //! construction — it routes once via `profile.protocol → TunnelKind` (the
    //! aggregate carrier defined in the binary) and dispatches statically.
    //!
    //! Plan #004 keeps trait methods sync (engine is sync today; mocks and real
    //! impls reach the global runner directly). The async engine
    //! migration adds `&CommandRunner` arguments and `async fn` where useful.

    use std::collections::{BTreeMap, BTreeSet};
    use std::net::IpAddr;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Instant;
    use std::time::{Duration, SystemTime};

    use serde::{Deserialize, Serialize};
    use thiserror::Error;

    use crate::core::profile::ProfileId;

    /// Cooperative cancellation fence shared by the canonical worker and
    /// protocol adapters. It lives at the port boundary so protocol crates never
    /// import the control implementation.
    #[derive(Debug, Clone, Default)]
    pub struct TunnelCancellation(Arc<AtomicBool>);

    impl TunnelCancellation {
        pub fn cancel(&self) {
            self.0.store(true, Ordering::Release);
        }

        #[must_use]
        pub fn is_cancelled(&self) -> bool {
            self.0.load(Ordering::Acquire)
        }
    }

    /// Canonical bounds for one protocol mutation.
    #[derive(Debug, Clone)]
    pub struct TunnelExecutionContext {
        pub cancellation: TunnelCancellation,
        pub deadline: Instant,
    }

    // ───────────────────────────────────────────────────────────────────────────
    // Handle / status / capabilities / errors
    // ───────────────────────────────────────────────────────────────────────────

    /// Tag identifying which `Tunnel` impl owns a [`TunnelHandle`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    #[non_exhaustive]
    pub enum TunnelKindTag {
        WireGuard,
        OpenVpn,
        Mock,
    }

    /// Protocol-owned configuration needed to tear a tunnel down safely.
    ///
    /// `managed` distinguishes a private, sanitized lifecycle copy from the
    /// user's source profile. Protocol adapters may remove managed copies after
    /// a successful teardown, but must never remove source profiles.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct TunnelTeardownConfig {
        pub path: PathBuf,
        pub managed: bool,
        /// Stable basename passed to `wg-quick`. On macOS this differs from the
        /// kernel-assigned `utunN` interface and is required to resolve the
        /// `/var/run/wireguard/<name>.name` ownership mapping during teardown.
        pub wg_quick_interface: Option<String>,
    }

    /// Lifecycle handle returned by a protocol's `up` and consumed by `down` / `status`.
    #[derive(Debug, Clone)]
    pub struct TunnelHandle {
        pub profile_id: ProfileId,
        /// Boundary label used only for user-visible output and legacy runtime
        /// filenames; lifecycle ownership remains keyed by `profile_id`.
        pub display_name: String,
        pub interface_name: String,
        /// Some(pid) when the impl manages a long-running daemon (e.g., `openvpn`);
        /// `None` when the kernel owns the lifecycle (e.g., kernel `WireGuard`).
        pub pid: Option<u32>,
        pub started_at: SystemTime,
        pub kind: TunnelKindTag,
        /// Attempt generation that owns this handle. Protocol observations copy
        /// this fence into handshake evidence so an older attempt can never
        /// complete newer desired state.
        pub generation: u64,
        /// Current-generation cryptographic proof. Present only after a
        /// `WireGuard` handshake gate succeeds.
        pub handshake: Option<HandshakeEvidence>,
        /// Every handshake-eliciting probe actually issued for this attempt.
        /// Configured targets alone never create a health expectation.
        pub probe_receipts: Vec<ProbeReceipt>,
        /// Exact lifecycle ownership capability for a userspace child. Kernel
        /// tunnels and externally observed sessions carry `None`.
        pub process_ownership: Option<crate::core::ports::process::ManagedProcessId>,
        /// Optional protocol configuration used by `down`. `WireGuard` carries a
        /// DNS-free copy here so `wg-quick down` cannot replay resolver changes.
        pub teardown_config: Option<TunnelTeardownConfig>,
        /// Resolver settings observed from the protocol profile and, where
        /// available, its negotiated runtime options. Platform mutation is not
        /// performed by the protocol adapter.
        pub dns_request: crate::core::ports::dns::DnsRequest,
        /// Complete configured and negotiated `OpenVPN` route truth from the
        /// same live generation. Other protocols carry `None`.
        pub openvpn_routes: Option<crate::core::openvpn_routes::OpenVpnRouteEvidence>,
    }

    /// Protocol-attested record of one `WireGuard` peer probe.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ProbeReceipt {
        pub peer_public_key: String,
        pub target: IpAddr,
        pub allowed_routes: Vec<String>,
        pub issued_at: SystemTime,
    }

    /// One `WireGuard` peer observation in protocol-neutral, typed form.
    ///
    /// Public-key identity and allowed routes are copied directly from `WireGuard`'s
    /// machine-readable dump. The control layer never parses `wg show` display
    /// strings.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct TunnelPeerStatus {
        pub public_key: String,
        pub endpoint: Option<String>,
        pub allowed_routes: Vec<String>,
        pub latest_handshake: Option<SystemTime>,
        pub evidence_observed_at: SystemTime,
        pub evidence_generation: u64,
        pub persistent_keepalive: Option<Duration>,
        pub bytes_rx: u64,
        pub bytes_tx: u64,
    }

    impl TunnelPeerStatus {
        /// Whether this peer is expected to produce fresh handshakes while idle.
        #[must_use]
        pub const fn keepalive_expected(&self) -> bool {
            self.persistent_keepalive.is_some()
        }
    }

    /// Snapshot of the current tunnel state.
    #[derive(Debug)]
    pub struct TunnelStatus {
        pub handle: TunnelHandle,
        pub bytes_rx: u64,
        pub bytes_tx: u64,
        pub last_handshake: Option<SystemTime>,
        pub observed_at: SystemTime,
        pub peers: Vec<TunnelPeerStatus>,
    }

    /// Immutable handshake attempt fence captured before interface creation.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct HandshakeAttempt {
        pub generation: u64,
        pub started_at: SystemTime,
        pub expected_peers: BTreeSet<String>,
        pub baseline: BTreeMap<String, Option<SystemTime>>,
    }

    /// Current-generation cryptographic liveness proof for one peer.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct HandshakeEvidence {
        pub generation: u64,
        pub peer_public_key: String,
        pub handshake_at: SystemTime,
        pub observed_at: SystemTime,
        pub allowed_routes: Vec<String>,
    }

    impl HandshakeAttempt {
        /// Accept only an expected peer whose timestamp is newer than both the
        /// pre-attempt baseline and attempt start, and whose observation carries
        /// this exact generation.
        #[must_use]
        pub fn evaluate(&self, status: &TunnelStatus) -> Option<HandshakeEvidence> {
            status.peers.iter().find_map(|peer| {
                if peer.evidence_generation != self.generation
                    || !self.expected_peers.contains(&peer.public_key)
                {
                    return None;
                }
                let handshake_at = peer.latest_handshake?;
                let baseline = self.baseline.get(&peer.public_key).copied().flatten();
                // WireGuard exports whole-second timestamps. Permit evidence from
                // the same wall-clock second as admission only when no baseline
                // existed; a captured baseline must always be strictly exceeded.
                let predates_attempt = baseline.map_or_else(
                    || {
                        handshake_at
                            .checked_add(Duration::from_secs(1))
                            .is_none_or(|rounded| rounded <= self.started_at)
                    },
                    |baseline| handshake_at <= baseline,
                );
                if predates_attempt {
                    return None;
                }
                Some(HandshakeEvidence {
                    generation: self.generation,
                    peer_public_key: peer.public_key.clone(),
                    handshake_at,
                    observed_at: peer.evidence_observed_at,
                    allowed_routes: peer.allowed_routes.clone(),
                })
            })
        }
    }

    /// Why ongoing freshness is expected for a `WireGuard` peer.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum PeerTrafficExpectation {
        Idle,
        PersistentKeepalive,
        RoutedTraffic,
        ConfiguredProbe { target: IpAddr },
    }

    /// Typed ongoing peer health; idle peers do not become falsely degraded.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum PeerHandshakeHealth {
        InformationalIdle { age: Option<Duration> },
        Healthy { age: Duration },
        Stale { age: Duration },
        NeverObserved,
    }

    /// Classify one peer without conflating interface presence with health.
    #[must_use]
    pub fn classify_peer_handshake_health(
        peer: &TunnelPeerStatus,
        now: SystemTime,
        expectation: &PeerTrafficExpectation,
        stale_after: Duration,
    ) -> PeerHandshakeHealth {
        let age = peer
            .latest_handshake
            .and_then(|handshake| now.duration_since(handshake).ok());
        if matches!(expectation, PeerTrafficExpectation::Idle) {
            return PeerHandshakeHealth::InformationalIdle { age };
        }
        match age {
            Some(age) if age > stale_after => PeerHandshakeHealth::Stale { age },
            Some(age) => PeerHandshakeHealth::Healthy { age },
            None => PeerHandshakeHealth::NeverObserved,
        }
    }

    /// Errors a protocol `up` / `down` / `status` call can return.
    #[derive(Debug, Error)]
    #[non_exhaustive]
    pub enum TunnelError {
        #[error("handshake failed: {0}")]
        HandshakeFailed(String),
        #[error("tunnel operation was cancelled")]
        Cancelled,
        #[error("tunnel outcome is ambiguous: {0}")]
        OutcomeUnknown(String),
        #[error("malformed protocol status: {0}")]
        MalformedStatus(String),
        #[error("protocol resource `{resource}` exceeded limit {limit}")]
        ResourceLimit {
            resource: &'static str,
            limit: usize,
        },
        #[error("authentication failed: {0}")]
        AuthFailed(String),
        #[error("connection timed out after {0:?}")]
        Timeout(std::time::Duration),
        #[error("daemon exited unexpectedly: {0}")]
        DaemonExited(String),
        #[error("subprocess failure: {0}")]
        Subprocess(String),
        #[error("I/O error: {0}")]
        Io(#[from] std::io::Error),
        #[error("requested capability `{0}` not supported by this protocol")]
        CapabilityUnsupported(&'static str),
        #[error("{0}")]
        Other(String),
    }

    /// Errors a profile parser can return.
    #[derive(Debug, Error)]
    #[non_exhaustive]
    pub enum ParseError {
        #[error("malformed value for `{field}`: {detail}")]
        MalformedField { field: &'static str, detail: String },
        #[error("unsupported profile feature: {0}")]
        Unsupported(String),
    }
}
