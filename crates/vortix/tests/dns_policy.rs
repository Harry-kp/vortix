use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use vortix::vortix_core::ports::dns::{
    DnsEffectiveState, DnsEffectiveStatus, DnsOwnedResource, DnsPlatformCapabilities, DnsPolicy,
    DnsPolicyAdapter, DnsPolicyCoordinator, DnsRequest, DnsScope, DnsTunnelIntent, DnsTunnelRole,
};
use vortix::vortix_core::profile::ProfileId;

#[derive(Clone, Default)]
struct RecordingAdapter {
    state: Arc<Mutex<RecordingState>>,
}

#[derive(Default)]
struct RecordingState {
    calls: Vec<u64>,
    verify_calls: Vec<u64>,
    released: Vec<String>,
    fail_next: bool,
    fail_verify: bool,
    unrelated: Vec<String>,
}

impl DnsPolicyAdapter for RecordingAdapter {
    fn capabilities(&self) -> DnsPlatformCapabilities {
        DnsPlatformCapabilities {
            scoped_domains: true,
        }
    }

    fn apply(
        &self,
        desired: &DnsPolicy,
        _previous_desired: Option<&DnsPolicy>,
        previous_effective: &DnsEffectiveState,
    ) -> DnsEffectiveState {
        let mut state = self.state.lock().unwrap();
        state.calls.push(desired.generation);
        if std::mem::take(&mut state.fail_next) {
            return DnsEffectiveState {
                requested_generation: desired.generation,
                applied_generation: previous_effective.applied_generation,
                status: DnsEffectiveStatus::Degraded,
                owned: previous_effective.owned.clone(),
                errors: vec!["injected partial platform failure".into()],
            };
        }

        let owned = desired
            .assignments
            .iter()
            .filter(|assignment| !matches!(assignment.scope, DnsScope::Suppressed))
            .map(|assignment| DnsOwnedResource {
                generation: desired.generation,
                id: format!("mock:{}", assignment.interface),
                profile_id: assignment.profile_id.clone(),
                interface: assignment.interface.clone(),
            })
            .collect::<Vec<_>>();
        for old in &previous_effective.owned {
            if !owned.iter().any(|new| new.id == old.id) {
                state.released.push(old.id.clone());
            }
        }
        DnsEffectiveState {
            requested_generation: desired.generation,
            applied_generation: Some(desired.generation),
            status: if owned.is_empty() {
                DnsEffectiveStatus::Released
            } else {
                DnsEffectiveStatus::Applied
            },
            owned,
            errors: Vec::new(),
        }
    }

    fn verify(
        &self,
        desired: &DnsPolicy,
        _effective: &DnsEffectiveState,
    ) -> Result<(), Vec<String>> {
        let mut state = self.state.lock().unwrap();
        state.verify_calls.push(desired.generation);
        if state.fail_verify {
            Err(vec!["injected DNS drift".into()])
        } else {
            Ok(())
        }
    }
}

fn intent(
    profile: &str,
    interface: &str,
    role: DnsTunnelRole,
    server: &str,
    domains: &[&str],
) -> DnsTunnelIntent {
    DnsTunnelIntent {
        profile_id: ProfileId::new(profile),
        interface: interface.into(),
        role,
        request: DnsRequest {
            servers: vec![server.parse::<IpAddr>().unwrap()],
            search_domains: domains.iter().map(|domain| (*domain).into()).collect(),
        },
    }
}

#[test]
fn primary_wireguard_secondary_openvpn_has_one_catch_all() {
    let policy = DnsPolicy::compute(
        1,
        &[
            intent("wg-primary", "wg0", DnsTunnelRole::Primary, "1.1.1.1", &[]),
            intent(
                "ovpn-secondary",
                "tun1",
                DnsTunnelRole::Secondary,
                "10.8.0.1",
                &[],
            ),
        ],
        DnsPlatformCapabilities {
            scoped_domains: true,
        },
    )
    .unwrap();

    assert!(matches!(policy.assignments[0].scope, DnsScope::Suppressed));
    assert!(matches!(policy.assignments[1].scope, DnsScope::CatchAll));
    assert_eq!(
        policy
            .assignments
            .iter()
            .filter(|assignment| matches!(assignment.scope, DnsScope::CatchAll))
            .count(),
        1
    );
}

#[test]
fn primary_openvpn_suppresses_secondary_wireguard_global_dns() {
    let policy = DnsPolicy::compute(
        9,
        &[
            intent("ovpn", "tun0", DnsTunnelRole::Primary, "10.8.0.1", &[]),
            intent("wg", "wg1", DnsTunnelRole::Secondary, "8.8.8.8", &[]),
        ],
        DnsPlatformCapabilities {
            scoped_domains: true,
        },
    )
    .unwrap();
    let wg = policy
        .assignments
        .iter()
        .find(|assignment| assignment.profile_id.as_str() == "wg")
        .unwrap();
    assert!(matches!(wg.scope, DnsScope::Suppressed));
}

#[test]
fn primary_transfer_recomputes_full_generation_and_releases_only_old_owned_resource() {
    let adapter = RecordingAdapter::default();
    adapter
        .state
        .lock()
        .unwrap()
        .unrelated
        .push("host-owned resolver".into());
    let mut coordinator = DnsPolicyCoordinator::default();
    let first = [
        intent("wg", "wg0", DnsTunnelRole::Primary, "1.1.1.1", &[]),
        intent("ovpn", "tun0", DnsTunnelRole::Secondary, "10.8.0.1", &[]),
    ];
    coordinator.reconcile(&first, &adapter).unwrap();

    let transferred = [
        intent("wg", "wg0", DnsTunnelRole::Secondary, "1.1.1.1", &[]),
        intent("ovpn", "tun0", DnsTunnelRole::Primary, "10.8.0.1", &[]),
    ];
    let effective = coordinator.reconcile(&transferred, &adapter).unwrap();
    assert_eq!(effective.applied_generation, Some(2));
    assert_eq!(effective.owned[0].id, "mock:tun0");
    let state = adapter.state.lock().unwrap();
    assert_eq!(state.released, vec!["mock:wg0"]);
    assert_eq!(state.unrelated, vec!["host-owned resolver"]);
}

#[test]
fn partial_platform_failure_is_degraded_and_preserves_prior_and_unrelated_state() {
    let adapter = RecordingAdapter::default();
    let mut coordinator = DnsPolicyCoordinator::default();
    coordinator
        .reconcile(
            &[intent("wg", "wg0", DnsTunnelRole::Primary, "1.1.1.1", &[])],
            &adapter,
        )
        .unwrap();
    {
        let mut state = adapter.state.lock().unwrap();
        state.fail_next = true;
        state.unrelated.push("system resolver".into());
    }

    let effective = coordinator
        .reconcile(
            &[intent(
                "ovpn",
                "tun0",
                DnsTunnelRole::Primary,
                "10.8.0.1",
                &[],
            )],
            &adapter,
        )
        .unwrap();
    assert_eq!(effective.status, DnsEffectiveStatus::Degraded);
    assert_eq!(effective.applied_generation, Some(1));
    assert_eq!(effective.owned[0].id, "mock:wg0");
    assert_eq!(
        adapter.state.lock().unwrap().unrelated,
        vec!["system resolver"]
    );
}

#[test]
fn repeated_apply_is_idempotent_and_scoped_secondary_stays_non_global() {
    let adapter = RecordingAdapter::default();
    let mut coordinator = DnsPolicyCoordinator::default();
    let intents = [
        intent("wg", "wg0", DnsTunnelRole::Primary, "1.1.1.1", &[]),
        intent(
            "ovpn",
            "tun0",
            DnsTunnelRole::Secondary,
            "10.8.0.1",
            &["corp.example"],
        ),
    ];
    coordinator.reconcile(&intents, &adapter).unwrap();
    coordinator.reconcile(&intents, &adapter).unwrap();
    assert_eq!(adapter.state.lock().unwrap().calls, vec![1]);
    let secondary = coordinator
        .desired()
        .unwrap()
        .assignments
        .iter()
        .find(|assignment| assignment.profile_id.as_str() == "ovpn")
        .unwrap();
    assert!(matches!(secondary.scope, DnsScope::Scoped { .. }));
}

#[test]
fn primary_search_domains_are_independent_of_catch_all_scope() {
    let policy = DnsPolicy::compute(
        1,
        &[
            intent(
                "primary",
                "wg0",
                DnsTunnelRole::Primary,
                "1.1.1.1",
                &[" Corp.Example. "],
            ),
            intent(
                "secondary",
                "tun0",
                DnsTunnelRole::Secondary,
                "10.8.0.1",
                &["internal.example"],
            ),
        ],
        DnsPlatformCapabilities {
            scoped_domains: true,
        },
    )
    .unwrap();
    let primary = policy
        .assignments
        .iter()
        .find(|assignment| assignment.profile_id.as_str() == "primary")
        .unwrap();
    assert!(matches!(primary.scope, DnsScope::CatchAll));
    assert_eq!(primary.search_domains, vec!["corp.example"]);
    let secondary = policy
        .assignments
        .iter()
        .find(|assignment| assignment.profile_id.as_str() == "secondary")
        .unwrap();
    assert_eq!(secondary.search_domains, vec!["internal.example"]);
    assert!(matches!(
        &secondary.scope,
        DnsScope::Scoped { domains } if domains == &["internal.example"]
    ));
}

#[test]
fn stale_unchanged_policy_is_read_back_without_reapply_and_drift_degrades() {
    let adapter = RecordingAdapter::default();
    let mut coordinator = DnsPolicyCoordinator::default();
    let intents = [intent("wg", "wg0", DnsTunnelRole::Primary, "1.1.1.1", &[])];
    coordinator.reconcile(&intents, &adapter).unwrap();
    coordinator.invalidate_verification();
    coordinator.reconcile(&intents, &adapter).unwrap();
    {
        let state = adapter.state.lock().unwrap();
        assert_eq!(state.calls, vec![1]);
        assert_eq!(state.verify_calls, vec![1]);
    }

    coordinator.invalidate_verification();
    adapter.state.lock().unwrap().fail_verify = true;
    let effective = coordinator.reconcile(&intents, &adapter).unwrap();
    assert_eq!(effective.status, DnsEffectiveStatus::Degraded);
    assert_eq!(effective.errors, vec!["injected DNS drift"]);
    assert_eq!(adapter.state.lock().unwrap().calls, vec![1]);
}

#[test]
fn failed_write_ahead_prevents_platform_mutation() {
    let adapter = RecordingAdapter::default();
    let mut coordinator = DnsPolicyCoordinator::default();
    let result = coordinator.reconcile_durable(
        &[intent("wg", "wg0", DnsTunnelRole::Primary, "1.1.1.1", &[])],
        &adapter,
        |_| Err::<(), _>("disk full"),
    );
    assert!(result.is_err());
    assert!(adapter.state.lock().unwrap().calls.is_empty());
    assert_eq!(coordinator.effective().status, DnsEffectiveStatus::Degraded);
}

#[test]
fn failed_effective_receipt_rolls_platform_back_and_degrades() {
    let adapter = RecordingAdapter::default();
    let mut coordinator = DnsPolicyCoordinator::default();
    let writes = std::cell::Cell::new(0_u8);
    let result = coordinator.reconcile_durable(
        &[intent("wg", "wg0", DnsTunnelRole::Primary, "1.1.1.1", &[])],
        &adapter,
        |_| {
            writes.set(writes.get().saturating_add(1));
            if writes.get() == 2 {
                Err("receipt write failed")
            } else {
                Ok(())
            }
        },
    );
    assert!(result.is_err());
    assert_eq!(adapter.state.lock().unwrap().calls, vec![1, 2]);
    assert_eq!(coordinator.effective().status, DnsEffectiveStatus::Degraded);
}
