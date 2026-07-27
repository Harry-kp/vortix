#![cfg(unix)]

use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{io::Read as _, io::Write as _};

use tokio::sync::broadcast;
use vortix::daemon::client::{self, ClientError};
use vortix::daemon::passive::PassiveQueryProvider;
use vortix::daemon::DaemonServer;
use vortix::vortix_core::engine::input::UserCommand;
use vortix::vortix_core::ipc::{
    ClientHello, IpcCapability, IpcError, IpcOp, IpcRequest, IpcResponse, IpcResult,
    PassiveSnapshot, PassiveTunnel,
};
use vortix::vortix_core::profile::{ProfileId, ProtocolKind};

struct FakeProvider {
    snapshot: Mutex<PassiveSnapshot>,
    events: broadcast::Sender<PassiveSnapshot>,
}

impl FakeProvider {
    fn new() -> Self {
        let (events, _) = broadcast::channel(4);
        Self {
            snapshot: Mutex::new(PassiveSnapshot {
                generation: 1,
                observed_at_millis: 1,
                tunnels: Vec::new(),
                authoritative: false,
            }),
            events,
        }
    }

    fn publish(&self, snapshot: PassiveSnapshot) {
        *self.snapshot.lock().unwrap() = snapshot.clone();
        let _ = self.events.send(snapshot);
    }
}

impl PassiveQueryProvider for FakeProvider {
    fn snapshot(&self) -> PassiveSnapshot {
        self.snapshot.lock().unwrap().clone()
    }

    fn subscribe(&self) -> broadcast::Receiver<PassiveSnapshot> {
        self.events.subscribe()
    }
}

fn raw_exchange(stream: &mut std::os::unix::net::UnixStream, request: &IpcRequest) -> IpcResponse {
    stream
        .write_all(&vortix::vortix_core::ipc::encode_frame(request).unwrap())
        .unwrap();
    let mut buffered = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        if let Some((response, _)) =
            vortix::vortix_core::ipc::decode_frame::<IpcResponse>(&buffered).unwrap()
        {
            return response;
        }
        let read = stream.read(&mut chunk).unwrap();
        assert!(read > 0);
        buffered.extend_from_slice(&chunk[..read]);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(
    clippy::too_many_lines,
    reason = "one live-server scenario verifies concurrency, replay fencing, streaming, and shutdown"
)]
async fn passive_candidate_is_concurrent_race_free_and_cannot_mutate() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("vortix.sock");
    let provider = Arc::new(FakeProvider::new());
    let server = DaemonServer::bind(socket.clone())
        .unwrap()
        .with_query_provider(provider.clone());
    let server_task = tokio::spawn(server.run());

    let mut clients = Vec::new();
    for _ in 0..8 {
        let socket = socket.clone();
        clients.push(tokio::task::spawn_blocking(move || {
            client::request(&socket, IpcOp::PassiveSnapshot)
        }));
    }
    for client in clients {
        let IpcResult::PassiveSnapshot { snapshot } = client.await.unwrap().unwrap() else {
            panic!("expected passive snapshot");
        };
        assert_eq!(snapshot.generation, 1);
        assert!(!snapshot.authoritative);
    }

    let duplicate_socket = socket.clone();
    let duplicate = tokio::task::spawn_blocking(move || {
        let mut stream = std::os::unix::net::UnixStream::connect(duplicate_socket).unwrap();
        let handshake = IpcRequest {
            id: 1,
            op: IpcOp::Handshake {
                hello: ClientHello::current(vec![IpcCapability::PassiveSnapshot]),
            },
        };
        assert!(matches!(
            raw_exchange(&mut stream, &handshake).result,
            Ok(IpcResult::Handshake { .. })
        ));
        let snapshot = IpcRequest {
            id: 7,
            op: IpcOp::PassiveSnapshot,
        };
        assert!(raw_exchange(&mut stream, &snapshot).result.is_ok());
        let conflicting = IpcRequest {
            id: 7,
            op: IpcOp::Shutdown,
        };
        raw_exchange(&mut stream, &conflicting).result
    })
    .await
    .unwrap();
    assert!(matches!(duplicate, Err(IpcError::DuplicateRequestId)));

    let mutation_socket = socket.clone();
    let mutation = tokio::task::spawn_blocking(move || {
        client::request(
            &mutation_socket,
            IpcOp::Execute(UserCommand::Disconnect { profile_id: None }),
        )
    })
    .await
    .unwrap();
    assert!(matches!(
        mutation,
        Err(ClientError::Daemon(IpcError::CapabilityUnavailable {
            capability: IpcCapability::ControlMutation
        }))
    ));

    let subscription_socket = socket.clone();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let subscription = tokio::task::spawn_blocking(move || {
        let mut subscription = client::subscribe(&subscription_socket).unwrap();
        ready_tx.send(subscription.initial().generation).unwrap();
        subscription.recv().unwrap()
    });
    assert_eq!(ready_rx.await.unwrap(), 1);
    provider.publish(PassiveSnapshot {
        generation: 2,
        observed_at_millis: 2,
        tunnels: vec![PassiveTunnel {
            profile_id: ProfileId::parse("c".repeat(ProfileId::HEX_LEN)).unwrap(),
            display_name: "corp".into(),
            protocol: ProtocolKind::WireGuard,
            interface_name: "wg0".into(),
            observed_at_millis: 2,
        }],
        authoritative: false,
    });
    let updated = tokio::time::timeout(Duration::from_secs(2), subscription)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated.generation, 2);
    assert_eq!(updated.tunnels.len(), 1);

    let shutdown_socket = socket.clone();
    let shutdown =
        tokio::task::spawn_blocking(move || client::request(&shutdown_socket, IpcOp::Shutdown))
            .await
            .unwrap()
            .unwrap();
    assert!(matches!(shutdown, IpcResult::ShuttingDown));
    tokio::time::timeout(Duration::from_secs(2), server_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
