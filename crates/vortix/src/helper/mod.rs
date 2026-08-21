//! Privileged-helper contract, dormant execution core, and packaging boundary.
//!
//! U11 established the wire, identity, and installation rules. U12 operation
//! families are implemented behind crate-private capabilities one at a time;
//! the helper binary remains staged and exposes no server entrypoint until U13
//! enrollment.

mod bootstrap;
mod child_evidence;
mod descriptor_transport;
mod dns;
mod enrollment_store;
mod executor;
mod firewall;
mod material;
mod observe;
mod platform_identity;
mod private_fs;
pub mod protocol;
mod replay_store;
mod root_store;
mod routes;
mod runtime;
mod server;
mod transport;
pub mod validate;

pub use bootstrap::{
    stage_package_from_reader, BootstrapError, BootstrapStageReceipt, MAX_INSTALL_REQUEST_BYTES,
};
pub(crate) use descriptor_transport::{
    expected_descriptor_count_for_operation, prepare_request, send_prepared_request,
};
pub use protocol::{
    decode_request_frame, decode_response_frame, encode_request_frame, encode_response_frame,
    negotiate_staged, parse_request, HelperAuthorityMode, HelperCapability, HelperClientHello,
    HelperError, HelperOp, HelperPolicyInventory, HelperPolicyResource, HelperRequest,
    HelperResponse, HelperResult, HelperServerHello, HelperSessionBinding, HELPER_PROTOCOL_MAX,
    HELPER_PROTOCOL_MIN, HELPER_SCHEMA_MAX, HELPER_SCHEMA_MIN, MAX_HELPER_FRAME_BYTES,
};
pub(crate) use runtime::HelperRuntimeIdentity;
pub(crate) use server::process_group_for_tunnel;
pub(crate) use transport::connect_verified_helper;
pub use transport::{serve_staged_helper, HelperTransportError};
pub use validate::{
    ArtifactKind, EnrollmentSupport, InstallError, InstallManifest, InstallPlan, InstallRequest,
    PackageChannel, PlatformLayout, StagedAuthority, HELPER_LEDGER_MODE, HELPER_RUNTIME_DIR_MODE,
    HELPER_SOCKET_DIR_MODE, HELPER_SOCKET_MODE, INSTALL_SCHEMA_VERSION,
};
