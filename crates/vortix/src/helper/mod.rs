//! Dormant privileged-helper contract and packaging boundary.
//!
//! This module deliberately contains no privileged execution. U11 freezes the
//! wire, identity, and installation rules so the later executor cannot grow a
//! generic command, path, environment, or profile-shaped escape hatch.

pub mod protocol;
pub mod validate;

pub use protocol::{
    negotiate_staged, parse_request, HelperAuthorityMode, HelperCapability, HelperClientHello,
    HelperError, HelperOp, HelperRequest, HelperResponse, HelperResult, HelperServerHello,
    HELPER_PROTOCOL_MAX, HELPER_PROTOCOL_MIN, HELPER_SCHEMA_MAX, HELPER_SCHEMA_MIN,
    MAX_HELPER_FRAME_BYTES,
};
pub use validate::{
    ArtifactKind, EnrollmentSupport, InstallError, InstallManifest, InstallPlan, InstallRequest,
    PackageChannel, PlatformLayout, StagedAuthority, HELPER_LEDGER_MODE, HELPER_RUNTIME_DIR_MODE,
    HELPER_SOCKET_MODE, INSTALL_SCHEMA_VERSION,
};
