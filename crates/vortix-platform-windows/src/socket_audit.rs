//! Windows `SocketAudit` stub (plan 015 phase C U13 / plan 013).
//!
//! Real impl would use `Get-NetTCPConnection`, `Get-NetUDPEndpoint`,
//! or the IP Helper API (`GetTcpTable2` etc.). Today returns
//! `Unsupported` so callers can surface a clean message; future
//! Windows work fills this in.

use vortix_core::ports::socket_audit::{
    SocketAudit, SocketAuditError, SocketAuditResult, SocketSnapshot,
};

#[derive(Debug, Clone, Copy, Default)]
pub struct WindowsSocketAudit;

impl SocketAudit for WindowsSocketAudit {
    fn snapshot() -> SocketAuditResult<Vec<SocketSnapshot>> {
        Err(SocketAuditError::Unsupported)
    }
}
