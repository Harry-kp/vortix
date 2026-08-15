//! Fixed-vocabulary macOS route-selection read-back for the root helper.

use std::net::IpAddr;

use crate::platform::fixed_root_command;
use crate::vortix_core::ports::owned_routes::{OwnedRouteError, OwnedRoutes};

const ROUTE_CANDIDATES: &[&str] = &["/sbin/route", "/usr/sbin/route"];

pub(crate) struct MacOsOwnedRoutes;

impl OwnedRoutes for MacOsOwnedRoutes {
    fn route_interface_for(&mut self, target: IpAddr) -> Result<String, OwnedRouteError> {
        let target = target.to_string();
        let output =
            fixed_root_command::run(ROUTE_CANDIDATES, &["-n", "get", target.as_str()], None, 0)
                .map_err(|_| OwnedRouteError::Unknown)?;
        if !output.status.success() {
            return Err(OwnedRouteError::Unknown);
        }
        super::route_table::parse_interface(&output.stdout).ok_or(OwnedRouteError::Unknown)
    }
}
