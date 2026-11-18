//! Provider accounts: an account, a server catalog and this computer's device
//! key. Each connection is a WireGuard profile Vortix writes from them, so the
//! engine runs it like any other; a driver per company turns its API into this
//! model (see `docs/adapters.md`).

mod mullvad;

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderDriver {
    Mullvad,
}

impl ProviderDriver {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Mullvad => "Mullvad",
        }
    }

    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Mullvad => "mullvad",
        }
    }

    pub const ALL: [Self; 1] = [Self::Mullvad];
}

/// One server a provider offers.
#[derive(Debug, Clone, PartialEq)]
pub struct Relay {
    pub hostname: String,
    pub country: String,
    pub city: String,
    pub latitude: f64,
    pub longitude: f64,
    pub public_key: String,
    /// `ip:port` to connect to.
    pub endpoint: String,
}

/// A provider's servers and the DNS server inside its tunnels.
#[derive(Debug, Clone, PartialEq)]
pub struct Catalog {
    pub relays: Vec<Relay>,
    pub dns: String,
}

/// This computer, registered with the account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub id: String,
    pub ipv4: String,
    pub ipv6: String,
}

/// `mullvad 1111 2222 3333 4444`: a provider and its account number.
#[must_use]
pub fn account_from_words(words: &str) -> Option<(ProviderDriver, Result<String, String>)> {
    let (first, rest) = words.trim().split_once(char::is_whitespace)?;
    let driver = ProviderDriver::ALL
        .into_iter()
        .find(|driver| first.eq_ignore_ascii_case(driver.slug()))?;
    let account = match driver {
        ProviderDriver::Mullvad => mullvad::account_number(rest),
    };
    Some((driver, account))
}

/// The server closest to `position`, else the first one.
fn nearest(catalog: &Catalog, position: Option<(f64, f64)>) -> Option<&Relay> {
    let Some((lat, lon)) = position else {
        return catalog.relays.first();
    };
    catalog.relays.iter().min_by(|a, b| {
        let distance =
            |relay: &Relay| (relay.latitude - lat).powi(2) + (relay.longitude - lon).powi(2);
        distance(a).total_cmp(&distance(b))
    })
}

/// The first line of a provider profile: which device of which provider.
fn header(driver: ProviderDriver, device: &Device) -> String {
    format!("# Provider: {} device {}", driver.slug(), device.id)
}

fn read_header(config: &str) -> Option<(ProviderDriver, String)> {
    let rest = config.lines().next()?.strip_prefix("# Provider: ")?;
    let (slug, id) = rest.split_once(" device ")?;
    let driver = ProviderDriver::ALL.into_iter().find(|d| d.slug() == slug)?;
    Some((driver, id.to_string()))
}

/// The WireGuard profile for `device` on `relay`.
#[must_use]
pub fn wireguard_config(
    driver: ProviderDriver,
    device: &Device,
    private_key: &str,
    relay: &Relay,
    dns: &str,
) -> String {
    format!(
        "{}\n# Server: {} ({}, {})\n[Interface]\nPrivateKey = {private_key}\nAddress = {}, {}\nDNS = {dns}\n\n[Peer]\nPublicKey = {}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = {}\n",
        header(driver, device),
        relay.hostname,
        relay.city,
        relay.country,
        device.ipv4,
        device.ipv6,
        relay.public_key,
        relay.endpoint,
    )
}

/// One HTTPS request through `curl`, with every option (the account number,
/// the token) on its stdin so none shows in the process list. Returns the
/// status and the body.
fn request(
    method: &str,
    url: &str,
    bearer: Option<&str>,
    body: Option<&str>,
) -> Result<(u16, Vec<u8>), String> {
    let quote = |text: &str| format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""));
    let mut config = format!(
        "silent\nshow-error\nmax-time = {}\nrequest = {}\nurl = {}\nwrite-out = \"\\n%{{http_code}}\"\n",
        crate::constants::HTTP_TIMEOUT_SECS,
        quote(method),
        quote(url),
    );
    if let Some(token) = bearer {
        config.push_str(&format!(
            "header = {}\n",
            quote(&format!("Authorization: Bearer {token}"))
        ));
    }
    if let Some(body) = body {
        config.push_str("header = \"Content-Type: application/json\"\n");
        config.push_str(&format!("data-binary = {}\n", quote(body)));
    }
    let spec = crate::process::CommandSpec::oneshot("curl", vec!["--config".into(), "-".into()])
        .stdin(config.into_bytes())
        .timeout(std::time::Duration::from_secs(
            crate::constants::HTTP_TIMEOUT_SECS + 5,
        ));
    let output =
        crate::process::run(spec).map_err(|error| format!("curl could not run: {error}"))?;
    if !output.success() {
        return Err(format!(
            "could not reach {}: {}",
            url.split('/').nth(2).unwrap_or(url),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let text = output.stdout;
    let split = text.iter().rposition(|byte| *byte == b'\n').unwrap_or(0);
    let status = String::from_utf8_lossy(&text[split..])
        .trim()
        .parse()
        .unwrap_or(0);
    Ok((status, text[..split].to_vec()))
}

fn state_dir() -> Result<PathBuf, String> {
    crate::config::get_config_dir()
        .map(|dir| dir.join("providers"))
        .map_err(|error| format!("cannot resolve the config directory: {error}"))
}

fn token(driver: ProviderDriver, account: &str) -> Result<String, String> {
    match driver {
        ProviderDriver::Mullvad => {
            let (url, body) = mullvad::token_request(account);
            let (_, reply) = request("POST", &url, None, Some(&body))?;
            mullvad::parse_token(&reply)
        }
    }
}

/// The server catalog, fresh from the provider.
pub fn catalog(driver: ProviderDriver) -> Result<Catalog, String> {
    match driver {
        ProviderDriver::Mullvad => {
            let (_, body) = request(
                "GET",
                &format!("{}/app/v1/relays", mullvad::API),
                None,
                None,
            )?;
            mullvad::parse_relays(&body)
        }
    }
}

/// Register this computer with `account` and write its profile, on the server
/// nearest to here, where imports are staged. Returns the staged file.
pub fn add(driver: ProviderDriver, account: &str) -> Result<PathBuf, String> {
    let catalog = catalog(driver)?;
    let position = match driver {
        ProviderDriver::Mullvad => request("GET", mullvad::WHERE_AM_I, None, None)
            .ok()
            .and_then(|(_, body)| mullvad::parse_position(&body)),
    };
    let relay = nearest(&catalog, position)
        .ok_or_else(|| format!("{} lists no servers right now", driver.name()))?
        .clone();
    let (private_key, public_key) = crate::wireguard::generate_keypair()?;
    let token = token(driver, account)?;
    let device = match driver {
        ProviderDriver::Mullvad => {
            let (url, body) = mullvad::device_request(&public_key);
            let (_, reply) = request("POST", &url, Some(&token), Some(&body))?;
            mullvad::parse_device(&reply)?
        }
    };
    // The account number is kept for removing this device again.
    let dir = state_dir()?;
    crate::config::owned_file::create_private_dir_all(&dir)
        .map_err(|error| format!("cannot create {}: {error}", dir.display()))?;
    crate::config::secret::write_secret_file(&dir.join(&device.id), account.as_bytes())
        .map_err(|error| format!("cannot save the account: {error}"))?;
    let staged = crate::config::get_config_dir()
        .map_err(|error| format!("cannot resolve the download directory: {error}"))?
        .join("downloads");
    crate::config::owned_file::create_private_dir_all(&staged)
        .map_err(|error| format!("cannot create the download directory: {error}"))?;
    let path =
        crate::config::profiles::get_unique_path(&staged, &format!("{}.conf", driver.slug()));
    let config = wireguard_config(driver, &device, &private_key, &relay, &catalog.dns);
    crate::config::secret::write_secret_file(&path, config.as_bytes())
        .map_err(|error| format!("cannot stage the {} profile: {error}", driver.name()))?;
    Ok(path)
}

/// The provider device a profile file belongs to, if a provider wrote it.
#[must_use]
pub fn device_of(config_path: &Path) -> Option<(ProviderDriver, String)> {
    std::fs::read_to_string(config_path)
        .ok()
        .and_then(|text| read_header(&text))
}

/// Remove `device` from its account, after its profile is deleted.
pub fn release(driver: ProviderDriver, device: &str) -> Result<(), String> {
    let saved = state_dir()?.join(device);
    let account = std::fs::read_to_string(&saved).map_err(|_| {
        format!(
            "the {} account for this profile is not saved here",
            driver.name()
        )
    })?;
    let token = token(driver, account.trim())?;
    let status = match driver {
        ProviderDriver::Mullvad => {
            request("DELETE", &mullvad::device_url(device), Some(&token), None)?.0
        }
    };
    // Already gone counts as removed.
    if !(status == 204 || status == 404) {
        return Err(format!(
            "{} kept this device (HTTP {status})",
            driver.name()
        ));
    }
    let _ = std::fs::remove_file(saved);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay(hostname: &str, latitude: f64, longitude: f64) -> Relay {
        Relay {
            hostname: hostname.into(),
            country: "Sweden".into(),
            city: "Gothenburg".into(),
            latitude,
            longitude,
            public_key: "c2VydmVy".into(),
            endpoint: "185.213.154.68:51820".into(),
        }
    }

    #[test]
    fn a_provider_name_and_an_account_number_add_an_account() {
        let (driver, account) = account_from_words("Mullvad 1111 2222 3333 4444").unwrap();
        assert_eq!(
            (driver, account),
            (ProviderDriver::Mullvad, Ok("1111222233334444".into()))
        );
        assert!(account_from_words("mullvad 12").unwrap().1.is_err());
        assert!(account_from_words("netbird https://x").is_none());
        assert!(account_from_words("mullvad").is_none());
    }

    #[test]
    fn the_nearest_server_is_chosen() {
        let catalog = Catalog {
            relays: vec![relay("far", 0.0, 100.0), relay("near", 52.0, 5.0)],
            dns: "10.64.0.1".into(),
        };
        assert_eq!(
            nearest(&catalog, Some((52.37, 4.9))).unwrap().hostname,
            "near"
        );
        assert_eq!(nearest(&catalog, None).unwrap().hostname, "far");
    }

    /// A full tunnel through the server, the provider's DNS, and a first line
    /// that names the device it belongs to.
    #[test]
    fn the_profile_is_a_full_wireguard_tunnel_that_names_its_device() {
        let device = Device {
            id: "d1".into(),
            ipv4: "10.68.1.2/32".into(),
            ipv6: "fc00::2/128".into(),
        };
        let config = wireguard_config(
            ProviderDriver::Mullvad,
            &device,
            "cHJpdg==",
            &relay("se-got-wg-001", 0.0, 0.0),
            "10.64.0.1",
        );
        let parsed = crate::wireguard::parser::parse_wg_conf(&config).unwrap();
        assert!(parsed.has_dns());
        assert!(config.contains("AllowedIPs = 0.0.0.0/0, ::/0"));
        assert!(config.contains("Endpoint = 185.213.154.68:51820"));
        assert!(config.contains("# Server: se-got-wg-001 (Gothenburg, Sweden)"));
        assert_eq!(
            read_header(&config),
            Some((ProviderDriver::Mullvad, "d1".into()))
        );
        assert_eq!(read_header("[Interface]\n"), None);
    }
}
