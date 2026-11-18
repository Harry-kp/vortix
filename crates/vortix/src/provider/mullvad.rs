//! Mullvad: the driver from its public API (the one its own app uses) to the
//! provider model. The only file that names Mullvad.

use super::{Catalog, Device, Relay};
use serde::Deserialize;

pub(super) const API: &str = "https://api.mullvad.net";
/// Where the caller is, by Mullvad's own lookup: picks the nearest server.
pub(super) const WHERE_AM_I: &str = "https://am.i.mullvad.net/json";
const WIREGUARD_PORT: u16 = 51820;

#[derive(Deserialize)]
struct RelayList {
    locations: std::collections::HashMap<String, Location>,
    wireguard: WireGuardRelays,
}

#[derive(Deserialize)]
struct Location {
    country: String,
    city: String,
    latitude: f64,
    longitude: f64,
}

#[derive(Deserialize)]
struct WireGuardRelays {
    relays: Vec<RelayEntry>,
    ipv4_gateway: String,
}

#[derive(Deserialize)]
struct RelayEntry {
    hostname: String,
    location: String,
    active: bool,
    public_key: String,
    ipv4_addr_in: String,
}

/// `GET /app/v1/relays`: the active WireGuard servers with their place, and
/// the in-tunnel DNS server.
pub(super) fn parse_relays(body: &[u8]) -> Result<Catalog, String> {
    let list: RelayList = serde_json::from_slice(body)
        .map_err(|error| format!("Mullvad's server list could not be read: {error}"))?;
    let mut relays: Vec<Relay> = list
        .wireguard
        .relays
        .into_iter()
        .filter(|relay| relay.active)
        .filter_map(|relay| {
            let place = list.locations.get(&relay.location)?;
            Some(Relay {
                hostname: relay.hostname,
                country: place.country.clone(),
                city: place.city.clone(),
                latitude: place.latitude,
                longitude: place.longitude,
                public_key: relay.public_key,
                endpoint: format!("{}:{WIREGUARD_PORT}", relay.ipv4_addr_in),
            })
        })
        .collect();
    relays.sort_by(|a, b| {
        (&a.country, &a.city, &a.hostname).cmp(&(&b.country, &b.city, &b.hostname))
    });
    Ok(Catalog {
        relays,
        dns: list.wireguard.ipv4_gateway,
    })
}

/// `POST /auth/v1/token`.
pub(super) fn token_request(account: &str) -> (String, String) {
    (
        format!("{API}/auth/v1/token"),
        serde_json::json!({ "account_number": account }).to_string(),
    )
}

pub(super) fn parse_token(body: &[u8]) -> Result<String, String> {
    #[derive(Deserialize)]
    struct Token {
        access_token: String,
    }
    serde_json::from_slice::<Token>(body)
        .map(|token| token.access_token)
        .map_err(|_| api_error(body))
}

/// `POST /accounts/v1/devices`: registers this computer's public key.
pub(super) fn device_request(public_key: &str) -> (String, String) {
    (
        format!("{API}/accounts/v1/devices"),
        serde_json::json!({ "pubkey": public_key, "hijack_dns": false }).to_string(),
    )
}

pub(super) fn parse_device(body: &[u8]) -> Result<Device, String> {
    #[derive(Deserialize)]
    struct Created {
        id: String,
        ipv4_address: String,
        ipv6_address: String,
    }
    serde_json::from_slice::<Created>(body)
        .map(|device| Device {
            id: device.id,
            ipv4: device.ipv4_address,
            ipv6: device.ipv6_address,
        })
        .map_err(|_| api_error(body))
}

/// `DELETE /accounts/v1/devices/{id}`.
pub(super) fn device_url(id: &str) -> String {
    format!("{API}/accounts/v1/devices/{id}")
}

/// `am.i.mullvad.net/json`: latitude and longitude of the caller.
pub(super) fn parse_position(body: &[u8]) -> Option<(f64, f64)> {
    #[derive(Deserialize)]
    struct Here {
        latitude: f64,
        longitude: f64,
    }
    serde_json::from_slice::<Here>(body)
        .ok()
        .map(|here| (here.latitude, here.longitude))
}

/// A refusal in words a user can act on. Mullvad answers errors as
/// `{"code": "..."}`.
pub(super) fn api_error(body: &[u8]) -> String {
    #[derive(Deserialize)]
    struct Refusal {
        code: String,
    }
    match serde_json::from_slice::<Refusal>(body).map(|refusal| refusal.code) {
        Ok(code) if code == "INVALID_ACCOUNT" => {
            "Mullvad does not know this account number; check it at mullvad.net".into()
        }
        Ok(code) if code == "MAX_DEVICES_REACHED" => {
            "this Mullvad account already has its maximum of devices; remove one at \
             mullvad.net/account (Devices), then add it again"
                .into()
        }
        Ok(code) => format!("Mullvad refused the request ({code})"),
        Err(_) => "Mullvad's API gave an answer Vortix could not read".into(),
    }
}

/// Mullvad account numbers are 16 digits; spaces between groups are allowed.
pub(super) fn account_number(text: &str) -> Result<String, String> {
    let digits: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if digits.len() == 16 && digits.chars().all(|c| c.is_ascii_digit()) {
        Ok(digits)
    } else {
        Err("a Mullvad account number is 16 digits".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RELAYS: &str = r#"{
        "locations": {
            "se-got": {"country": "Sweden", "city": "Gothenburg", "latitude": 57.7, "longitude": 11.97},
            "de-fra": {"country": "Germany", "city": "Frankfurt", "latitude": 50.11, "longitude": 8.68}
        },
        "openvpn": {"relays": []},
        "wireguard": {
            "relays": [
                {"hostname": "se-got-wg-001", "location": "se-got", "active": true,
                 "public_key": "c2Utc2VydmVyLWtleQ==", "ipv4_addr_in": "185.213.154.68",
                 "ipv6_addr_in": "2a03:1b20:5:f011::a01f", "weight": 100, "daita": true},
                {"hostname": "de-fra-wg-002", "location": "de-fra", "active": false,
                 "public_key": "ZGUta2V5", "ipv4_addr_in": "193.27.14.1"},
                {"hostname": "de-fra-wg-001", "location": "de-fra", "active": true,
                 "public_key": "ZGUta2V5LTE=", "ipv4_addr_in": "193.27.14.2"},
                {"hostname": "xx-nowhere-wg-001", "location": "xx-nowhere", "active": true,
                 "public_key": "eHg=", "ipv4_addr_in": "10.0.0.1"}
            ],
            "port_ranges": [[51820, 51820]],
            "ipv4_gateway": "10.64.0.1",
            "ipv6_gateway": "fc00:bbbb:bbbb:bb01::1"
        },
        "bridge": {"relays": []}
    }"#;

    /// Active servers with a known place, sorted by country and city; the
    /// gateway is the DNS server.
    #[test]
    fn the_server_list_keeps_active_wireguard_servers_with_their_place() {
        let catalog = parse_relays(RELAYS.as_bytes()).unwrap();
        let names: Vec<_> = catalog.relays.iter().map(|r| r.hostname.as_str()).collect();
        assert_eq!(names, ["de-fra-wg-001", "se-got-wg-001"]);
        let gothenburg = &catalog.relays[1];
        assert_eq!(
            (gothenburg.country.as_str(), gothenburg.city.as_str()),
            ("Sweden", "Gothenburg")
        );
        assert_eq!(gothenburg.endpoint, "185.213.154.68:51820");
        assert_eq!(catalog.dns, "10.64.0.1");
        assert!(parse_relays(b"<html>").is_err());
    }

    #[test]
    fn requests_carry_their_secrets_only_in_the_body() {
        let (url, body) = token_request("1111222233334444");
        assert_eq!(url, "https://api.mullvad.net/auth/v1/token");
        assert_eq!(body, r#"{"account_number":"1111222233334444"}"#);
        let (url, body) = device_request("cHVi");
        assert_eq!(url, "https://api.mullvad.net/accounts/v1/devices");
        assert!(body.contains(r#""pubkey":"cHVi""#) && body.contains(r#""hijack_dns":false"#));
        assert_eq!(
            device_url("abc"),
            "https://api.mullvad.net/accounts/v1/devices/abc"
        );
    }

    #[test]
    fn a_registered_device_gives_its_addresses() {
        let device = parse_device(
            br#"{"id": "d1", "name": "happy otter", "pubkey": "cHVi",
                 "ipv4_address": "10.68.1.2/32", "ipv6_address": "fc00:bbbb:bbbb:bb01::1:2/128",
                 "hijack_dns": false, "created": "2026-11-04T00:00:00Z"}"#,
        )
        .unwrap();
        assert_eq!(
            (
                device.id.as_str(),
                device.ipv4.as_str(),
                device.ipv6.as_str()
            ),
            ("d1", "10.68.1.2/32", "fc00:bbbb:bbbb:bb01::1:2/128")
        );
        assert_eq!(
            parse_token(br#"{"access_token": "t0k", "expiry": "2999-01-01T00:00:00Z"}"#),
            Ok("t0k".into())
        );
    }

    /// Refusals read as what to do, never as a raw code or the account number.
    #[test]
    fn refusals_say_what_to_do() {
        assert!(parse_device(br#"{"code": "MAX_DEVICES_REACHED"}"#)
            .unwrap_err()
            .contains("remove one at mullvad.net/account"));
        assert!(parse_token(br#"{"code": "INVALID_ACCOUNT"}"#)
            .unwrap_err()
            .contains("does not know this account number"));
        assert!(parse_token(b"").unwrap_err().contains("could not read"));
    }

    #[test]
    fn account_numbers_are_sixteen_digits() {
        assert_eq!(
            account_number("1111 2222 3333 4444"),
            Ok("1111222233334444".into())
        );
        assert!(account_number("1111").is_err());
        assert!(account_number("1111222233334444x").is_err());
    }

    #[test]
    fn the_callers_position_is_read() {
        assert_eq!(
            parse_position(br#"{"ip": "203.0.113.7", "latitude": 52.37, "longitude": 4.9}"#),
            Some((52.37, 4.9))
        );
        assert_eq!(parse_position(b"{}"), None);
    }
}
