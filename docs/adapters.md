# Adapters: one interface for every VPN

Vortix is one interface for the VPNs people actually use, whatever they call them: WireGuard,
OpenVPN, NetBird, Mullvad, and others as users ask for them. Users never pick a protocol; they
add a connection and use it. Behind each connection sits an adapter. This page is the contract
every adapter follows. It describes the target design; today the adapters are WireGuard and
OpenVPN, which read profile files, and NetBird, whose `.netbird` profile names a network.

## The fixed experience

Every connection, whatever its adapter, gets the same Vortix:

- a row in the sidebar, the same connect, disconnect, switch and reconnect keys, and the same
  states (connecting, up, reconnecting, waiting for credentials, failed with the reason);
- the header, Connection Details (and its Health side), the throughput chart and the logs;
- the Security Guard's leak verdicts and the kill switch, which knows every running tunnel;
- the CLI (`up`, `down`, `status`, `list`) and the versioned JSON;
- autoconnect at boot, lifecycle hooks and the session journal.

An adapter may add **one** thing the fixed layout cannot hold, behind one key and only where
it applies: a server picker for a provider's catalog, a peer list for a mesh, a login step.
It never adds a panel per connection, a second vocabulary or its own settings screen.

## Sources and transports

- **Source**: where connections come from and how the user authenticates. Files (`.conf`,
  `.ovpn`), a provider account (Mullvad: an account number, a server catalog, key
  management), a network (NetBird: a management URL with SSO or a setup key). A source
  produces connections; it does not run them.
- **Transport**: how a connection runs as a process Vortix starts, supervises and stops:
  `wg-quick`, `openvpn`, the `netbird` daemon (`netbird service run`, one per network with its
  own state directory), later `openconnect`. A
  transport reports what it can (peers, handshakes, pushed routes) and says whether it
  installs its own routes and DNS; the planner coordinates with one that does instead of
  overriding it.

A provider such as Mullvad is a source on the WireGuard transport, so it adds no new process
type. NetBird is both a source and a transport.

Vortix runs every transport itself. It never attaches to a VPN it has no profile for; a
running tunnel is adopted only when it matches a known profile (see `control/scanner.rs`). If a
product's own system service is running, Vortix explains and offers to take over rather than
fight it.

## Generic by kind, specific only at the edge

The unit of design is the **kind** of VPN, not the company. Each kind has one model, one
behaviour in the engine and one UI, written once:

| Kind | Examples | Shared model and UI |
|---|---|---|
| Config file | WireGuard `.conf`, OpenVPN `.ovpn` | Profile; import, rename, delete |
| Provider account | Mullvad, Proton, IVPN | Account, `Server` catalog (location, load, latency), keys; one server picker, favourites, recents, connect fastest |
| Mesh network (`mesh/`, a `MeshDriver` per vendor) | NetBird, Tailscale, Headscale, Netmaker | Network, `MeshPeer` (address, connected, direct or relayed, latency), `RoutedNetwork` (range or domains, in use, exit node), login (a link or a key); one overlay (`P`) for networks and peers, one login step; the daemon runs under the kill switch's transport group |

A company is a **driver**: the code that turns its CLI output or API into that model and
issues its commands, plus its name and wording in the UI. Nothing outside the driver names the
company. The test for every change: would the next company of the same kind need only a new
driver and labels? If not, move the logic into the kind. A capability one company lacks is an
optional field on the model, not a branch on the company.

## Adding an adapter

1. **Demand first.** An adapter is a maintenance contract with someone else's API or binary;
   it needs an `approved` issue with users who asked for it.
2. **Its own module** (`wireguard/`, `openvpn/`, or a driver file under `mesh/`), the only place its binary is
   named; add the binary to `check_protocol_leak` in `crates/xtask/src/main.rs`. Sources and
   transports are plain enums matched in one place, not traits.
3. **Tests** with `process::MockRunner` canned output for every state the UI shows, and a
   `control/plan.rs` test for how its routes and DNS meet the planner.
4. **A live check** in `docs/manual-testing/P0.md`, and how to reach its test account in
   `docs/live-testing.md` (never the credentials); release QA runs it like any other protocol.
5. **Say what it does not cover.** A product feature that lives only inside the vendor's
   own app (for example Mullvad's DAITA) is listed as unsupported in `docs/usage.md`.

## Release order

The North Star in `CLAUDE.md` is the goal; this is the path.

| Release | Feature | What users get |
|---|---|---|
| — | The seam (no visible change) | One transport enum behind today's WireGuard/OpenVPN dispatch; a source on every profile |
| 0.6 | NetBird | Add a network (setup key or login link); connect and disconnect run by Vortix; peers (direct or relayed, latency) and the networks it routes to; a kill switch that keeps it working beside other tunnels; moving from the NetBird app with the same device |
| 0.7 | Mullvad | Add an account by its number; a server picker by country and city with latency, favourites and recents; connect fastest (imported files too); key housekeeping |
| 0.8 | Always works | Reconnect after sleep, network changes and server address changes, for every adapter; "why can't I reach X?" (which tunnel carries an address, direct or relayed, which DNS answered) |
| next | Another adapter | Proton, IVPN, corporate VPNs through `openconnect`, as users ask |

From 0.6 the first-run screen offers Add NetBird, Add Mullvad and Import a file, and the README
tagline changes to the one-interface story (every copy at once).
