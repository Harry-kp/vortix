use crate::app::App;
use crate::state::{KillSwitchMode, KillSwitchState};
use crate::vortix_core::engine::registry::TunnelSnapshot;
use crate::vortix_core::engine::state::Connection;
use crate::{constants, theme, utils};
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Padding, Paragraph},
    Frame,
};

// ── Layout primitives ───────────────────────────────────────────────────────
//
// The panel reads like a form: each row is `<indent> <label> <value> <…> <sigil>`
// with the sigil right-aligned in a fixed 3-cell column. Visual hierarchy
// comes from `Sigil` variants (muted-by-default for OK rows, bright for
// alarms) and from a single dim accent on the section words. Theme constants
// only — no new colours. The polish principles apply uniformly to all three
// render branches (`PROTECTED` / `PARTIAL` / `EXPOSED`) so the panel feels
// the same regardless of posture.

/// Width threshold below which section words drop and the panel renders as
/// a flat list. Picked against the panel's actual budget at 80×24 — the
/// Security panel gets ~40% of the dash row's width, which lands around
/// 24 cells of inner content on a typical terminal.
const SECTION_HEADER_MIN_INNER_WIDTH: u16 = 24;

/// Total width of the label column: 10-char label slot + `: ` separator
/// (2 chars). Mirrors `connection_details.rs`'s `<label>: <value>` style
/// so the two side-by-side panels read with the same tabular rhythm.
/// The block itself already adds 1 cell of horizontal padding.
///
/// 10 chars accommodates the longest Identity/Defense row labels
/// without truncation: `Killswitch` (10), `Encryption` (10),
/// `Real IP` / `Exit IP` / `Location` / `DNS` / `IPv6` (≤8).
const LABEL_COLUMN_WIDTH: usize = 12;

/// Total width of the right-pinned sigil column: 1-char sigil + 1-space pad.
const SIGIL_COLUMN_WIDTH: usize = 2;

/// Status sigil with its rendering rules.
///
/// - `OkMuted` — the row is fine; sigil sits in the right column in the
///   theme's success colour, no bold modifier. Recedes visually.
/// - `NotApplicable` — the row is reporting a dimension the current
///   platform doesn't enforce (e.g. IPv6 on a v4-only killswitch). Greys
///   out so it doesn't read as a fixable warning.
/// - `AlarmWarn` / `AlarmError` — the row needs attention. Bold modifier
///   pulls the eye; these are the only bolded sigils on screen in the
///   all-OK state.
#[derive(Clone, Copy)]
enum Sigil {
    OkMuted,
    NotApplicable,
    AlarmWarn,
    AlarmError,
}

impl Sigil {
    /// Map this panel-local sigil onto its [`SigilId`] in the shared
    /// catalog. The mapping is intentionally explicit so any new SG
    /// sigil added here forces a catalog entry too.
    fn id(self) -> crate::ui::sigils::SigilId {
        use crate::ui::sigils::SigilId;
        match self {
            Self::OkMuted => SigilId::SgOk,
            Self::NotApplicable => SigilId::SgNotApplicable,
            Self::AlarmWarn => SigilId::SgAlarmWarn,
            Self::AlarmError => SigilId::SgAlarmError,
        }
    }

    fn glyph(self) -> &'static str {
        crate::ui::sigils::sigil(self.id()).glyph
    }

    fn style(self) -> Style {
        crate::ui::sigils::sigil(self.id()).style()
    }
}

// ── Cipher strength classification ──────────────────────────────────────────
//
// The Encryption row used to render the cipher name with the same green
// `✓` regardless of whether the cipher was modern AEAD or 1990s broken
// crypto (BF-CBC etc. still ship in legacy OpenVPN profiles). The
// classification below turns the raw cipher string into a security-grade
// verdict so the panel actually surfaces the strength, not just the name.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum CipherStrength {
    /// Modern AEAD (ChaCha20-Poly1305, AES-GCM family). The right
    /// default for any new VPN deployment.
    Modern,
    /// Non-AEAD but cryptographically strong (AES-256 in CBC/CTR mode,
    /// AES-192). Acceptable but worth upgrading.
    Strong,
    /// Deprecated — still functional crypto but vulnerable to known
    /// attacks (Sweet32 on 64-bit-block ciphers, 3DES brute-force window,
    /// AES-128-CBC padding-oracle exposure in some protocols). Should be
    /// replaced.
    Deprecated,
    /// Broken or null. Active compromise: BF-CBC (Sweet32 + small block),
    /// DES / RC4 / RC2 / NULL / CAST5 / IDEA — the wire is effectively
    /// plaintext to a motivated adversary.
    Insecure,
}

impl CipherStrength {
    fn label(self) -> &'static str {
        match self {
            Self::Modern => "modern AEAD",
            Self::Strong => "strong",
            Self::Deprecated => "deprecated",
            Self::Insecure => "INSECURE",
        }
    }

    fn sigil(self) -> Sigil {
        match self {
            Self::Modern | Self::Strong => Sigil::OkMuted,
            Self::Deprecated => Sigil::AlarmWarn,
            Self::Insecure => Sigil::AlarmError,
        }
    }

    fn value_color(self) -> Color {
        match self {
            Self::Modern | Self::Strong => theme::NORD_YELLOW,
            Self::Deprecated => theme::WARNING,
            Self::Insecure => theme::ERROR,
        }
    }

    /// Sub-line copy shown under an alarming Encryption row. None for
    /// `Modern` / `Strong` — those rows stay silent.
    fn alarm_subline(self) -> Option<&'static str> {
        match self {
            Self::Insecure => Some("broken cipher — switch to AES-GCM or ChaCha20"),
            Self::Deprecated => Some("upgrade to AES-GCM or ChaCha20-Poly1305"),
            Self::Modern | Self::Strong => None,
        }
    }
}

/// Classify a cipher string into a security-grade verdict. Accepts the
/// common `OpenVPN` / `WireGuard` cipher names (case-insensitive; tolerates
/// whitespace and embedded protocol metadata).
fn classify_cipher(cipher: &str) -> CipherStrength {
    let c = cipher.to_uppercase();

    // Order matters: check the BROKEN family first so a name like
    // `DES-EDE3-CBC` doesn't slip through a generic `AES-` test below.

    // Broken — wire is effectively plaintext.
    // BF/Blowfish — Sweet32 (CVE-2016-2183).
    if c.contains("BF-") || c.contains("BLOWFISH") {
        return CipherStrength::Insecure;
    }
    // DES (single) — 56-bit key, brute-forceable.
    if c == "DES" || c.contains("DES-CBC") && !c.contains("3DES") && !c.contains("DES-EDE") {
        return CipherStrength::Insecure;
    }
    // RC4 / RC2 — broken stream ciphers (CVE-2015-2808).
    if c.contains("RC4") || c.contains("RC2") {
        return CipherStrength::Insecure;
    }
    // NULL cipher — no encryption.
    if c.contains("NULL") {
        return CipherStrength::Insecure;
    }
    // CAST5 / IDEA — small block, known attacks.
    if c.contains("CAST5") || c.contains("IDEA") {
        return CipherStrength::Insecure;
    }

    // Modern AEAD — preferred default.
    if c.contains("CHACHA20-POLY1305")
        || c.contains("XCHACHA20")
        || c.contains("AES-256-GCM")
        || c.contains("AES-192-GCM")
        || c.contains("AES-128-GCM")
    {
        return CipherStrength::Modern;
    }

    // Deprecated — still secret today but plan to migrate.
    // 3DES (DES-EDE3) — brute-force window narrowing; deprecated by NIST.
    if c.contains("3DES") || c.contains("DES-EDE3") || c.contains("DES-EDE") {
        return CipherStrength::Deprecated;
    }
    // AES-128 in CBC — Sweet32 + padding-oracle exposure depending on
    // surrounding protocol. Still strong primitive but worth upgrading.
    if c.contains("AES-128-CBC") {
        return CipherStrength::Deprecated;
    }

    // Strong — AES-256 in CBC/CTR, AES-192 non-GCM. Acceptable.
    if c.contains("AES-256-CBC") || c.contains("AES-256-CTR") || c.contains("AES-192") {
        return CipherStrength::Strong;
    }

    // Anything we don't recognise — be cautious. Better to flag a
    // false-positive deprecated label than to mark unknown crypto as
    // Modern.
    CipherStrength::Deprecated
}

/// Section word rendered above its rows. Uses the theme's primary accent in
/// non-bold form so it reads as a structural marker, not an alarm. Mirrors
/// how other dashboard panels (Sidebar, Connection Details) treat their
/// section labels for cross-panel coherence.
fn section_header(name: &'static str) -> Line<'static> {
    Line::from(Span::styled(
        name.to_string(),
        Style::default().fg(theme::ACCENT_PRIMARY),
    ))
}

/// Single row in the audit panel. Three columns visually: indent+label
/// (fixed width), value (gets the remaining space), sigil (right-pinned).
///
/// `value_color` is the colour of the value text itself — usually
/// `theme::TEXT_PRIMARY` for muted-OK rows or the sigil's colour for
/// alarming rows.
fn audit_row(
    label: &str,
    value: &str,
    value_color: Color,
    sigil: Sigil,
    inner_width: usize,
) -> Line<'static> {
    let label_col = format!("{label:<10}: ");
    debug_assert_eq!(label_col.chars().count(), LABEL_COLUMN_WIDTH);

    let value_budget = inner_width
        .saturating_sub(LABEL_COLUMN_WIDTH)
        .saturating_sub(SIGIL_COLUMN_WIDTH);
    let value_truncated = utils::truncate(value, value_budget);
    let value_chars = value_truncated.chars().count();
    let padding = " ".repeat(value_budget.saturating_sub(value_chars));

    let sigil_col = format!("{} ", sigil.glyph());

    Line::from(vec![
        Span::styled(label_col, Style::default().fg(theme::TEXT_SECONDARY)),
        Span::styled(value_truncated, Style::default().fg(value_color)),
        Span::raw(padding),
        Span::styled(sigil_col, sigil.style()),
    ])
}

/// One-line human-readable explainer rendered under an alarming row.
/// Aligned to the value column for visual continuity with its parent row.
fn alarm_subline(text: &str, inner_width: usize) -> Line<'static> {
    let indent = " ".repeat(LABEL_COLUMN_WIDTH);
    let budget = inner_width.saturating_sub(LABEL_COLUMN_WIDTH);
    let truncated = utils::truncate(text, budget);
    Line::from(vec![
        Span::raw(indent),
        Span::styled(truncated, Style::default().fg(theme::TEXT_SECONDARY)),
    ])
}

/// Footer line: `Updated Ns ago` / `Updated Nm ago` / pending placeholder.
fn footer_line(secs: Option<u64>) -> Line<'static> {
    let text = match secs {
        Some(s) if s < 5 => "Updated just now".to_string(),
        Some(s) if s < 60 => format!("Updated {s}s ago"),
        Some(s) => format!("Updated {}m ago", s / 60),
        None => "Updated pending…".to_string(),
    };
    Line::from(Span::styled(text, Style::default().fg(Color::DarkGray)))
}

// ── PanelState: the polished panel's read-only input ────────────────────────

/// Compact data the layout builders read from. Lifting this off `App`
/// makes the builders pure functions, which lets us unit-test the
/// `PROTECTED` branch without driving the registry into
/// `Connection::Connected` (currently requires private test helpers).
#[derive(Clone)]
struct PanelState {
    inner_width: u16,
    /// Always-true for `build_protected_audit`; always-false for
    /// `build_exposed_audit`; data-dependent for `build_partial_audit`.
    show_section_headers: bool,

    // Identity
    /// Cached pre-VPN public IP (your ISP-visible address). Always
    /// shown in its own row when known so the user can see what
    /// they'd be exposed as if the VPN dropped — the masking question
    /// has two sides and the panel now surfaces both.
    real_ip: Option<String>,
    /// Currently-observed public IP. With a working VPN this equals
    /// the tunnel's exit IP; without (or with a leak) this equals
    /// `real_ip`.
    public_ip: String,
    location: Option<String>,
    ip_status: IpStatus,
    dns_server: String,
    dns_provider: Option<&'static str>,
    dns_leaking: bool,
    real_dns: Option<String>,

    // Defense
    killswitch_mode: KillSwitchMode,
    killswitch_state: KillSwitchState,
    encryption: String,

    // Footer
    last_check_secs: Option<u64>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum IpStatus {
    Masked,
    Leaking,
    Pending,
}

impl PanelState {
    fn show_headers(&self) -> bool {
        self.show_section_headers && self.inner_width >= SECTION_HEADER_MIN_INNER_WIDTH
    }
}

// ── Render entry point ──────────────────────────────────────────────────────

/// Top-level safety verdict — the answer to "how safe am I right now?".
/// Rendered as a prominent banner at the top of the panel: bold + colour
/// for `Protected` / `Partial`, bg-bar with black text for `Exposed`
/// (the eye-catcher because no VPN is the genuine alarm).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Protected,
    Partial,
    Exposed,
}

impl Verdict {
    fn banner(self) -> Line<'static> {
        match self {
            Self::Protected => Line::from(Span::styled(
                "  PROTECTED",
                Style::default()
                    .fg(theme::SUCCESS)
                    .add_modifier(Modifier::BOLD),
            )),
            Self::Partial => Line::from(Span::styled(
                "  PARTIAL",
                Style::default()
                    .fg(theme::WARNING)
                    .add_modifier(Modifier::BOLD),
            )),
            Self::Exposed => Line::from(Span::styled(
                " ⚠ EXPOSED ",
                Style::default()
                    .bg(theme::WARNING)
                    .fg(Color::Black)
                    .add_modifier(Modifier::BOLD),
            )),
        }
    }
}

#[allow(clippy::too_many_lines)]
pub(super) fn render(frame: &mut Frame, app: &App, area: Rect) {
    let is_focused = app.should_draw_focus(&crate::app::FocusedPanel::Security);
    let border_style = if is_focused {
        Style::default().fg(theme::BORDER_FOCUSED)
    } else {
        Style::default().fg(theme::BORDER_DEFAULT)
    };

    if app.effective_flipped(&crate::app::FocusedPanel::Security) {
        render_back(frame, app, area, border_style);
        return;
    }

    let primary_snap = app
        .registry
        .primary()
        .and_then(|id| app.registry.snapshot(id));
    let primary_connected = matches!(
        primary_snap.as_ref().map(|s| &s.state),
        Some(Connection::Connected { .. })
    );
    let any_tunnels = app.registry.tunnel_count() > 0;

    let verdict = if primary_connected {
        verdict_for_protected(app, primary_snap.as_ref())
    } else if any_tunnels {
        Verdict::Partial
    } else {
        Verdict::Exposed
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .padding(Padding::horizontal(1))
        .title(" Security Guard ");

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let body = match verdict {
        Verdict::Protected => {
            let state = collect_protected_state(app, primary_snap.as_ref(), inner.width);
            build_protected_audit(&state)
        }
        Verdict::Partial => {
            let state = collect_partial_state(app, primary_snap.as_ref(), inner.width);
            build_partial_audit(&state)
        }
        Verdict::Exposed => build_exposed_audit(app, inner.width),
    };

    // Banner sits above body content with a single blank between for breath.
    let mut audit = Vec::with_capacity(body.len() + 2);
    audit.push(verdict.banner());
    audit.push(Line::from(""));
    audit.extend(body);

    let final_audit = compact_to_fit(audit, inner.height as usize);
    frame.render_widget(Paragraph::new(final_audit), inner);
}

/// Refines the headline verdict for the connected-primary case. Even with
/// a primary up, the panel demotes to `Partial` when IP/DNS posture is
/// degraded so the title doesn't claim full protection while a row is red.
fn verdict_for_protected(app: &App, primary_snap: Option<&TunnelSnapshot>) -> Verdict {
    let ip_leaking = matches!(&app.runtime.real_ip, Some(real) if &app.runtime.public_ip == real);
    let dns_leaking =
        matches!(&app.runtime.real_dns, Some(real) if &app.runtime.dns_server == real);
    let ks_alarm = matches!(
        (app.runtime.killswitch_mode, app.runtime.killswitch_state),
        (
            crate::state::KillSwitchMode::Auto,
            crate::state::KillSwitchState::Blocking
        ) | (crate::state::KillSwitchMode::Off, _)
    );
    // Insecure cipher = effective wire plaintext. Demote to Partial so
    // the title doesn't claim full protection while crypto is broken.
    let cipher_insecure = matches!(
        classify_cipher(&derive_encryption(primary_snap)),
        CipherStrength::Insecure
    );

    if ip_leaking || dns_leaking || ks_alarm || cipher_insecure {
        Verdict::Partial
    } else {
        Verdict::Protected
    }
}

/// Drop blank lines first, then truncate. Same shape as the prior
/// implementation — preserves headline + status rows on tight terminals.
/// In the new layout the audit list is sized to fit at 80×24, so this is
/// the safety net for smaller-than-baseline windows, not the default path.
fn compact_to_fit(audit: Vec<Line<'static>>, available_height: usize) -> Vec<Line<'static>> {
    if available_height == 0 || audit.len() <= available_height {
        return audit;
    }
    let mut compacted = Vec::with_capacity(available_height);
    for line in audit {
        let is_blank =
            line.spans.is_empty() || line.spans.iter().all(|s| s.content.trim().is_empty());
        if is_blank && compacted.len() + 1 == available_height {
            // never let a blank be the last visible line
            continue;
        }
        compacted.push(line);
        if compacted.len() == available_height {
            break;
        }
    }
    compacted
}

// ── State collection ────────────────────────────────────────────────────────

fn collect_protected_state(
    app: &App,
    primary_snap: Option<&TunnelSnapshot>,
    inner_width: u16,
) -> PanelState {
    let ip_status = match &app.runtime.real_ip {
        Some(real)
            if !app.runtime.public_ip.is_empty()
                && app.runtime.public_ip != constants::MSG_DETECTING
                && app.runtime.public_ip != constants::MSG_FETCHING
                && !app.runtime.public_ip.starts_with("Error") =>
        {
            if &app.runtime.public_ip == real {
                IpStatus::Leaking
            } else {
                IpStatus::Masked
            }
        }
        _ => IpStatus::Pending,
    };

    let dns_leaking = match &app.runtime.real_dns {
        Some(real_dns) => &app.runtime.dns_server == real_dns,
        None => false,
    };

    let dns_provider = dns_provider_label(&app.runtime.dns_server);

    let encryption = derive_encryption(primary_snap);

    let location = if app.runtime.location.is_empty()
        || app.runtime.location == constants::MSG_DETECTING
        || app.runtime.location == constants::MSG_FETCHING
    {
        None
    } else {
        Some(app.runtime.location.clone())
    };

    PanelState {
        inner_width,
        show_section_headers: true,
        real_ip: app.runtime.real_ip.clone(),
        public_ip: app.runtime.public_ip.clone(),
        location,
        ip_status,
        dns_server: app.runtime.dns_server.clone(),
        dns_provider,
        dns_leaking,
        real_dns: app.runtime.real_dns.clone(),
        killswitch_mode: app.runtime.killswitch_mode,
        killswitch_state: app.runtime.killswitch_state,
        encryption,
        last_check_secs: app
            .runtime
            .last_security_check
            .map(|t| t.elapsed().as_secs()),
    }
}

fn collect_partial_state(
    app: &App,
    primary_snap: Option<&TunnelSnapshot>,
    inner_width: u16,
) -> PanelState {
    // Cipher source: prefer the primary (when verdict is Partial because
    // of degraded defense), otherwise pick the first Connected tunnel
    // from the registry (split-only topology). Ciphers are usually
    // homogeneous in practice (all WG or all OpenVPN); if they diverge,
    // surfacing the first one is still strictly more useful than `N/A`.
    let snapshots = app.registry.snapshot_all();
    let encryption = if let Some(snap) = primary_snap {
        derive_encryption(Some(snap))
    } else {
        snapshots
            .iter()
            .find(|s| matches!(s.state, Connection::Connected { .. }))
            .map_or_else(|| "N/A".to_string(), |s| derive_encryption(Some(s)))
    };

    // When a primary IS present (Partial fired from a degraded-defense
    // signal — killswitch off, weak cipher, IP/DNS leak), the IP row
    // should reflect the real exit IP, just like Protected does. Only
    // when no primary owns the default route does "split-route — no
    // exit" become the truthful rendering.
    let has_primary = primary_snap.is_some();
    let (public_ip, location, ip_status, dns_leaking, real_dns) = if has_primary {
        let ip_status = match &app.runtime.real_ip {
            Some(real)
                if !app.runtime.public_ip.is_empty()
                    && app.runtime.public_ip != constants::MSG_DETECTING
                    && app.runtime.public_ip != constants::MSG_FETCHING
                    && !app.runtime.public_ip.starts_with("Error") =>
            {
                if &app.runtime.public_ip == real {
                    IpStatus::Leaking
                } else {
                    IpStatus::Masked
                }
            }
            _ => IpStatus::Pending,
        };
        let dns_leaking = matches!(&app.runtime.real_dns, Some(r) if &app.runtime.dns_server == r);
        let location = if app.runtime.location.is_empty()
            || app.runtime.location == constants::MSG_DETECTING
            || app.runtime.location == constants::MSG_FETCHING
        {
            None
        } else {
            Some(app.runtime.location.clone())
        };
        (
            app.runtime.public_ip.clone(),
            location,
            ip_status,
            dns_leaking,
            app.runtime.real_dns.clone(),
        )
    } else {
        // No primary — IP row will render "split-route — no exit"
        // (the build_partial_audit branch keys off public_ip being empty).
        (String::new(), None, IpStatus::Pending, false, None)
    };

    PanelState {
        inner_width,
        show_section_headers: true,
        real_ip: app.runtime.real_ip.clone(),
        public_ip,
        location,
        ip_status,
        dns_server: app.runtime.dns_server.clone(),
        dns_provider: dns_provider_label(&app.runtime.dns_server),
        dns_leaking,
        real_dns,
        killswitch_mode: app.runtime.killswitch_mode,
        killswitch_state: app.runtime.killswitch_state,
        encryption,
        last_check_secs: app
            .runtime
            .last_security_check
            .map(|t| t.elapsed().as_secs()),
    }
}

/// Pull the active cipher name out of the primary tunnel snapshot.
/// `WireGuard` always uses `ChaCha20-Poly1305` by spec; `OpenVPN` reports
/// its cipher in `details.latest_handshake` prefixed with `Cipher:` (an
/// existing convention from the `OpenVPN` parser). Returns `"N/A"` when
/// no primary is connected — callers should treat unrecognised strings
/// the same as `classify_cipher` would (downgrades unknown to
/// `Deprecated`).
fn derive_encryption(primary_snap: Option<&TunnelSnapshot>) -> String {
    match primary_snap.map(|s| &s.state) {
        Some(Connection::Connected { details, .. }) => {
            if details.public_key == "OpenVPN" || details.public_key.is_empty() {
                if details.latest_handshake.starts_with("Cipher:") {
                    details.latest_handshake.replace("Cipher: ", "")
                } else {
                    "AES-256-GCM".to_string()
                }
            } else {
                "ChaCha20-Poly1305".to_string()
            }
        }
        _ => "N/A".to_string(),
    }
}

fn dns_provider_label(dns_server: &str) -> Option<&'static str> {
    if dns_server.contains("1.1.1.1") {
        Some("Cloudflare")
    } else if dns_server.contains("8.8.8.8") || dns_server.contains("8.8.4.4") {
        Some("Google")
    } else if dns_server.contains("9.9.9.9") {
        Some("Quad9")
    } else {
        None
    }
}

// ── Builders (pure) ─────────────────────────────────────────────────────────

fn build_protected_audit(s: &PanelState) -> Vec<Line<'static>> {
    let mut lines = Vec::with_capacity(20);
    let w = s.inner_width as usize;
    let show_headers = s.show_headers();

    if show_headers {
        lines.push(section_header("Identity"));
    }

    // Real IP row — your cached pre-VPN IP. Always informational (no
    // safety verdict on this row — the Exit IP row carries the verdict).
    // Detection-pending lands on `─`; known value shows muted-OK.
    let (real_ip_value, real_ip_sigil, real_ip_color) = match s.real_ip.as_deref() {
        Some(ip) if !ip.is_empty() => (ip.to_string(), Sigil::OkMuted, theme::TEXT_PRIMARY),
        _ => (
            "detecting…".to_string(),
            Sigil::NotApplicable,
            theme::INACTIVE,
        ),
    };
    lines.push(audit_row(
        "Real IP",
        &real_ip_value,
        real_ip_color,
        real_ip_sigil,
        w,
    ));

    // Exit IP row — what the world sees right now. Carries the
    // masking verdict: ✓ when it differs from Real IP (mask works),
    // ✗ when it matches (leak), pending while detecting.
    let (exit_sigil, exit_color) = match s.ip_status {
        IpStatus::Masked => (Sigil::OkMuted, theme::TEXT_PRIMARY),
        IpStatus::Leaking => (Sigil::AlarmError, theme::ERROR),
        IpStatus::Pending => (Sigil::NotApplicable, theme::WARNING),
    };
    lines.push(audit_row(
        "Exit IP",
        &s.public_ip,
        exit_color,
        exit_sigil,
        w,
    ));
    if s.ip_status == IpStatus::Leaking {
        lines.push(alarm_subline("real IP exposed", w));
    }

    // Location row — geo of Exit IP. Informational sanity check
    // (connected a DE server, should say DE).
    let (loc_value, loc_sigil, loc_color) = match s.location.as_deref() {
        Some(loc) if !loc.is_empty() => (loc.to_string(), Sigil::OkMuted, theme::TEXT_PRIMARY),
        _ => (
            "detecting…".to_string(),
            Sigil::NotApplicable,
            theme::INACTIVE,
        ),
    };
    lines.push(audit_row("Location", &loc_value, loc_color, loc_sigil, w));

    // DNS row — provider tag still inlines (Cloudflare/Google/Quad9)
    // since DNS doesn't have a separate "Provider" row to graduate to.
    let dns_value = format_value_with_tag(&s.dns_server, s.dns_provider);
    let (dns_sigil, dns_color) = if s.dns_leaking {
        (Sigil::AlarmError, theme::ERROR)
    } else {
        (Sigil::OkMuted, theme::TEXT_PRIMARY)
    };
    lines.push(audit_row("DNS", &dns_value, dns_color, dns_sigil, w));
    if s.dns_leaking {
        let why = match &s.real_dns {
            Some(_) => "leaking — matches pre-VPN resolver",
            None => "leaking — see status",
        };
        lines.push(alarm_subline(why, w));
    }

    lines.push(Line::from(""));

    if show_headers {
        lines.push(section_header("Defense"));
    }

    // Killswitch row
    let (ks_sigil, ks_color, ks_subline) =
        killswitch_visuals(s.killswitch_mode, s.killswitch_state);
    let ks_value = killswitch_value(s.killswitch_mode, s.killswitch_state);
    lines.push(audit_row("Killswitch", &ks_value, ks_color, ks_sigil, w));
    if let Some(why) = ks_subline {
        lines.push(alarm_subline(why, w));
    }

    // Encryption row — annotates the cipher with its security grade.
    // Modern AEAD / strong stay muted; deprecated / insecure pull the
    // eye and get an alarm sub-line so the user knows what to do.
    let cipher_strength = classify_cipher(&s.encryption);
    let encryption_value = format!("{} · {}", s.encryption, cipher_strength.label());
    lines.push(audit_row(
        "Encryption",
        &encryption_value,
        cipher_strength.value_color(),
        cipher_strength.sigil(),
        w,
    ));
    if let Some(why) = cipher_strength.alarm_subline() {
        lines.push(alarm_subline(why, w));
    }

    // IPv6 row — always `─` (v4-only killswitch on every supported platform)
    lines.push(audit_row(
        "IPv6",
        "v4-only",
        theme::INACTIVE,
        Sigil::NotApplicable,
        w,
    ));

    lines.push(Line::from(""));
    lines.push(footer_line(s.last_check_secs));

    lines
}

fn build_partial_audit(s: &PanelState) -> Vec<Line<'static>> {
    let mut lines = Vec::with_capacity(16);
    let w = s.inner_width as usize;
    let show_headers = s.show_headers();

    if show_headers {
        lines.push(section_header("Identity"));
    }

    // Real IP row — same as Protected: always informational. Carries
    // no verdict; just surfaces what you'd be exposed as if the VPN
    // went down.
    let (real_ip_value, real_ip_sigil, real_ip_color) = match s.real_ip.as_deref() {
        Some(ip) if !ip.is_empty() => (ip.to_string(), Sigil::OkMuted, theme::TEXT_PRIMARY),
        _ => (
            "detecting…".to_string(),
            Sigil::NotApplicable,
            theme::INACTIVE,
        ),
    };
    lines.push(audit_row(
        "Real IP",
        &real_ip_value,
        real_ip_color,
        real_ip_sigil,
        w,
    ));

    // Exit IP row: when a primary owns the default route (Partial
    // fired from a degraded-defense signal like killswitch=off),
    // render the real exit IP the same way Protected does. When no
    // primary owns the default route (split-only topology), flag the
    // row as not-applicable with the `split-route — no exit`
    // placeholder. `public_ip` being empty is the in-band signal for
    // the no-primary case (set by `collect_partial_state`).
    if s.public_ip.is_empty() {
        lines.push(audit_row(
            "Exit IP",
            "split-route — no exit",
            theme::INACTIVE,
            Sigil::NotApplicable,
            w,
        ));
    } else {
        let (exit_sigil, exit_color) = match s.ip_status {
            IpStatus::Masked => (Sigil::OkMuted, theme::TEXT_PRIMARY),
            IpStatus::Leaking => (Sigil::AlarmError, theme::ERROR),
            IpStatus::Pending => (Sigil::NotApplicable, theme::WARNING),
        };
        lines.push(audit_row(
            "Exit IP",
            &s.public_ip,
            exit_color,
            exit_sigil,
            w,
        ));
        if s.ip_status == IpStatus::Leaking {
            lines.push(alarm_subline("real IP exposed", w));
        }
    }

    // Location row — geo of Exit IP when known; n-a placeholder
    // otherwise (the split-only branch and the pending case).
    let (loc_value, loc_sigil, loc_color) = match s.location.as_deref() {
        Some(loc) if !loc.is_empty() => (loc.to_string(), Sigil::OkMuted, theme::TEXT_PRIMARY),
        _ => (
            "detecting…".to_string(),
            Sigil::NotApplicable,
            theme::INACTIVE,
        ),
    };
    lines.push(audit_row("Location", &loc_value, loc_color, loc_sigil, w));

    let dns_value = format_value_with_tag(&s.dns_server, s.dns_provider);
    lines.push(audit_row(
        "DNS",
        &dns_value,
        theme::TEXT_PRIMARY,
        Sigil::OkMuted,
        w,
    ));

    lines.push(Line::from(""));

    if show_headers {
        lines.push(section_header("Defense"));
    }

    let (ks_sigil, ks_color, ks_subline) =
        killswitch_visuals(s.killswitch_mode, s.killswitch_state);
    let ks_value = killswitch_value(s.killswitch_mode, s.killswitch_state);
    lines.push(audit_row("Killswitch", &ks_value, ks_color, ks_sigil, w));
    if let Some(why) = ks_subline {
        lines.push(alarm_subline(why, w));
    }

    // Encryption row — sourced from a representative active tunnel.
    // Only render when we have a real cipher (skip the `N/A` case where
    // no tunnel was Connected at scan time — the Killswitch row already
    // carries the relevant alarm in that situation).
    if s.encryption != "N/A" {
        let cipher_strength = classify_cipher(&s.encryption);
        let encryption_value = format!("{} · {}", s.encryption, cipher_strength.label());
        lines.push(audit_row(
            "Encryption",
            &encryption_value,
            cipher_strength.value_color(),
            cipher_strength.sigil(),
            w,
        ));
        if let Some(why) = cipher_strength.alarm_subline() {
            lines.push(alarm_subline(why, w));
        }
    }

    lines.push(audit_row(
        "IPv6",
        "v4-only",
        theme::INACTIVE,
        Sigil::NotApplicable,
        w,
    ));

    lines.push(Line::from(""));
    lines.push(footer_line(s.last_check_secs));

    lines
}

fn build_exposed_audit(app: &App, inner_width: u16) -> Vec<Line<'static>> {
    let mut lines = Vec::with_capacity(14);
    let w = inner_width as usize;

    // In EXPOSED both Real IP and Exit IP resolve to the same value
    // (no tunnel masking anything). Showing both rows side-by-side
    // with the same IP IS the alarm visualization: "your exit IP IS
    // your real IP".
    let exposed_ip = if app.runtime.public_ip.is_empty()
        || app.runtime.public_ip == constants::MSG_DETECTING
        || app.runtime.public_ip == constants::MSG_FETCHING
    {
        "checking…".to_string()
    } else {
        app.runtime.public_ip.clone()
    };

    // Real IP row — informational, muted-OK (we know what it is).
    lines.push(audit_row(
        "Real IP",
        &exposed_ip,
        theme::TEXT_PRIMARY,
        Sigil::OkMuted,
        w,
    ));
    // Exit IP row — same value, carries the alarm.
    lines.push(audit_row(
        "Exit IP",
        &exposed_ip,
        theme::WARNING,
        Sigil::AlarmWarn,
        w,
    ));
    lines.push(alarm_subline("no VPN — your real IP is visible", w));

    // Location of Exit IP — informational sanity check.
    let location = if app.runtime.location.is_empty()
        || app.runtime.location == constants::MSG_DETECTING
        || app.runtime.location == constants::MSG_FETCHING
    {
        "detecting…".to_string()
    } else {
        app.runtime.location.clone()
    };
    let loc_sigil = if location == "detecting…" {
        Sigil::NotApplicable
    } else {
        Sigil::OkMuted
    };
    let loc_color = if location == "detecting…" {
        theme::INACTIVE
    } else {
        theme::TEXT_PRIMARY
    };
    lines.push(audit_row("Location", &location, loc_color, loc_sigil, w));

    // DNS row — your ISP's DNS (no VPN to leak from, so no leak check).
    let dns_value = format_value_with_tag(
        &app.runtime.dns_server,
        dns_provider_label(&app.runtime.dns_server),
    );
    lines.push(audit_row(
        "DNS",
        &dns_value,
        theme::TEXT_PRIMARY,
        Sigil::OkMuted,
        w,
    ));

    lines.push(Line::from(""));

    lines.push(audit_row(
        "Killswitch",
        killswitch_mode_label(app.runtime.killswitch_mode),
        match app.runtime.killswitch_mode {
            KillSwitchMode::Off => theme::ERROR,
            _ => theme::TEXT_PRIMARY,
        },
        match app.runtime.killswitch_mode {
            KillSwitchMode::Off => Sigil::AlarmError,
            _ => Sigil::OkMuted,
        },
        w,
    ));
    lines.push(audit_row(
        "IPv6",
        "v4-only",
        theme::INACTIVE,
        Sigil::NotApplicable,
        w,
    ));

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Connect to a profile to protect this traffic.",
        Style::default().fg(theme::TEXT_SECONDARY),
    )));

    lines
}

// ── Killswitch row helpers ──────────────────────────────────────────────────

fn killswitch_mode_label(mode: KillSwitchMode) -> &'static str {
    mode.display_name()
}

fn killswitch_value(mode: KillSwitchMode, state: KillSwitchState) -> String {
    // Auto + Blocking is the alarm state — value names the situation,
    // not the mode label. The mode is implied by the rest of the panel.
    if matches!(
        (mode, state),
        (KillSwitchMode::Auto, KillSwitchState::Blocking)
    ) {
        "VPN dropped".to_string()
    } else {
        mode.display_name().to_string()
    }
}

/// Returns `(sigil, value_color, optional_subline)` for the Killswitch row.
fn killswitch_visuals(
    mode: KillSwitchMode,
    state: KillSwitchState,
) -> (Sigil, Color, Option<&'static str>) {
    use KillSwitchMode::{AlwaysOn, Auto, Off};
    use KillSwitchState::Blocking;
    match (mode, state) {
        (Off, _) => (
            Sigil::AlarmError,
            theme::ERROR,
            Some("off — not protecting"),
        ),
        (Auto, Blocking) => (
            Sigil::AlarmWarn,
            theme::WARNING,
            Some("press r to reconnect"),
        ),
        (AlwaysOn | Auto, _) => (Sigil::OkMuted, theme::TEXT_PRIMARY, None),
    }
}

/// `value · tag` when `tag` is present, otherwise just `value`. Used for
/// inlining a provider name with a DNS server, or a country/city with an IP.
fn format_value_with_tag(value: &str, tag: Option<&str>) -> String {
    match tag {
        Some(t) if !t.is_empty() => format!("{value} · {t}"),
        _ => value.to_string(),
    }
}

// ── Flip-side view (unchanged — placeholder for issue #168) ────────────────

fn render_back(frame: &mut Frame, app: &App, area: Rect, border_style: Style) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .padding(Padding::horizontal(1))
        .title(constants::TITLE_FLIP_CONNECTIONS_AUDIT)
        .title_bottom(
            Line::from(Span::styled(
                constants::FLIP_BACK_HINT,
                Style::default().fg(theme::KEY_HINT_DESC),
            ))
            .right_aligned(),
        );

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let is_connected = app.registry.primary().is_some();

    let text = if is_connected {
        vec![
            Line::from(Span::styled(
                "Active Connections Audit",
                Style::default()
                    .fg(theme::ACCENT_PRIMARY)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "  Per-socket VPN routing verification",
                Style::default().fg(theme::TEXT_SECONDARY),
            )),
            Line::from(Span::styled(
                "  will be available in a future release.",
                Style::default().fg(theme::TEXT_SECONDARY),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "  This view will show which connections",
                Style::default().fg(theme::TEXT_SECONDARY),
            )),
            Line::from(Span::styled(
                "  are routed through the VPN tunnel vs",
                Style::default().fg(theme::TEXT_SECONDARY),
            )),
            Line::from(Span::styled(
                "  bypassing it (split-tunnel detection).",
                Style::default().fg(theme::TEXT_SECONDARY),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "  See: github.com/Harry-kp/vortix/issues/168",
                Style::default().fg(theme::NORD_POLAR_NIGHT_4),
            )),
        ]
    } else {
        vec![
            Line::from(Span::styled(
                "Active Connections Audit",
                Style::default()
                    .fg(theme::INACTIVE)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "  Connect to a VPN to see",
                Style::default().fg(theme::TEXT_SECONDARY),
            )),
            Line::from(Span::styled(
                "  connection routing details.",
                Style::default().fg(theme::TEXT_SECONDARY),
            )),
        ]
    };

    let max_lines = inner.height as usize;
    let mut text = text;
    text.truncate(max_lines);
    frame.render_widget(Paragraph::new(text), inner);
}

#[cfg(test)]
mod tests {
    //! The polish redesign keeps the existing `TestBackend`-based pattern
    //! for `PARTIAL` and `EXPOSED` (the branches reachable from
    //! `App::new_test()`) and adds pure-function tests against
    //! `build_protected_audit` for the `PROTECTED` branch (which still
    //! can't be driven into `Connection::Connected` without private
    //! registry test helpers).
    use super::*;
    use crate::app::App;
    use crate::state::KillSwitchMode;
    use crate::vortix_core::engine::Engine;
    use crate::vortix_core::profile::ProfileId;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn insert_idle_tunnel(app: &mut App, name: &str) {
        let tunnel = crate::tunnel::TunnelKind::Mock(
            crate::vortix_core::ports::tunnel::mock::MockTunnel::new(),
        );
        let engine = Engine::new(tunnel, |_| None);
        app.registry.insert(ProfileId::new(name), engine, vec![]);
    }

    fn render_to_string(app: &App, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("terminal");
        terminal
            .draw(|frame| {
                let area = Rect::new(0, 0, width, height);
                render(frame, app, area);
            })
            .expect("draw");
        let buf = terminal.backend().buffer().clone();
        let mut out = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    fn line_text(line: &Line<'static>) -> String {
        line.spans.iter().map(|s| s.content.as_ref()).collect()
    }

    fn baseline_protected_state(inner_width: u16) -> PanelState {
        PanelState {
            inner_width,
            show_section_headers: true,
            real_ip: Some("203.0.113.5".to_string()),
            public_ip: "1.2.3.4".to_string(),
            location: Some("US-East".to_string()),
            ip_status: IpStatus::Masked,
            dns_server: "1.1.1.1".to_string(),
            dns_provider: Some("Cloudflare"),
            dns_leaking: false,
            real_dns: None,
            killswitch_mode: KillSwitchMode::AlwaysOn,
            killswitch_state: KillSwitchState::Blocking,
            encryption: "ChaCha20-Poly1305".to_string(),
            last_check_secs: Some(3),
        }
    }

    // ── Cipher strength classification ────────────────────────────────────

    #[test]
    fn classify_cipher_modern_aead() {
        for name in [
            "ChaCha20-Poly1305",
            "chacha20-poly1305",
            "AES-256-GCM",
            "AES-128-GCM",
            "AES-192-GCM",
            "XChaCha20-Poly1305",
        ] {
            assert_eq!(
                classify_cipher(name),
                CipherStrength::Modern,
                "{name} should be Modern"
            );
        }
    }

    #[test]
    fn classify_cipher_strong_non_aead() {
        for name in ["AES-256-CBC", "AES-256-CTR", "AES-192-CBC"] {
            assert_eq!(
                classify_cipher(name),
                CipherStrength::Strong,
                "{name} should be Strong"
            );
        }
    }

    #[test]
    fn classify_cipher_deprecated() {
        for name in ["3DES-CBC", "DES-EDE3-CBC", "AES-128-CBC"] {
            assert_eq!(
                classify_cipher(name),
                CipherStrength::Deprecated,
                "{name} should be Deprecated"
            );
        }
    }

    #[test]
    fn classify_cipher_insecure() {
        for name in [
            "BF-CBC",
            "blowfish-cbc",
            "DES-CBC",
            "DES",
            "RC4",
            "RC2-CBC",
            "NULL",
            "CAST5-CBC",
            "IDEA-CBC",
        ] {
            assert_eq!(
                classify_cipher(name),
                CipherStrength::Insecure,
                "{name} should be Insecure"
            );
        }
    }

    #[test]
    fn classify_cipher_unknown_is_cautiously_deprecated() {
        // Unknown ciphers must NOT be labelled Modern — that would
        // green-light a string we've never seen.
        assert_eq!(
            classify_cipher("MysteryCipher-256"),
            CipherStrength::Deprecated
        );
        assert_eq!(classify_cipher("N/A"), CipherStrength::Deprecated);
    }

    #[test]
    fn classify_cipher_does_not_misread_3des_as_single_des() {
        // Order-of-checks regression: `3DES-CBC` contains `DES-CBC` as a
        // substring; the single-DES rule must skip it via the `!3DES`
        // guard so it lands in Deprecated, not Insecure.
        assert_eq!(classify_cipher("3DES-CBC"), CipherStrength::Deprecated);
        assert_eq!(classify_cipher("DES-EDE3-CBC"), CipherStrength::Deprecated);
    }

    // ── Encryption row rendering driven by cipher strength ────────────────

    #[test]
    fn protected_encryption_modern_cipher_is_muted_with_strength_inline() {
        let s = baseline_protected_state(48);
        let lines = build_protected_audit(&s);
        let enc_idx = lines
            .iter()
            .position(|l| line_text(l).starts_with("Encryption"))
            .expect("Encryption row missing");
        let text = line_text(&lines[enc_idx]);
        assert!(
            text.contains("modern AEAD"),
            "modern cipher must surface strength label, got {text:?}"
        );
        let sigil = lines[enc_idx].spans.last().unwrap();
        assert!(sigil.content.trim_end() == "✓");
        assert!(!sigil.style.add_modifier.contains(Modifier::BOLD));
        // No alarm sub-line follows a modern cipher.
        let next_text = line_text(&lines[enc_idx + 1]);
        assert!(
            !next_text.contains("AES-GCM") && !next_text.contains("broken"),
            "modern cipher must not have an alarm sub-line, got {next_text:?}"
        );
    }

    #[test]
    fn protected_encryption_insecure_cipher_alarms_with_subline() {
        let mut s = baseline_protected_state(60);
        s.encryption = "BF-CBC".to_string();
        let lines = build_protected_audit(&s);
        let enc_idx = lines
            .iter()
            .position(|l| line_text(l).starts_with("Encryption"))
            .expect("Encryption row missing");
        let text = line_text(&lines[enc_idx]);
        assert!(
            text.contains("INSECURE"),
            "insecure cipher must say INSECURE, got {text:?}"
        );
        let sigil = lines[enc_idx].spans.last().unwrap();
        assert!(sigil.content.trim_end() == "✗");
        assert!(sigil.style.add_modifier.contains(Modifier::BOLD));
        let sub_text = line_text(&lines[enc_idx + 1]);
        assert!(
            sub_text.contains("broken cipher"),
            "alarm sub-line missing for insecure cipher, got {sub_text:?}"
        );
    }

    #[test]
    fn protected_encryption_deprecated_cipher_warns_with_subline() {
        let mut s = baseline_protected_state(60);
        s.encryption = "AES-128-CBC".to_string();
        let lines = build_protected_audit(&s);
        let enc_idx = lines
            .iter()
            .position(|l| line_text(l).starts_with("Encryption"))
            .expect("Encryption row missing");
        let text = line_text(&lines[enc_idx]);
        assert!(text.contains("deprecated"), "got {text:?}");
        let sigil = lines[enc_idx].spans.last().unwrap();
        assert!(sigil.content.trim_end() == "⚠");
        assert!(sigil.style.add_modifier.contains(Modifier::BOLD));
        let sub_text = line_text(&lines[enc_idx + 1]);
        assert!(
            sub_text.contains("upgrade to AES-GCM"),
            "deprecated cipher sub-line missing, got {sub_text:?}"
        );
    }

    // ── PROTECTED branch (pure-function tests against build_protected_audit) ──

    #[test]
    fn protected_renders_section_words_and_no_loud_banner() {
        // R3: section words `Identity` / `Defense` replace the bold
        // `PROTECTED` headline.
        let s = baseline_protected_state(34);
        let lines = build_protected_audit(&s);
        let all_text: String = lines.iter().map(line_text).collect::<Vec<_>>().join("\n");

        assert!(
            all_text.contains("Identity"),
            "section word `Identity` missing:\n{all_text}"
        );
        assert!(
            all_text.contains("Defense"),
            "section word `Defense` missing:\n{all_text}"
        );
        assert!(
            !all_text.contains("PROTECTED"),
            "loud `PROTECTED` banner must be removed:\n{all_text}"
        );
    }

    #[test]
    fn protected_sigils_render_in_right_column() {
        // R2: every row ends in the right-pinned sigil column.
        let s = baseline_protected_state(40);
        let lines = build_protected_audit(&s);
        let exit_line = lines
            .iter()
            .find(|l| line_text(l).starts_with("Exit IP"))
            .expect("Exit IP row missing");
        let dns_line = lines
            .iter()
            .find(|l| line_text(l).starts_with("DNS"))
            .expect("DNS row missing");

        for row in [exit_line, dns_line] {
            let last_span = row.spans.last().expect("non-empty row");
            assert!(
                last_span.content.trim_end() == "✓",
                "sigil must be last span on row (got {:?}):\n{row:?}",
                last_span.content
            );
        }
    }

    #[test]
    fn protected_all_ok_state_has_no_bold_modifiers() {
        // R7: in the all-OK state every sigil renders muted (no BOLD).
        let s = baseline_protected_state(34);
        let lines = build_protected_audit(&s);
        for line in &lines {
            for span in &line.spans {
                assert!(
                    !span.style.add_modifier.contains(Modifier::BOLD),
                    "all-OK state must not bold any span (offender: {:?})",
                    span.content
                );
            }
        }
    }

    #[test]
    fn protected_dns_leak_brightens_dns_sigil_and_adds_subline() {
        // R7 + R15 (AE2): a leaking DNS row goes bright `✗ ` and gets
        // exactly one sub-line below it. Other rows stay muted.
        let mut s = baseline_protected_state(40);
        s.dns_leaking = true;
        s.real_dns = Some("1.1.1.1".to_string());
        let lines = build_protected_audit(&s);

        let dns_idx = lines
            .iter()
            .position(|l| line_text(l).starts_with("DNS"))
            .expect("DNS row missing");
        let dns_sigil = lines[dns_idx].spans.last().expect("non-empty DNS row");
        assert!(
            dns_sigil.content.trim_end() == "✗",
            "leaking DNS sigil must be ✗ (got {:?})",
            dns_sigil.content
        );
        assert!(
            dns_sigil.style.add_modifier.contains(Modifier::BOLD),
            "leaking DNS sigil must be BOLD"
        );

        let subline_text = line_text(&lines[dns_idx + 1]);
        assert!(
            subline_text.contains("leaking"),
            "leaking DNS must render an alarm sub-line (got {subline_text:?})"
        );

        // Exit IP row stays calm.
        let ip_idx = lines
            .iter()
            .position(|l| line_text(l).starts_with("Exit IP"))
            .expect("Exit IP row missing");
        for span in &lines[ip_idx].spans {
            assert!(
                !span.style.add_modifier.contains(Modifier::BOLD),
                "Exit IP row must stay muted while DNS alarms: {:?}",
                span.content
            );
        }
    }

    #[test]
    fn protected_killswitch_auto_blocking_is_loud_with_subline() {
        // R15 (AE3): Auto + Blocking is the alarm state — bright sigil
        // and a "press r to reconnect" sub-line.
        let mut s = baseline_protected_state(40);
        s.killswitch_mode = KillSwitchMode::Auto;
        s.killswitch_state = KillSwitchState::Blocking;
        let lines = build_protected_audit(&s);

        let ks_idx = lines
            .iter()
            .position(|l| line_text(l).starts_with("Killswitch"))
            .expect("Killswitch row missing");
        let ks_row_text = line_text(&lines[ks_idx]);
        assert!(
            ks_row_text.contains("VPN dropped"),
            "Auto+Blocking value must say `VPN dropped`, got {ks_row_text:?}"
        );
        let ks_sigil = lines[ks_idx].spans.last().expect("non-empty row");
        assert!(ks_sigil.content.trim_end() == "⚠");
        assert!(ks_sigil.style.add_modifier.contains(Modifier::BOLD));

        let sub_text = line_text(&lines[ks_idx + 1]);
        assert!(
            sub_text.contains("press r to reconnect"),
            "alarm sub-line missing: {sub_text:?}"
        );
    }

    #[test]
    fn protected_ipv6_is_not_applicable_not_a_warning() {
        // R10: IPv6 uses ─ (not ⚠) and value reads `v4-only`. The previous
        // explainer string is removed.
        let s = baseline_protected_state(34);
        let lines = build_protected_audit(&s);
        let ipv6 = lines
            .iter()
            .find(|l| line_text(l).starts_with("IPv6"))
            .expect("IPv6 row missing");
        let text = line_text(ipv6);
        assert!(text.contains("v4-only"), "IPv6 value got {text:?}");
        let sigil = ipv6.spans.last().expect("non-empty row");
        assert!(
            sigil.content.trim_end() == "─",
            "IPv6 sigil must be ─, got {:?}",
            sigil.content
        );
    }

    #[test]
    fn protected_dns_provider_inlines_without_subbullet() {
        // R12: provider collapses inline as `1.1.1.1 · Cloudflare`.
        // No `Provider:` sub-row.
        let s = baseline_protected_state(40);
        let lines = build_protected_audit(&s);
        let all_text: String = lines.iter().map(line_text).collect::<Vec<_>>().join("\n");
        assert!(
            all_text.contains("1.1.1.1 · Cloudflare"),
            "DNS provider must inline: {all_text}"
        );
        assert!(
            !all_text.contains("Provider:"),
            "no `Provider:` sub-bullet allowed: {all_text}"
        );
    }

    #[test]
    fn protected_renders_real_ip_and_exit_ip_as_separate_rows() {
        // The split-row redesign: Real IP (your ISP-visible IP) lives
        // in its own row alongside Exit IP (the world-visible IP).
        // Both must appear in the Protected branch with different
        // values when masking works.
        let s = baseline_protected_state(40);
        let lines = build_protected_audit(&s);
        let all_text: String = lines.iter().map(line_text).collect::<Vec<_>>().join("\n");
        assert!(
            all_text.contains("Real IP") && all_text.contains("203.0.113.5"),
            "Real IP row must render with cached real IP: {all_text}"
        );
        assert!(
            all_text.contains("Exit IP") && all_text.contains("1.2.3.4"),
            "Exit IP row must render with current public IP: {all_text}"
        );
    }

    #[test]
    fn protected_location_has_its_own_row_not_inlined_with_exit_ip() {
        // Location lives in its own row now — the Exit IP row should
        // NOT inline location with `·` separator any more.
        let s = baseline_protected_state(50);
        let lines = build_protected_audit(&s);
        let exit_line_text = lines
            .iter()
            .map(line_text)
            .find(|t| t.starts_with("Exit IP"))
            .expect("Exit IP row missing");
        assert!(
            !exit_line_text.contains("·"),
            "Exit IP must not inline location with `·`: {exit_line_text:?}"
        );
        let loc_line_text = lines
            .iter()
            .map(line_text)
            .find(|t| t.starts_with("Location"))
            .expect("Location row missing");
        assert!(
            loc_line_text.contains("US-East"),
            "Location row must render the geo value: {loc_line_text:?}"
        );
    }

    #[test]
    fn protected_long_ks_phrase_removed_in_default_render() {
        // R9: long KS status phrase (the multi-clause "firewall engaged …
        // only VPN traffic permitted") must not render in the default
        // PROTECTED state. The mode label is enough; the phrase only
        // surfaces as an alarm sub-line.
        let s = baseline_protected_state(60);
        let lines = build_protected_audit(&s);
        let all_text: String = lines.iter().map(line_text).collect::<Vec<_>>().join("\n");
        assert!(
            !all_text.contains("only VPN traffic permitted"),
            "long KS phrase must not render in default state: {all_text}"
        );
        assert!(
            !all_text.contains("watching — will engage"),
            "long KS phrase must not render in default state: {all_text}"
        );
    }

    #[test]
    fn protected_footer_says_updated_not_last_checked() {
        // R18: `Updated 3s ago` (not `Last checked: 3s ago`).
        let s = baseline_protected_state(34);
        let lines = build_protected_audit(&s);
        let footer_text = line_text(lines.last().expect("footer"));
        assert!(
            footer_text.contains("Updated"),
            "footer must say `Updated`: {footer_text}"
        );
        assert!(
            !footer_text.contains("Last checked"),
            "old `Last checked` wording must be gone: {footer_text}"
        );
    }

    #[test]
    fn protected_section_headers_drop_below_width_threshold() {
        // R16: section words drop at panel widths < threshold.
        let mut s = baseline_protected_state(20);
        s.show_section_headers = true;
        let lines = build_protected_audit(&s);
        let all_text: String = lines.iter().map(line_text).collect::<Vec<_>>().join("\n");
        assert!(
            !all_text.contains("Identity"),
            "section words must drop at narrow widths: {all_text}"
        );
        assert!(
            !all_text.contains("Defense"),
            "section words must drop at narrow widths: {all_text}"
        );
        // Seven content rows still render (Real IP / Exit IP / Location
        // / DNS / Killswitch / Encryption / IPv6).
        for label in [
            "Real IP",
            "Exit IP",
            "Location",
            "DNS",
            "Killswitch",
            "Encryption",
            "IPv6",
        ] {
            assert!(
                all_text.contains(label),
                "row `{label}` missing at narrow width:\n{all_text}"
            );
        }
    }

    #[test]
    fn protected_no_legend_in_panel() {
        // R13: sigil legend lives in the help overlay, never in the panel.
        let s = baseline_protected_state(40);
        let lines = build_protected_audit(&s);
        let all_text: String = lines.iter().map(line_text).collect::<Vec<_>>().join("\n");
        assert!(
            !all_text.contains("Legend"),
            "panel must not render sigil legend: {all_text}"
        );
    }

    // ── PARTIAL branch (rendered) ───────────────────────────────────────────

    #[test]
    fn no_tunnels_renders_exposed_with_banner_and_polish() {
        let app = App::new_test();
        assert_eq!(app.registry.tunnel_count(), 0);

        let out = render_to_string(&app, 60, 20);
        // Loud EXPOSED banner is the eye-catcher when no VPN is up.
        assert!(
            out.contains("EXPOSED"),
            "EXPOSED banner must be present:\n{out}"
        );
        // Real IP + Exit IP rows present (same value in EXPOSED — that
        // IS the leak visualization) + alarm sub-line on Exit IP.
        assert!(out.contains("Real IP"), "Real IP row missing:\n{out}");
        assert!(out.contains("Exit IP"), "Exit IP row missing:\n{out}");
        assert!(
            out.contains("no VPN — your real IP is visible"),
            "EXPOSED alarm sub-line missing:\n{out}"
        );
        // No legend inside the panel — lives in `?` overlay now.
        assert!(
            !out.contains("Legend:"),
            "EXPOSED must not render the in-panel legend:\n{out}"
        );
    }

    #[test]
    fn partial_renders_banner_section_words_and_killswitch_row() {
        // The PARTIAL banner sits at the top; below it the `Identity` /
        // `Defense` section words and a single Killswitch row in the
        // right-column layout.
        let mut app = App::new_test();
        insert_idle_tunnel(&mut app, "alpha");
        app.runtime.killswitch_mode = KillSwitchMode::AlwaysOn;

        let out = render_to_string(&app, 60, 20);
        assert!(out.contains("PARTIAL"), "PARTIAL banner missing:\n{out}");
        assert!(out.contains("Identity"), "PARTIAL panel:\n{out}");
        assert!(out.contains("Defense"), "PARTIAL panel:\n{out}");
        assert!(out.contains("Killswitch"), "PARTIAL panel:\n{out}");
        assert!(out.contains("VPN-only"), "active mode label:\n{out}");
        assert!(!out.contains("Legend:"), "no in-panel legend:\n{out}");
    }

    #[test]
    fn partial_killswitch_off_renders_off_with_alarm() {
        let mut app = App::new_test();
        insert_idle_tunnel(&mut app, "alpha");
        app.runtime.killswitch_mode = KillSwitchMode::Off;

        let out = render_to_string(&app, 70, 20);
        assert!(
            out.contains("Off"),
            "Off mode value missing in PARTIAL:\n{out}"
        );
        assert!(
            out.contains("not protecting"),
            "Off alarm sub-line missing:\n{out}"
        );
    }

    #[test]
    fn partial_killswitch_auto_renders_block_on_drop() {
        let mut app = App::new_test();
        insert_idle_tunnel(&mut app, "alpha");
        app.runtime.killswitch_mode = KillSwitchMode::Auto;

        let out = render_to_string(&app, 70, 20);
        assert!(
            out.contains("Block on drop"),
            "Auto mode label missing:\n{out}"
        );
    }

    #[test]
    fn partial_with_primary_renders_real_ip_not_split_route_noexit() {
        // Regression for the "Role=Primary everywhere else but Security
        // Guard says split-route — no exit" bug. When PARTIAL fires from
        // a degraded-defense signal (e.g. killswitch=Off) but a primary
        // tunnel IS up and owning the default route, the IP row must
        // show the real exit IP, not the "no exit" placeholder.
        let mut state = baseline_protected_state(60);
        state.public_ip = "46.101.235.146".to_string();
        state.location = Some("Frankfurt am Main, DE".to_string());
        state.ip_status = IpStatus::Masked;
        state.killswitch_mode = KillSwitchMode::Off;
        state.killswitch_state = crate::state::KillSwitchState::Disabled;

        let lines = build_partial_audit(&state);
        let body: String = lines.iter().map(line_text).collect::<Vec<_>>().join("\n");

        assert!(
            body.contains("46.101.235.146"),
            "real exit IP missing in PARTIAL-with-primary IP row:\n{body}"
        );
        assert!(
            !body.contains("split-route"),
            "must not render `split-route — no exit` when a primary owns the route:\n{body}"
        );
    }

    #[test]
    fn partial_without_primary_keeps_split_route_no_exit_row() {
        // Mirror of the above: with no primary (public_ip empty), the IP
        // row remains the not-applicable placeholder so the panel
        // doesn't lie about an exit posture that doesn't exist.
        let mut state = baseline_protected_state(60);
        state.public_ip = String::new();
        state.location = None;
        state.ip_status = IpStatus::Pending;

        let lines = build_partial_audit(&state);
        let body: String = lines.iter().map(line_text).collect::<Vec<_>>().join("\n");

        assert!(
            body.contains("split-route"),
            "split-only PARTIAL must still show split-route — no exit:\n{body}"
        );
    }

    #[test]
    fn partial_ipv6_is_not_applicable() {
        let mut app = App::new_test();
        insert_idle_tunnel(&mut app, "alpha");
        app.runtime.ipv6_leak = false;

        let out = render_to_string(&app, 70, 20);
        assert!(out.contains("v4-only"), "IPv6 value missing:\n{out}");
        assert!(
            !out.contains("Not enforced"),
            "old IPv6 explainer must be gone:\n{out}"
        );
        // The `─` sigil renders in the right column for the IPv6 row.
        assert!(out.contains("─"), "IPv6 ─ sigil missing:\n{out}");
    }
}
