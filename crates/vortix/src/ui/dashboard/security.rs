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
/// `Real IPv4` / `Real IPv6` / `Exit IPv4` / `Exit IPv6` (9), and
/// the v4-only fallbacks `Real IP` / `Exit IP` (≤8).
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

    fn value_color(self) -> Color {
        crate::ui::sigils::sigil(self.id()).color
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

/// Value color is derived from the sigil so each row reads as one unit.
fn audit_row(label: &str, value: &str, sigil: Sigil, inner_width: usize) -> Line<'static> {
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
        Span::styled(value_truncated, Style::default().fg(sigil.value_color())),
        Span::raw(padding),
        Span::styled(sigil_col, sigil.style()),
    ])
}

fn push_dns_rows(lines: &mut Vec<Line<'static>>, s: &PanelState, w: usize) {
    use crate::core::dns_leak::DnsLeakStatus;
    let dns_value = format_value_with_tag(&s.dns_server, s.dns_provider);
    let sigil = match &s.dns_leak {
        DnsLeakStatus::Leaking { .. } => Sigil::AlarmError,
        DnsLeakStatus::ProbeFailed => Sigil::NotApplicable,
        DnsLeakStatus::Protected { .. } | DnsLeakStatus::Unknown => Sigil::OkMuted,
    };
    lines.push(audit_row("DNS", &dns_value, sigil, w));
    if let DnsLeakStatus::Leaking {
        recursor,
        configured,
    } = &s.dns_leak
    {
        let msg = format!("leaking — queries answered by {recursor}, not configured {configured}");
        lines.push(alarm_subline(&msg, w));
    }
}

fn has_v6_signal(s: &PanelState) -> bool {
    s.real_ipv6.is_some() || s.public_ipv6.is_some()
}

fn push_real_ip_rows(lines: &mut Vec<Line<'static>>, s: &PanelState, w: usize) {
    let v6 = has_v6_signal(s);
    let v4_label = if v6 { "Real IPv4" } else { "Real IP" };
    let (v4_value, v4_sigil) = match s.real_ip.as_deref() {
        Some(ip) if !ip.is_empty() => (ip.to_string(), Sigil::OkMuted),
        _ => ("detecting…".to_string(), Sigil::NotApplicable),
    };
    lines.push(audit_row(v4_label, &v4_value, v4_sigil, w));
    if v6 {
        let (v6_value, v6_sigil) = match s.real_ipv6.as_deref() {
            Some(ip) => (ip.to_string(), Sigil::OkMuted),
            None => ("checking…".to_string(), Sigil::NotApplicable),
        };
        lines.push(audit_row("Real IPv6", &v6_value, v6_sigil, w));
    }
}

fn push_exit_ip_rows(lines: &mut Vec<Line<'static>>, s: &PanelState, w: usize) {
    let v6 = has_v6_signal(s);
    let v4_label = if v6 { "Exit IPv4" } else { "Exit IP" };
    let v4_sigil = match s.ip_status {
        IpStatus::Masked => Sigil::OkMuted,
        IpStatus::Leaking => Sigil::AlarmError,
        IpStatus::Pending => Sigil::NotApplicable,
    };
    lines.push(audit_row(v4_label, &s.public_ip, v4_sigil, w));
    if s.ip_status == IpStatus::Leaking {
        lines.push(alarm_subline("real IPv4 exposed", w));
    }
    if v6 {
        push_exit_ipv6_row(lines, s, w);
    }
}

fn push_exit_ipv6_row(lines: &mut Vec<Line<'static>>, s: &PanelState, w: usize) {
    let (v6_value, v6_sigil, leak_subline) = match s.ipv6_status {
        Ipv6RowStatus::Masked => (
            s.public_ipv6.clone().unwrap_or_else(|| "checking…".into()),
            Sigil::OkMuted,
            false,
        ),
        Ipv6RowStatus::Leaking => (
            s.public_ipv6.clone().unwrap_or_default(),
            Sigil::AlarmError,
            true,
        ),
        Ipv6RowStatus::Pending | Ipv6RowStatus::Absent => (
            s.public_ipv6.clone().unwrap_or_else(|| "checking…".into()),
            Sigil::NotApplicable,
            false,
        ),
    };
    lines.push(audit_row("Exit IPv6", &v6_value, v6_sigil, w));
    if leak_subline {
        lines.push(alarm_subline("v6 exposed — matches real IPv6", w));
    }
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
    real_ip: Option<String>,
    public_ip: String,
    real_ipv6: Option<String>,
    public_ipv6: Option<String>,
    location: Option<String>,
    ip_status: IpStatus,
    ipv6_status: Ipv6RowStatus,
    dns_server: String,
    dns_provider: Option<&'static str>,
    dns_leak: crate::core::dns_leak::DnsLeakStatus,

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

#[derive(Clone, Copy, PartialEq, Eq)]
enum Ipv6RowStatus {
    Absent,
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
    let dns_leaking = matches!(
        app.runtime.dns_leak,
        crate::core::dns_leak::DnsLeakStatus::Leaking { .. }
    );
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

fn derive_ipv6_row_status(app: &App) -> Ipv6RowStatus {
    let public = app.runtime.public_ipv6.as_deref();
    let real = app.runtime.real_ipv6.as_deref();
    if public.is_none() && real.is_none() {
        return Ipv6RowStatus::Absent;
    }
    if app.registry.primary().is_none() {
        return Ipv6RowStatus::Masked;
    }
    match (public, real) {
        (Some(p), Some(r)) if p == r => Ipv6RowStatus::Leaking,
        (Some(_), Some(_)) => Ipv6RowStatus::Masked,
        _ => Ipv6RowStatus::Pending,
    }
}

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
        real_ipv6: app.runtime.real_ipv6.clone(),
        public_ipv6: app.runtime.public_ipv6.clone(),
        location,
        ip_status,
        ipv6_status: derive_ipv6_row_status(app),
        dns_server: app.runtime.dns_server.clone(),
        dns_provider,
        dns_leak: app.runtime.dns_leak.clone(),
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
    let (public_ip, location, ip_status) = if has_primary {
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
        let location = if app.runtime.location.is_empty()
            || app.runtime.location == constants::MSG_DETECTING
            || app.runtime.location == constants::MSG_FETCHING
        {
            None
        } else {
            Some(app.runtime.location.clone())
        };
        (app.runtime.public_ip.clone(), location, ip_status)
    } else {
        (String::new(), None, IpStatus::Pending)
    };

    PanelState {
        inner_width,
        show_section_headers: true,
        real_ip: app.runtime.real_ip.clone(),
        public_ip,
        real_ipv6: app.runtime.real_ipv6.clone(),
        public_ipv6: app.runtime.public_ipv6.clone(),
        location,
        ip_status,
        ipv6_status: derive_ipv6_row_status(app),
        dns_server: app.runtime.dns_server.clone(),
        dns_provider: dns_provider_label(&app.runtime.dns_server),
        dns_leak: app.runtime.dns_leak.clone(),
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

    push_real_ip_rows(&mut lines, s, w);
    push_exit_ip_rows(&mut lines, s, w);

    let (loc_value, loc_sigil) = match s.location.as_deref() {
        Some(loc) if !loc.is_empty() => (loc.to_string(), Sigil::OkMuted),
        _ => ("detecting…".to_string(), Sigil::NotApplicable),
    };
    lines.push(audit_row("Location", &loc_value, loc_sigil, w));

    push_dns_rows(&mut lines, s, w);

    lines.push(Line::from(""));

    if show_headers {
        lines.push(section_header("Defense"));
    }

    let (ks_sigil, ks_subline) = killswitch_visuals(s.killswitch_mode, s.killswitch_state);
    let ks_value = killswitch_value(s.killswitch_mode, s.killswitch_state);
    lines.push(audit_row("Killswitch", &ks_value, ks_sigil, w));
    if let Some(why) = ks_subline {
        lines.push(alarm_subline(why, w));
    }

    let cipher_strength = classify_cipher(&s.encryption);
    let encryption_value = format!("{} · {}", s.encryption, cipher_strength.label());
    lines.push(audit_row(
        "Encryption",
        &encryption_value,
        cipher_strength.sigil(),
        w,
    ));
    if let Some(why) = cipher_strength.alarm_subline() {
        lines.push(alarm_subline(why, w));
    }

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

    push_real_ip_rows(&mut lines, s, w);
    let v6 = has_v6_signal(s);
    if s.public_ip.is_empty() {
        let v4_label = if v6 { "Exit IPv4" } else { "Exit IP" };
        lines.push(audit_row(
            v4_label,
            "split-route — no exit",
            Sigil::NotApplicable,
            w,
        ));
        if v6 {
            lines.push(audit_row(
                "Exit IPv6",
                "split-route — no exit",
                Sigil::NotApplicable,
                w,
            ));
        }
    } else {
        push_exit_ip_rows(&mut lines, s, w);
    }

    let (loc_value, loc_sigil) = match s.location.as_deref() {
        Some(loc) if !loc.is_empty() => (loc.to_string(), Sigil::OkMuted),
        _ => ("detecting…".to_string(), Sigil::NotApplicable),
    };
    lines.push(audit_row("Location", &loc_value, loc_sigil, w));

    push_dns_rows(&mut lines, s, w);

    lines.push(Line::from(""));

    if show_headers {
        lines.push(section_header("Defense"));
    }

    let (ks_sigil, ks_subline) = killswitch_visuals(s.killswitch_mode, s.killswitch_state);
    let ks_value = killswitch_value(s.killswitch_mode, s.killswitch_state);
    lines.push(audit_row("Killswitch", &ks_value, ks_sigil, w));
    if let Some(why) = ks_subline {
        lines.push(alarm_subline(why, w));
    }

    if s.encryption != "N/A" {
        let cipher_strength = classify_cipher(&s.encryption);
        let encryption_value = format!("{} · {}", s.encryption, cipher_strength.label());
        lines.push(audit_row(
            "Encryption",
            &encryption_value,
            cipher_strength.sigil(),
            w,
        ));
        if let Some(why) = cipher_strength.alarm_subline() {
            lines.push(alarm_subline(why, w));
        }
    }

    lines.push(Line::from(""));
    lines.push(footer_line(s.last_check_secs));

    lines
}

#[allow(clippy::too_many_lines)]
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

    let v6_ip = app
        .runtime
        .real_ipv6
        .as_deref()
        .or(app.runtime.public_ipv6.as_deref())
        .map(str::to_string);
    let real_label = if v6_ip.is_some() {
        "Real IPv4"
    } else {
        "Real IP"
    };
    let exit_label = if v6_ip.is_some() {
        "Exit IPv4"
    } else {
        "Exit IP"
    };

    lines.push(audit_row(real_label, &exposed_ip, Sigil::OkMuted, w));
    if let Some(ref ip6) = v6_ip {
        lines.push(audit_row("Real IPv6", ip6, Sigil::OkMuted, w));
    }
    lines.push(audit_row(exit_label, &exposed_ip, Sigil::AlarmWarn, w));
    if let Some(ref ip6) = v6_ip {
        lines.push(audit_row("Exit IPv6", ip6, Sigil::AlarmWarn, w));
    }
    let alarm = if v6_ip.is_some() {
        "no VPN — your real IPv4 and IPv6 are visible"
    } else {
        "no VPN — your real IPv4 is visible"
    };
    lines.push(alarm_subline(alarm, w));

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
    lines.push(audit_row("Location", &location, loc_sigil, w));

    let dns_value = format_value_with_tag(
        &app.runtime.dns_server,
        dns_provider_label(&app.runtime.dns_server),
    );
    lines.push(audit_row("DNS", &dns_value, Sigil::OkMuted, w));

    lines.push(Line::from(""));

    lines.push(audit_row(
        "Killswitch",
        killswitch_mode_label(app.runtime.killswitch_mode),
        match app.runtime.killswitch_mode {
            KillSwitchMode::Off => Sigil::AlarmError,
            _ => Sigil::OkMuted,
        },
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

fn killswitch_visuals(
    mode: KillSwitchMode,
    state: KillSwitchState,
) -> (Sigil, Option<&'static str>) {
    use KillSwitchMode::{AlwaysOn, Auto, Off};
    use KillSwitchState::Blocking;
    match (mode, state) {
        (Off, _) => (Sigil::AlarmError, Some("off — not protecting")),
        (Auto, Blocking) => (Sigil::AlarmWarn, Some("press r to reconnect")),
        (AlwaysOn | Auto, _) => (Sigil::OkMuted, None),
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
            real_ipv6: None,
            public_ipv6: None,
            location: Some("US-East".to_string()),
            ip_status: IpStatus::Masked,
            ipv6_status: Ipv6RowStatus::Absent,
            dns_server: "1.1.1.1".to_string(),
            dns_provider: Some("Cloudflare"),
            dns_leak: crate::core::dns_leak::DnsLeakStatus::Protected {
                recursor: "1.1.1.1".parse().unwrap(),
                configured: "1.1.1.1".parse().unwrap(),
            },
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
        use crate::core::dns_leak::DnsLeakStatus;
        let mut s = baseline_protected_state(40);
        s.dns_leak = DnsLeakStatus::Leaking {
            configured: "1.1.1.1".parse().unwrap(),
            recursor: "218.248.42.7".parse().unwrap(),
        };
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
    fn protected_no_v6_connectivity_keeps_legacy_real_ip_and_exit_ip_labels() {
        let s = baseline_protected_state(48);
        let lines = build_protected_audit(&s);
        let all_text: String = lines.iter().map(line_text).collect::<Vec<_>>().join("\n");
        assert!(
            all_text.contains("Real IP   :") && all_text.contains("Exit IP   :"),
            "labels stay as `Real IP` / `Exit IP` when no v6 present: {all_text}"
        );
        assert!(
            !all_text.contains("Real IPv6") && !all_text.contains("Exit IPv6"),
            "no v6 rows when no v6 connectivity: {all_text}"
        );
    }

    #[test]
    fn protected_v6_present_renames_v4_label_and_renders_ok_v6_row() {
        let mut s = baseline_protected_state(60);
        s.real_ipv6 = Some("2401:4900::abcd".to_string());
        s.public_ipv6 = Some("2001:db8::1".to_string());
        s.ipv6_status = Ipv6RowStatus::Masked;
        let lines = build_protected_audit(&s);
        let all_text: String = lines.iter().map(line_text).collect::<Vec<_>>().join("\n");
        assert!(
            all_text.contains("Real IPv4") && all_text.contains("Exit IPv4"),
            "v4 rows must switch to explicit IPv4 labels when v6 present: {all_text}"
        );
        let exit_v6_idx = lines
            .iter()
            .position(|l| line_text(l).starts_with("Exit IPv6"))
            .expect("Exit IPv6 row missing");
        let v6_line = &lines[exit_v6_idx];
        assert!(line_text(v6_line).contains("2001:db8::1"));
        assert_eq!(v6_line.spans.last().unwrap().content.trim_end(), "✓");
    }

    #[test]
    fn protected_v6_leaking_alarms_exit_ipv6_row() {
        let mut s = baseline_protected_state(60);
        s.real_ipv6 = Some("2401:4900::abcd".to_string());
        s.public_ipv6 = Some("2401:4900::abcd".to_string());
        s.ipv6_status = Ipv6RowStatus::Leaking;
        let lines = build_protected_audit(&s);
        let exit_v6_idx = lines
            .iter()
            .position(|l| line_text(l).starts_with("Exit IPv6"))
            .expect("Exit IPv6 row missing");
        let v6_line = &lines[exit_v6_idx];
        assert_eq!(v6_line.spans.last().unwrap().content.trim_end(), "✗");
        let sub_text = line_text(&lines[exit_v6_idx + 1]);
        assert!(
            sub_text.contains("v6 exposed"),
            "alarm sub-line: {sub_text:?}"
        );
    }

    #[test]
    fn protected_v6_pending_renders_checking_in_real_ipv6_row() {
        let mut s = baseline_protected_state(60);
        s.real_ipv6 = None;
        s.public_ipv6 = Some("2401:4900::abcd".to_string());
        s.ipv6_status = Ipv6RowStatus::Pending;
        let lines = build_protected_audit(&s);
        let real_v6_idx = lines
            .iter()
            .position(|l| line_text(l).starts_with("Real IPv6"))
            .expect("Real IPv6 row missing");
        let text = line_text(&lines[real_v6_idx]);
        assert!(
            text.contains("checking…"),
            "Real IPv6 must show checking…: {text:?}"
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
        for label in [
            "Real IP",
            "Exit IP",
            "Location",
            "DNS",
            "Killswitch",
            "Encryption",
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
            out.contains("no VPN — your real IPv4 is visible"),
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
    fn partial_no_v6_connectivity_keeps_legacy_labels() {
        let mut app = App::new_test();
        insert_idle_tunnel(&mut app, "alpha");

        let out = render_to_string(&app, 70, 20);
        assert!(
            !out.contains("Real IPv6") && !out.contains("Exit IPv6"),
            "no v6 connectivity must not render IPv6 rows:\n{out}"
        );
        assert!(
            !out.contains("Not enforced"),
            "old IPv6 explainer must be gone:\n{out}"
        );
    }
}
