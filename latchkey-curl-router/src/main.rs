//! `latchkey-curl-router` — a drop-in `curl` that routes each
//! invocation to one of two real implementations, and optionally to a
//! different destination. Impersonation is asked for by a private marker
//! header in the arguments; the desktop proxy is chosen by looking up the
//! service latchkey matched the request to, which it reports in another
//! header, in a config file named in the environment. That file gives each
//! service an ordered list of rules — a device id, or `self` — and the
//! request leaves from the first of them that a connected desktop
//! satisfies; `self` is this machine, and is what a service the config
//! says nothing about gets. A caller can name one of the desktops the
//! rules admit outright, with an `X-Latchkey-Device` header. It exists
//! so a single `LATCHKEY_CURL` binary can serve impersonating and
//! non-impersonating callers alike without breaking the latter: only
//! callers that opt in get the Chrome-impersonating curl; everyone else
//! keeps getting the system curl they expect.
//!
//! The impersonating curl is upstream `curl-impersonate` (shipped next to
//! this binary as `curl-impersonate`), a real curl whose
//! `--impersonate` flag selects a browser profile. This binary is what
//! turns that flag on, so an impersonating invocation is rewritten, not
//! forwarded verbatim; see [`impersonate_args`].

use std::collections::BTreeMap;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

use serde::de::Error as _;
use serde::{Deserialize, Deserializer};
use serde_json::Value;

/// Name of the private routing marker header. Namespaced so it can't
/// collide with a header a caller legitimately wants to set or strip.
const MARKER_HEADER_NAME: &str = "X-Imbue-Impersonate";

/// Env var naming the JSON file that says which requests leave from one of
/// the user's own computers rather than from this machine. The file holds
/// one object; each key is a latchkey service name and each value is that
/// service's rules, an ordered list of [`ProxyTerm`]s. Unset or empty:
/// nothing is proxied. Set but unreadable or malformed: an error, since the
/// operator asked for routing they are not getting.
const DESKTOP_PROXY_CONFIG_ENV: &str = "LATCHKEY_DESKTOP_PROXY_CONFIG";

/// The header latchkey reports the matched service in, when it runs with
/// `LATCHKEY_DIAGNOSTIC_HEADERS=1`. Latchkey decides which service a URL
/// belongs to (by prefix or by pattern), so we take its answer rather than
/// matching URLs a second time. Latchkey puts its header ahead of the
/// caller's arguments and leaves a copy the caller supplied in place, so the
/// first occurrence is the one read. The header is for us alone: every
/// occurrence is dropped before curl runs.
const MATCHED_SERVICE_HEADER_NAME: &str = "X-Latchkey-Matched-Service";

/// The header a caller names the desktop it wants in, in place of the
/// choice the service's rules would otherwise make. The value is one
/// device id and nothing else: a list, a wildcard, a rule name or any
/// other string that is not the id of a desktop with a record here is
/// refused, and so is a desktop the service's rules do not admit. The
/// header is for us alone: every occurrence is dropped before curl runs.
const DESKTOP_DEVICE_HEADER_NAME: &str = "X-Latchkey-Device";

/// The headers addressed to us rather than to curl: read before anything
/// is routed and dropped from every invocation, whichever route it takes,
/// so they reach neither the desktop gateway nor the third party.
const ROUTER_ONLY_HEADERS: &[&str] = &[MATCHED_SERVICE_HEADER_NAME, DESKTOP_DEVICE_HEADER_NAME];

/// Env var naming the directory of device records: one JSON file per
/// desktop connected to this machine, written by the desktop itself when
/// its reverse tunnel comes up and touched by every keepalive (about once
/// a minute) after that. The user may be connected from several desktops
/// at once, each with its own tunnel on its own port, so which gateway a
/// matched request goes to is decided per invocation: the record touched
/// most recently is the desktop the user is at. It is the variable minds
/// already gives the VPS gateway for its own desktop-forwarding extension;
/// the gateway runs us as a child, so we inherit it. Unset or empty:
/// [`DEFAULT_DESKTOP_DEVICES_DIR`].
const DESKTOP_DEVICES_DIR_ENV: &str = "LATCHKEY_EXTENSION_DEVICES_DIR";

/// Where minds keeps the device records when [`DESKTOP_DEVICES_DIR_ENV`]
/// says nothing else.
const DEFAULT_DESKTOP_DEVICES_DIR: &str = "/run/mngr-latchkey/devices";

/// The extension of a device record: `<device_id>.json`. Anything else in
/// the directory (a lock file, an editor backup) is not a record.
const DESKTOP_DEVICE_RECORD_EXTENSION: &str = "json";

/// How long after its last keepalive a desktop still counts as connected,
/// and so as one a rule can be satisfied by. A desktop touches its record
/// with every keepalive, about once a minute, so this is a few missed
/// ones: long enough that a desktop which is merely busy keeps its turn,
/// short enough that one which went away without cleaning up stops taking
/// the requests a later rule — another desktop, or `self` — can still
/// carry.
const DESKTOP_ACTIVE_WINDOW: Duration = Duration::from_secs(180);

/// The latchkey gateway's outbound-proxy endpoint: `<gateway>/gateway/<target-url>`.
const GATEWAY_PATH_PREFIX: &str = "/gateway/";

/// The header a latchkey gateway reads its shared password from.
const GATEWAY_PASSWORD_HEADER_NAME: &str = "X-Latchkey-Gateway-Password";

/// The header a latchkey gateway reads a permissions-override JWT from.
const GATEWAY_PERMISSIONS_OVERRIDE_HEADER_NAME: &str = "X-Latchkey-Gateway-Permissions-Override";

/// The header that asks a latchkey gateway to forward a `/gateway/<url>`
/// request without injecting credentials, because they are already in it,
/// injected by the gateway that handed the request to us. The receiving
/// gateway still runs its permission check, and refuses the header
/// outright unless it runs with `LATCHKEY_PASSTHROUGH_UNKNOWN`.
const GATEWAY_NO_CREDENTIALS_HEADER: &str = "X-Latchkey-Gateway-No-Credentials: 1";

/// Filenames to look for next to `current_exe()` — mirrors
/// `SIBLING_NAMES` in datalib's `latchkey.rs`. Installers ship the impersonator and
/// this router side by side in the same dir, so a sibling lookup
/// resolves it without any configuration.
const IMPERSONATE_SIBLING_NAMES: &[&str] = &["curl-impersonate"];

/// Env var naming the `--impersonate` target. Passed through as-is:
/// curl-impersonate rejects a name it does not know (exit 43, naming a
/// valid one), which is the loud failure we want rather than a fallback
/// to some other fingerprint.
const PROFILE_ENV: &str = "DATALIB_IMPERSONATE_PROFILE";

/// The profile used when [`PROFILE_ENV`] is unset. Its JA4 and HTTP/2
/// fingerprints matched a real Chromium 152 when it was chosen
/// (2026-09-11, `tls.browserleaks.com`); bump it as Chrome moves.
const DEFAULT_PROFILE: &str = "chrome150";

/// Headers the caller may not set on an impersonated request: the marker
/// is ours and must not reach the wire, and a `User-Agent` would override
/// the one the profile sends (curl lets `-H` replace any header). The
/// latchkey gateway forwards its own client's `User-Agent: curl/...`, so
/// the second is the normal case, not a corner.
const IMPERSONATE_STRIPPED_HEADERS: &[&str] = &[MARKER_HEADER_NAME, "User-Agent"];

fn die(msg: impl AsRef<str>) -> ! {
    eprintln!("latchkey-curl-router: {}", msg.as_ref());
    std::process::exit(2);
}

fn warn(msg: impl AsRef<str>) {
    eprintln!("latchkey-curl-router: warning: {}", msg.as_ref());
}

fn is_header_named(header_argument: &str, name: &str) -> bool {
    match header_argument.find([':', ';']) {
        Some(index) => header_argument[..index].trim().eq_ignore_ascii_case(name),
        // No separator: not a header argument curl would accept, so not
        // a marker either.
        None => false,
    }
}

fn is_header_flag(token: &str) -> bool {
    token == "-H" || token == "--header"
}

fn has_header(argv: &[String], name: &str) -> bool {
    let mut it = argv.iter();
    while let Some(tok) = it.next() {
        // Consume the value along with the flag, so a header value that
        // happens to look like a flag is never read as one. `&&`
        // short-circuits, so `it.next()` still runs only when the flag
        // matched — the advance is identical to the nested-`if` form
        // clippy asked us to collapse.
        if is_header_flag(tok) && it.next().is_some_and(|v| is_header_named(v, name)) {
            return true;
        }
    }
    false
}

/// The value of the first header called `name`, trimmed. Empty for the
/// value-less `name;` spelling.
fn header_value<'a>(argv: &'a [String], name: &str) -> Option<&'a str> {
    let mut it = argv.iter();
    while let Some(tok) = it.next() {
        if !is_header_flag(tok) {
            continue;
        }
        let Some(header_argument) = it.next() else {
            break;
        };
        if is_header_named(header_argument, name) {
            let separator = header_argument.find([':', ';'])?;
            return Some(header_argument[separator + 1..].trim());
        }
    }
    None
}

/// `argv` without the headers called any of `names`.
fn without_headers(argv: &[String], names: &[&str]) -> Vec<String> {
    let mut kept = Vec::with_capacity(argv.len());
    let mut it = argv.iter();
    while let Some(tok) = it.next() {
        if is_header_flag(tok) {
            // A header's value belongs to it: keep or drop the pair as a
            // unit, so a value that looks like a flag is never re-read.
            match it.next() {
                Some(value) if names.iter().any(|name| is_header_named(value, name)) => continue,
                Some(value) => {
                    kept.push(tok.clone());
                    kept.push(value.clone());
                }
                None => kept.push(tok.clone()),
            }
        } else {
            kept.push(tok.clone());
        }
    }
    kept
}

/// One rule: a place a request is allowed to leave from. A service's
/// rules are an ordered list of these, and the first one a connected
/// desktop satisfies is the one that carries the request.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ProxyTerm {
    /// This machine's own egress: the request goes out from here, the way
    /// an unproxied one always has. Nothing has to be connected for this
    /// rule to be satisfied, so no rule after it is ever reached.
    SelfEgress,
    /// One desktop, named by the device id its record is called after.
    Device(String),
    /// Whichever desktop is connected; the one seen most recently when
    /// several are. **Not a rule that can be written**: it is only what
    /// the old config's truthy value is read as, since that value named
    /// no device and this is what it used to do. A desktop reached this
    /// way is whichever one the user happens to be at, which is why the
    /// new rules name devices instead — a permission is granted to a
    /// device, so the device has to be the one the config chose.
    LegacyAnyDesktop,
}

/// How [`ProxyTerm::SelfEgress`] is written in the config.
const SELF_TERM: &str = "self";

/// The rule that used to mean [`ProxyTerm::LegacyAnyDesktop`]. It is no
/// longer one: a permission belongs to a device, so a rule has to name
/// the device it is about. The name stays reserved rather than becoming
/// an ordinary device id, so a config that still writes it is refused
/// instead of being read as a device that will never be found.
const RETIRED_ANY_DESKTOP_TERM: &str = "any-desktop";

/// Names a device record cannot use, because no rule could then name it:
/// the one rule name, and the retired one.
const RESERVED_DEVICE_IDS: &[&str] = &[SELF_TERM, RETIRED_ANY_DESKTOP_TERM];

impl ProxyTerm {
    fn parse(text: &str) -> Result<Self, String> {
        match text {
            SELF_TERM => Ok(Self::SelfEgress),
            RETIRED_ANY_DESKTOP_TERM => Err(format!(
                "{RETIRED_ANY_DESKTOP_TERM:?} is no longer a rule: name the device ids to try,                  since a permission is granted to one device"
            )),
            "" => Err(format!(
                "a rule is {SELF_TERM:?} or a device id, not an empty string"
            )),
            device_id => Ok(Self::Device(device_id.to_string())),
        }
    }

    /// Whether this rule lets `device_id` carry a request. This is what
    /// the [`DESKTOP_DEVICE_HEADER_NAME`] override is checked against: a
    /// desktop the caller names is admissible when any one of the
    /// service's rules admits it, wherever that rule sits in the order
    /// and whatever the rules before it would have chosen.
    fn admits(&self, device_id: &str) -> bool {
        match self {
            Self::SelfEgress => false,
            Self::Device(id) => id == device_id,
            // The old config's truthy value would have sent the request
            // to whichever desktop was connected, so naming one of them
            // asks for no more than it already allowed.
            Self::LegacyAnyDesktop => true,
        }
    }
}

impl std::fmt::Display for ProxyTerm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SelfEgress => f.write_str(SELF_TERM),
            Self::Device(device_id) => f.write_str(device_id),
            Self::LegacyAnyDesktop => f.write_str("<any connected desktop>"),
        }
    }
}

/// A list of rules as the config would have written it, for the error
/// message of a request they leave nowhere to go.
fn describe_terms(terms: &[ProxyTerm]) -> String {
    let written: Vec<String> = terms.iter().map(ProxyTerm::to_string).collect();
    format!("[{}]", written.join(", "))
}

/// The rules of a service the config says nothing about, and of every
/// service when there is no config at all: out from this machine. It is
/// the implicit default, so it never has to be written down.
static DEFAULT_PROXY_TERMS: [ProxyTerm; 1] = [ProxyTerm::SelfEgress];

/// Where each latchkey service's requests may leave from: the config
/// file, one list of rules per service name.
#[derive(Debug, Default, PartialEq, Eq)]
struct DesktopProxyRules {
    services: BTreeMap<String, Vec<ProxyTerm>>,
}

impl DesktopProxyRules {
    /// `None` when the env var is unset or empty; an error when it names
    /// a file that cannot be read or is not a JSON object.
    fn from_env() -> Result<Option<Self>, String> {
        let path = match std::env::var(DESKTOP_PROXY_CONFIG_ENV) {
            Ok(value) if !value.is_empty() => value,
            _ => return Ok(None),
        };
        let text = std::fs::read_to_string(&path)
            .map_err(|err| format!("cannot read {DESKTOP_PROXY_CONFIG_ENV}={path}: {err}"))?;
        Self::parse(&text)
            .map(Some)
            .map_err(|err| format!("{DESKTOP_PROXY_CONFIG_ENV}={path}: {err}"))
    }

    fn parse(text: &str) -> Result<Self, String> {
        let value: Value = serde_json::from_str(text).map_err(|err| format!("not JSON: {err}"))?;
        let Value::Object(entries) = value else {
            return Err("expected a JSON object with latchkey service names as keys".to_string());
        };
        let mut services = BTreeMap::new();
        for (service_name, value) in entries {
            let terms = parse_terms(&value)
                .map_err(|err| format!("rules for service {service_name:?}: {err}"))?;
            services.insert(service_name, terms);
        }
        Ok(Self { services })
    }

    /// The rules for `service_name`, which are [`DEFAULT_PROXY_TERMS`]
    /// when the config does not mention it. A service name is matched
    /// whole and as written: latchkey's names are case-sensitive
    /// identifiers, and one may be a prefix of another (`fastmail`,
    /// `fastmail-dav`).
    fn terms_for(&self, service_name: &str) -> &[ProxyTerm] {
        self.services
            .get(service_name)
            .map_or(DEFAULT_PROXY_TERMS.as_slice(), Vec::as_slice)
    }
}

/// One service's value in the config. A list is the rules themselves, and
/// a non-empty string is a one-rule list.
///
/// Anything else is the old config, which held one JavaScript value per
/// service and could only say "proxied" or "not": a truthy one becomes
/// [`ProxyTerm::LegacyAnyDesktop`], which is what it used to do and
/// cannot be asked for in the new form, and a falsy one — `false`, `0`,
/// `""`, `null` — becomes `[self]`.
fn parse_terms(value: &Value) -> Result<Vec<ProxyTerm>, String> {
    match value {
        Value::Array(items) => items
            .iter()
            .map(|item| match item {
                Value::String(text) => ProxyTerm::parse(text),
                other => Err(format!("a rule is a string, not {other}")),
            })
            .collect(),
        Value::String(text) if !text.is_empty() => Ok(vec![ProxyTerm::parse(text)?]),
        legacy if is_truthy(legacy) => Ok(vec![ProxyTerm::LegacyAnyDesktop]),
        _ => Ok(vec![ProxyTerm::SelfEgress]),
    }
}

/// JavaScript's truthiness, since the values are whatever a JavaScript
/// writer put there. An empty array or object is truthy, as in JS.
fn is_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        Value::String(s) => !s.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

/// The URL a curl invocation is for: its last argument, when that is an
/// absolute http(s) URL. This is the shape every caller of ours produces
/// (latchkey's gateway and `latchkey curl` both put the URL last).
fn request_url(argv: &[String]) -> Option<&str> {
    let last = argv.last()?;
    (last.starts_with("http://") || last.starts_with("https://")).then_some(last.as_str())
}

/// Where an invocation goes; see the module docs for the order.
#[derive(Debug, PartialEq, Eq)]
enum Route {
    /// Rewritten onto this desktop's latchkey gateway and run by the
    /// system curl.
    DesktopProxy(DesktopGateway),
    /// Handed to the Chrome-impersonating curl.
    Impersonate,
    /// Handed to the system curl.
    SystemCurl,
}

/// The desktop proxy is decided first, by [`plan_desktop_proxy`]: a
/// request that also carries the impersonation marker must keep it for
/// the desktop gateway's own curl, which the impersonator here would
/// strip.
fn choose_route(argv: &[String], gateway: Option<DesktopGateway>) -> Route {
    match gateway {
        Some(gateway) => Route::DesktopProxy(gateway),
        None if has_header(argv, MARKER_HEADER_NAME) => Route::Impersonate,
        None => Route::SystemCurl,
    }
}

/// The desktop latchkey gateway a matched request is sent to, read from
/// the record of the desktop the rules chose.
#[derive(Debug, PartialEq, Eq)]
struct DesktopGateway {
    /// Base URL without a trailing slash, so the endpoint path can be
    /// appended directly.
    base_url: String,
    password: Option<String>,
    permissions_override: Option<String>,
}

impl DesktopGateway {
    /// The gateway a desktop's record names. An error when the record
    /// cannot be used: a request the rules sent to a desktop is not
    /// quietly let out from here instead, since the operator asked for a
    /// different source address on purpose.
    fn from_record(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|err| format!("cannot read device record {}: {err}", path.display()))?;
        Self::parse(&text).map_err(|err| format!("device record {}: {err}", path.display()))
    }

    fn parse(text: &str) -> Result<Self, String> {
        let record: DeviceRecord =
            serde_json::from_str(text).map_err(|err| format!("not a device record: {err}"))?;
        if record.port == 0 {
            return Err("\"port\" is not a TCP port number".to_string());
        }
        Ok(Self {
            base_url: format!("http://127.0.0.1:{}", record.port),
            password: record.gateway_password,
            permissions_override: record.permissions_override,
        })
    }
}

/// A desktop's device record: `<device_id>.json`, written by minds. Keys
/// not listed here are ignored.
#[derive(Deserialize)]
struct DeviceRecord {
    /// The loopback port the desktop's tunnel listens on here. The desktop
    /// gateway is reached as `http://127.0.0.1:<port>`: a reverse tunnel
    /// lands on this machine's loopback and nowhere else.
    port: u16,

    /// The password to send as [`GATEWAY_PASSWORD_HEADER_NAME`]: the
    /// desktop gateway's own listen password. It is not the password the
    /// gateway running us listens with. In minds that one is fixed by
    /// whichever of the user's computers created the workspace, while the
    /// desktop's belongs to the computer the record describes. Absent or
    /// `null`: no password header is sent, for a gateway that requires
    /// none. Present but not a non-empty string: an error, since the
    /// desktop asked for a secret to be sent and its gateway would refuse
    /// the request without it.
    #[serde(default, deserialize_with = "gateway_password_secret")]
    gateway_password: Option<String>,

    /// The JWT to send as [`GATEWAY_PERMISSIONS_OVERRIDE_HEADER_NAME`].
    /// The desktop gateway checks a request against the permissions file
    /// this JWT names instead of its default one, which in minds denies
    /// everything. Same absent/invalid handling as `gateway_password`.
    #[serde(default, deserialize_with = "permissions_override_secret")]
    permissions_override: Option<String>,
}

fn gateway_password_secret<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    optional_secret(deserializer, "gateway_password")
}

fn permissions_override_secret<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    optional_secret(deserializer, "permissions_override")
}

/// A secret field of a device record: `None` for `null`, an error for
/// anything but a non-empty string. serde's own message is replaced,
/// since it quotes the value it rejected and the value is a secret.
fn optional_secret<'de, D: Deserializer<'de>>(
    deserializer: D,
    key: &str,
) -> Result<Option<String>, D::Error> {
    let invalid = || D::Error::custom(format!("{key:?} is neither a non-empty string nor null"));
    match Option::<String>::deserialize(deserializer) {
        Ok(Some(secret)) if secret.is_empty() => Err(invalid()),
        Ok(secret) => Ok(secret),
        Err(_) => Err(invalid()),
    }
}

/// A desktop with a record in the devices directory.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Desktop {
    /// The record's name without `.json`: the device id a rule, and the
    /// [`DESKTOP_DEVICE_HEADER_NAME`] override, name this desktop by.
    device_id: String,
    path: PathBuf,
    /// Whether its last keepalive is recent enough for the desktop to
    /// count as connected; see [`DESKTOP_ACTIVE_WINDOW`].
    active: bool,
}

/// The directory of device records: [`DESKTOP_DEVICES_DIR_ENV`], or
/// [`DEFAULT_DESKTOP_DEVICES_DIR`] when it says nothing.
fn desktop_devices_dir() -> PathBuf {
    match std::env::var(DESKTOP_DEVICES_DIR_ENV) {
        Ok(value) if !value.is_empty() => PathBuf::from(value),
        _ => PathBuf::from(DEFAULT_DESKTOP_DEVICES_DIR),
    }
}

/// Every desktop with a record in `devices_dir`, the one touched most
/// recently first; ties go to the greater device id, so the order is the
/// same on every invocation. Only files whose extension is
/// [`DESKTOP_DEVICE_RECORD_EXTENSION`] count.
///
/// A record that vanishes while the directory is being read is a desktop
/// that just disconnected, and is skipped silently; one that cannot be
/// stat'ed, or whose name is not a usable device id, is skipped with a
/// warning, so one odd file does not cut off every desktop. Trouble with
/// the directory itself is a warning too rather than an error: it means
/// no desktop can be seen, which is a thing the rules have an answer for
/// — a desktop is no more reachable than if its record were missing, and
/// `self` is still reachable.
fn list_desktops(devices_dir: &Path, now: SystemTime) -> Vec<Desktop> {
    let describe_dir = || format!("{DESKTOP_DEVICES_DIR_ENV}={}", devices_dir.display());
    let entries = match std::fs::read_dir(devices_dir) {
        Ok(entries) => entries,
        Err(err) => {
            warn(format!(
                "no desktop can be seen: cannot list {}: {err}",
                describe_dir()
            ));
            return Vec::new();
        }
    };
    let mut found: Vec<(SystemTime, Desktop)> = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                warn(format!(
                    "skipping a device record: cannot list {}: {err}",
                    describe_dir()
                ));
                continue;
            }
        };
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some(DESKTOP_DEVICE_RECORD_EXTENSION) {
            continue;
        }
        let Some(device_id) = path.file_stem().and_then(|stem| stem.to_str()) else {
            warn(format!(
                "skipping device record {}: its name is not a device id",
                path.display()
            ));
            continue;
        };
        if RESERVED_DEVICE_IDS.contains(&device_id) {
            warn(format!(
                "skipping device record {}: {device_id:?} is a reserved name no rule can name",
                path.display()
            ));
            continue;
        }
        let device_id = device_id.to_string();
        let metadata = match std::fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => {
                warn(format!(
                    "skipping device record {}: cannot stat it: {err}",
                    path.display()
                ));
                continue;
            }
        };
        if !metadata.is_file() {
            continue;
        }
        let modified = match metadata.modified() {
            Ok(modified) => modified,
            Err(err) => {
                warn(format!(
                    "skipping device record {}: cannot read its modification time: {err}",
                    path.display()
                ));
                continue;
            }
        };
        let active = match now.duration_since(modified) {
            Ok(since_keepalive) => since_keepalive <= DESKTOP_ACTIVE_WINDOW,
            // Touched in the future: a clock that moved, not a desktop
            // that is gone.
            Err(_) => true,
        };
        found.push((
            modified,
            Desktop {
                device_id,
                path,
                active,
            },
        ));
    }
    found.sort_by(|(left_modified, left), (right_modified, right)| {
        (right_modified, &right.device_id).cmp(&(left_modified, &left.device_id))
    });
    found.into_iter().map(|(_, desktop)| desktop).collect()
}

/// The desktop a request leaves from, or `None` for this machine's own
/// egress. The rules are walked in order and the first one a connected
/// desktop satisfies wins; `requested_device`, the caller's
/// [`DESKTOP_DEVICE_HEADER_NAME`], replaces that walk with the desktop it
/// names, as long as the rules admit that desktop and it has a record
/// here. How long ago that desktop was last heard from is then not
/// checked: the caller named it on purpose, and the request fails at its
/// port rather than here, the way it did when the desktop was never
/// chosen by rule.
///
/// An error when the rules call for a desktop and none of them can be
/// satisfied, or when the named desktop is not one the caller may have:
/// such a request is not quietly let out from this machine instead.
fn choose_desktop<'a>(
    terms: &[ProxyTerm],
    desktops: &'a [Desktop],
    requested_device: Option<&str>,
) -> Result<Option<&'a Desktop>, String> {
    if let Some(device_id) = requested_device {
        if !terms.iter().any(|term| term.admits(device_id)) {
            return Err(format!(
                "{DESKTOP_DEVICE_HEADER_NAME}: {device_id:?} is not a desktop these rules allow: {}",
                describe_terms(terms)
            ));
        }
        let Some(desktop) = desktops.iter().find(|d| d.device_id == device_id) else {
            return Err(format!(
                "{DESKTOP_DEVICE_HEADER_NAME}: {device_id:?} is not the id of a known device"
            ));
        };
        return Ok(Some(desktop));
    }
    for term in terms {
        match term {
            ProxyTerm::SelfEgress => return Ok(None),
            ProxyTerm::Device(device_id) => {
                if let Some(desktop) = desktops
                    .iter()
                    .find(|d| d.active && &d.device_id == device_id)
                {
                    return Ok(Some(desktop));
                }
            }
            ProxyTerm::LegacyAnyDesktop => {
                if let Some(desktop) = desktops.iter().find(|d| d.active) {
                    return Ok(Some(desktop));
                }
            }
        }
    }
    Err(format!(
        "no desktop is connected that satisfies any of these rules: {}",
        describe_terms(terms)
    ))
}

/// The desktop gateway this invocation is rewritten onto, or `None` when
/// it goes out from this machine like any unproxied request. The devices
/// directory, and the chosen desktop's record, are read only when the
/// rules can lead to a desktop at all: the common case is the default
/// `self`, where there is nothing to look up.
fn plan_desktop_proxy(
    argv: &[String],
    rules: Option<&DesktopProxyRules>,
) -> Result<Option<DesktopGateway>, String> {
    let service_name = header_value(argv, MATCHED_SERVICE_HEADER_NAME);
    let requested_device = header_value(argv, DESKTOP_DEVICE_HEADER_NAME);
    // Latchkey names the service only for a request it injected
    // credentials into. Anything else, and anything the config says
    // nothing about, leaves from here.
    let terms = match (rules, service_name) {
        (Some(rules), Some(service_name)) => rules.terms_for(service_name),
        _ => DEFAULT_PROXY_TERMS.as_slice(),
    };
    if requested_device.is_none() && matches!(terms.first(), Some(ProxyTerm::SelfEgress)) {
        return Ok(None);
    }
    let desktops = list_desktops(&desktop_devices_dir(), SystemTime::now());
    let chosen =
        choose_desktop(terms, &desktops, requested_device).map_err(|err| match service_name {
            Some(service_name) => {
                format!("latchkey matched this request to service {service_name:?}: {err}")
            }
            None => err,
        })?;
    match chosen {
        Some(desktop) => DesktopGateway::from_record(&desktop.path).map(Some),
        None => Ok(None),
    }
}

/// Rewrite a matched invocation so it goes to the desktop gateway's
/// outbound proxy instead of straight to the third party. Everything but
/// the URL is kept verbatim, in order: the impersonation marker and the
/// caller's credentials are for the desktop gateway to handle.
fn rewrite_for_desktop_proxy(
    argv: &[String],
    gateway: &DesktopGateway,
) -> Result<Vec<String>, String> {
    let Some(target_url) = request_url(argv) else {
        return Err(format!(
            "desktop proxy requested but the last argument is not an absolute http(s) URL: {:?}",
            argv.last()
        ));
    };

    let mut rewritten = Vec::with_capacity(argv.len() + 6);
    rewritten.push("-H".to_string());
    rewritten.push(GATEWAY_NO_CREDENTIALS_HEADER.to_string());
    if let Some(password) = &gateway.password {
        rewritten.push("-H".to_string());
        rewritten.push(format!("{GATEWAY_PASSWORD_HEADER_NAME}: {password}"));
    }
    if let Some(permissions_override) = &gateway.permissions_override {
        rewritten.push("-H".to_string());
        rewritten.push(format!(
            "{GATEWAY_PERMISSIONS_OVERRIDE_HEADER_NAME}: {permissions_override}"
        ));
    }
    rewritten.extend_from_slice(&argv[..argv.len() - 1]);
    rewritten.push(format!(
        "{}{GATEWAY_PATH_PREFIX}{target_url}",
        gateway.base_url
    ));
    Ok(rewritten)
}

fn sibling_of_exe(names: &[&str]) -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let exe = std::fs::canonicalize(&exe).unwrap_or(exe);
    let dir = exe.parent()?;
    names
        .iter()
        .map(|n| dir.join(n))
        .find(|candidate| candidate.is_file())
}

fn resolve_impersonator() -> PathBuf {
    sibling_of_exe(IMPERSONATE_SIBLING_NAMES).unwrap_or_else(|| {
        die(
            "impersonation requested but no impersonator curl found next to \
             this binary (expected a curl-impersonate sibling)",
        )
    })
}

/// The argv handed to curl-impersonate for a marked invocation.
///
/// Three flags go in front. `--impersonate <profile>` is the whole point.
/// `--compressed` is required, not cosmetic: the profile advertises
/// `Accept-Encoding: gzip, deflate, br, zstd` as part of looking like
/// Chrome, and without this flag curl hands the caller the still-encoded
/// body. `--noproxy '*'` keeps `HTTP(S)_PROXY` and the macOS proxy pane
/// out of a request that carries the user's credentials — deliberately
/// stricter than plain curl, which honors them.
fn impersonate_args(argv: &[String], profile: &str) -> Vec<String> {
    let mut rewritten = Vec::with_capacity(argv.len() + 5);
    rewritten.extend(
        ["--compressed", "--noproxy", "*", "--impersonate", profile]
            .into_iter()
            .map(str::to_string),
    );
    rewritten.extend(without_headers(argv, IMPERSONATE_STRIPPED_HEADERS));
    rewritten
}

fn impersonation_profile() -> String {
    match std::env::var(PROFILE_ENV) {
        Ok(value) if !value.is_empty() => value,
        _ => DEFAULT_PROFILE.to_string(),
    }
}

fn curl_on_path(self_exe: Option<&Path>) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join("curl");
        if !candidate.is_file() {
            continue;
        }
        let canonical = std::fs::canonicalize(&candidate).unwrap_or_else(|_| candidate.clone());
        if self_exe == Some(canonical.as_path()) {
            continue;
        }
        return Some(candidate);
    }
    None
}

fn resolve_real_curl(self_exe: Option<&Path>) -> PathBuf {
    curl_on_path(self_exe).unwrap_or_else(|| die("no system curl found on $PATH"))
}

fn main() {
    let mut argv: Vec<String> = std::env::args().skip(1).collect();
    let self_exe = std::env::current_exe()
        .ok()
        .map(|p| std::fs::canonicalize(&p).unwrap_or(p));

    let rules = DesktopProxyRules::from_env().unwrap_or_else(|message| die(message));
    let gateway = plan_desktop_proxy(&argv, rules.as_ref()).unwrap_or_else(|message| die(message));
    let route = choose_route(&argv, gateway);
    // Read above, and of no use to anyone after us: not to the desktop
    // gateway, which would forward them, nor to the third party.
    argv = without_headers(&argv, ROUTER_ONLY_HEADERS);
    let target = match route {
        Route::DesktopProxy(gateway) => {
            argv =
                rewrite_for_desktop_proxy(&argv, &gateway).unwrap_or_else(|message| die(message));
            resolve_real_curl(self_exe.as_deref())
        }
        Route::Impersonate => {
            argv = impersonate_args(&argv, &impersonation_profile());
            resolve_impersonator()
        }
        Route::SystemCurl => resolve_real_curl(self_exe.as_deref()),
    };

    // `exec` replaces this process on success and only returns on error.
    let err = Command::new(&target).args(&argv).exec();
    die(format!("failed to exec {}: {err}", target.display()));
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn argv(tokens: &[&str]) -> Vec<String> {
        tokens.iter().map(|t| t.to_string()).collect()
    }

    /// Every value the marker can arrive with is recognized, under either
    /// spelling of the header flag.
    #[test]
    fn detects_marker_whatever_its_value() {
        for marker in [
            "X-Imbue-Impersonate:",
            "X-Imbue-Impersonate: 1",
            "X-Imbue-Impersonate;",
            "x-imbue-impersonate: 1",
            "X-IMBUE-IMPERSONATE:",
        ] {
            for flag in ["-H", "--header"] {
                let tokens = argv(&[
                    "-sS",
                    "-H",
                    "Accept: */*",
                    flag,
                    marker,
                    "https://example.com/",
                ]);
                assert!(
                    has_header(&tokens, MARKER_HEADER_NAME),
                    "not recognized: {flag} {marker:?}"
                );
            }
        }
    }

    /// The shape the latchkey gateway rebuilds an inbound request into
    /// (`gatewayEndpoint.ts`'s `buildCurlArguments`, plus the `-sS -D`
    /// it prepends) routes to the impersonator.
    #[test]
    fn detects_marker_in_the_gateway_reconstructed_invocation() {
        let tokens = argv(&[
            "-sS",
            "-D",
            "/tmp/headers",
            "-X",
            "POST",
            "-H",
            "User-Agent: curl/8.7.1",
            "-H",
            "Accept: */*",
            "-H",
            "X-Imbue-Impersonate: 1",
            "--data-binary",
            "@-",
            "https://claude.ai/api/organizations",
        ]);
        assert!(has_header(&tokens, MARKER_HEADER_NAME));
    }

    #[test]
    fn leaves_unmarked_invocations_to_the_system_curl() {
        let tokens = argv(&["-sS", "-H", "Accept: */*", "https://example.com/"]);
        assert!(!has_header(&tokens, MARKER_HEADER_NAME));
    }

    /// A header named something else is not the marker, and neither is a
    /// bare name with no `:` / `;` separator.
    #[test]
    fn does_not_match_other_headers() {
        for header in [
            "X-Imbue-Impersonation:",
            "Authorization: Bearer x",
            "X-Imbue-Impersonate",
        ] {
            let tokens = argv(&["-H", header, "https://example.com/"]);
            assert!(
                !has_header(&tokens, MARKER_HEADER_NAME),
                "unexpectedly matched {header:?}"
            );
        }
    }

    /// A value belongs to the flag before it: something that merely looks
    /// like a marker header argument is not read as one.
    #[test]
    fn does_not_match_inside_a_header_value() {
        let tokens = argv(&[
            "-H",
            "X-Echo: -H",
            "X-Imbue-Impersonate:",
            "https://example.com/",
        ]);
        assert!(!has_header(&tokens, MARKER_HEADER_NAME));
    }

    /// A dangling `-H` with no value is not a marker (and is left for the
    /// target binary to reject).
    #[test]
    fn tolerates_dangling_header_flag() {
        let tokens = argv(&["https://example.com/", "-H"]);
        assert!(!has_header(&tokens, MARKER_HEADER_NAME));
    }

    fn gateway_with_secrets() -> DesktopGateway {
        DesktopGateway {
            base_url: "http://127.0.0.1:1988".to_string(),
            password: Some("hunter2".to_string()),
            permissions_override: Some("override.jwt".to_string()),
        }
    }

    fn gateway_without_secrets() -> DesktopGateway {
        DesktopGateway {
            base_url: "http://127.0.0.1:1988".to_string(),
            password: None,
            permissions_override: None,
        }
    }

    /// A service's rules, written the way the config writes them.
    fn terms(written: &[&str]) -> Vec<ProxyTerm> {
        written
            .iter()
            .map(|term| ProxyTerm::parse(term).expect("a rule"))
            .collect()
    }

    fn rules(services: &[(&str, &[&str])]) -> DesktopProxyRules {
        DesktopProxyRules {
            services: services
                .iter()
                .map(|(service_name, written)| (service_name.to_string(), terms(written)))
                .collect(),
        }
    }

    /// A desktop with a record in the devices directory, connected or
    /// not. The path is the one [`list_desktops`] would have given it.
    fn desktop(device_id: &str, active: bool) -> Desktop {
        Desktop {
            device_id: device_id.to_string(),
            path: PathBuf::from(format!("/devices/{device_id}.json")),
            active,
        }
    }

    /// What the VPS gateway hands us for a request latchkey matched to
    /// `service_name`: latchkey's header ahead of the caller's arguments.
    fn gateway_invocation(service_name: &str) -> Vec<String> {
        let matched_service = format!("X-Latchkey-Matched-Service: {service_name}");
        argv(&[
            "-sS",
            "-D",
            "/tmp/headers",
            "-X",
            "POST",
            "-H",
            &matched_service,
            "-H",
            "User-Agent: curl/8.7.1",
            "-H",
            "X-Imbue-Impersonate: 1",
            "-H",
            "Authorization: Bearer injected-on-the-vps",
            "--data-binary",
            "@-",
            "https://slack.com/api/conversations.history?channel=C1&limit=100",
        ])
    }

    /// Each service's value is its rules, in the order they are tried. A
    /// bare string is the one-rule list it reads as.
    #[test]
    fn config_reads_one_list_of_rules_per_service() {
        let parsed = DesktopProxyRules::parse(
            r#"{
                "slack": ["self"],
                "github": ["desktop-1", "desktop-2"],
                "gitlab": ["desktop-1", "desktop-2", "self"],
                "google-docs": "desktop-1",
                "linear": "self",
                "notion": []
            }"#,
        )
        .expect("parses");
        assert_eq!(
            parsed,
            rules(&[
                ("slack", &["self"]),
                ("github", &["desktop-1", "desktop-2"]),
                ("gitlab", &["desktop-1", "desktop-2", "self"]),
                ("google-docs", &["desktop-1"]),
                ("linear", &["self"]),
                ("notion", &[]),
            ])
        );
    }

    /// The config as it was before the rules were a list: one JavaScript
    /// value per service, saying only whether it was proxied. Truthiness
    /// is JavaScript's, since the file is written by JavaScript, and a
    /// truthy value keeps doing what it did — whichever desktop is
    /// connected — which no rule can ask for any more.
    #[test]
    fn config_reads_the_old_boolean_form() {
        let parsed = DesktopProxyRules::parse(
            r#"{
                "on-true": true,
                "on-one": 1,
                "on-float": 0.5,
                "on-array": [],
                "on-object": {},
                "off-false": false,
                "off-zero": 0,
                "off-float-zero": 0.0,
                "off-empty": "",
                "off-null": null
            }"#,
        )
        .expect("parses");
        assert_eq!(
            parsed,
            DesktopProxyRules {
                services: [
                    ("on-true", vec![ProxyTerm::LegacyAnyDesktop]),
                    ("on-one", vec![ProxyTerm::LegacyAnyDesktop]),
                    ("on-float", vec![ProxyTerm::LegacyAnyDesktop]),
                    // An empty list is no rule at all, which is what an
                    // empty JSON array has to mean now; it was truthy
                    // before.
                    ("on-array", vec![]),
                    ("on-object", vec![ProxyTerm::LegacyAnyDesktop]),
                    ("off-false", terms(&["self"])),
                    ("off-zero", terms(&["self"])),
                    ("off-float-zero", terms(&["self"])),
                    ("off-empty", terms(&["self"])),
                    ("off-null", terms(&["self"])),
                ]
                .into_iter()
                .map(|(service_name, terms)| (service_name.to_string(), terms))
                .collect(),
            }
        );
    }

    #[test]
    fn config_that_is_not_an_object_is_an_error() {
        for text in ["[]", "\"slack\"", "null", "true", "{", ""] {
            assert!(
                DesktopProxyRules::parse(text).is_err(),
                "unexpectedly parsed {text:?}"
            );
        }
        assert_eq!(DesktopProxyRules::parse("{}").unwrap(), rules(&[]));
    }

    /// A rule list holds strings, and a string that names nothing is a
    /// typo rather than a device id: either is loud, since a config that
    /// does not mean what it says would route a request to the wrong
    /// source address.
    #[test]
    fn config_rejects_a_rule_that_is_not_a_device_id_or_a_rule_name() {
        for text in [
            r#"{"slack": [1]}"#,
            r#"{"slack": [true]}"#,
            r#"{"slack": [null]}"#,
            r#"{"slack": [["desktop-1"]]}"#,
            r#"{"slack": ["self", ""]}"#,
        ] {
            let err = DesktopProxyRules::parse(text).expect_err(text);
            assert!(err.contains("slack"), "{text}: {err}");
        }
    }

    /// `any-desktop` was a rule and is not one any more: a config still
    /// writing it is refused rather than read as a device id that will
    /// never be found. Only the old config's truthy value still reaches
    /// that behaviour.
    #[test]
    fn config_rejects_the_retired_any_desktop_rule() {
        for text in [
            r#"{"slack": ["any-desktop"]}"#,
            r#"{"slack": ["desktop-1", "any-desktop"]}"#,
            r#"{"slack": "any-desktop"}"#,
        ] {
            let err = DesktopProxyRules::parse(text).expect_err(text);
            assert!(err.contains("no longer a rule"), "{text}: {err}");
            assert!(err.contains("slack"), "{text}: {err}");
        }
    }

    /// A service name is matched whole and as written: latchkey's names
    /// are case-sensitive identifiers, and one may be a prefix of another
    /// (`fastmail`, `fastmail-dav`). Anything the config does not name
    /// goes out from this machine, which is also what an empty config and
    /// no config at all mean.
    #[test]
    fn a_service_the_config_does_not_name_goes_out_from_here() {
        let rules = rules(&[("fastmail", &["desktop-1"]), ("google-docs", &["self"])]);
        assert_eq!(rules.terms_for("fastmail"), terms(&["desktop-1"]));
        assert_eq!(rules.terms_for("google-docs"), terms(&["self"]));
        for service_name in [
            "fastmail-dav",
            "fast",
            "Fastmail",
            "google",
            "",
            " fastmail",
        ] {
            assert_eq!(
                rules.terms_for(service_name),
                DEFAULT_PROXY_TERMS,
                "{service_name:?}"
            );
        }
        assert_eq!(
            DesktopProxyRules::default().terms_for("slack"),
            DEFAULT_PROXY_TERMS
        );
    }

    #[test]
    fn header_value_is_the_first_matching_header_trimmed() {
        let tokens = argv(&[
            "-H",
            "Accept: x-latchkey-matched-service: no",
            "--header",
            "x-latchkey-matched-service:  slack ",
            "-H",
            "X-Latchkey-Matched-Service: github",
            "https://example.com/",
        ]);
        assert_eq!(
            header_value(&tokens, MATCHED_SERVICE_HEADER_NAME),
            Some("slack")
        );
        assert_eq!(
            header_value(&tokens, "Accept"),
            Some("x-latchkey-matched-service: no")
        );
        assert_eq!(header_value(&tokens, "X-Absent"), None);
        assert_eq!(
            header_value(
                &argv(&["-H", "X-Latchkey-Matched-Service;"]),
                MATCHED_SERVICE_HEADER_NAME
            ),
            Some("")
        );
        assert_eq!(
            header_value(&argv(&["-H"]), MATCHED_SERVICE_HEADER_NAME),
            None
        );
    }

    #[test]
    fn without_headers_drops_each_named_header_with_its_flag() {
        let tokens = argv(&[
            "-sS",
            "-H",
            "X-Latchkey-Matched-Service: slack",
            "-H",
            "Accept: */*",
            "--header",
            "x-latchkey-matched-service: github",
            "-H",
            "X-Note: X-Latchkey-Matched-Service: kept",
            "https://example.com/",
            "-H",
        ]);
        assert_eq!(
            without_headers(&tokens, &[MATCHED_SERVICE_HEADER_NAME]),
            argv(&[
                "-sS",
                "-H",
                "Accept: */*",
                "-H",
                "X-Note: X-Latchkey-Matched-Service: kept",
                "https://example.com/",
                "-H",
            ])
        );
    }

    /// A request the rules sent to a desktop goes there even when it also
    /// carries the impersonation marker, so the marker reaches the desktop
    /// gateway's own curl intact.
    #[test]
    fn a_desktop_is_routed_to_before_impersonation_is_considered() {
        let gateway = gateway_with_secrets();
        assert_eq!(
            choose_route(&gateway_invocation("slack"), Some(gateway_with_secrets())),
            Route::DesktopProxy(gateway)
        );
        assert_eq!(
            choose_route(&gateway_invocation("slack"), None),
            Route::Impersonate
        );
        assert_eq!(
            choose_route(&argv(&["https://slack.com/api/users.list"]), None),
            Route::SystemCurl
        );
    }

    /// The rules are walked in order, and the first of them a connected
    /// desktop satisfies is the one that carries the request. A desktop
    /// that is not connected is passed over rather than tried.
    #[test]
    fn the_first_rule_a_connected_desktop_satisfies_wins() {
        let desktops = [
            desktop("laptop", true),
            desktop("mac-at-the-office", false),
            desktop("old-tower", true),
        ];
        for (written, chosen) in [
            (&["mac-at-the-office", "old-tower"][..], Some("old-tower")),
            (&["old-tower", "laptop"][..], Some("old-tower")),
            (&["mac-at-the-office", "laptop"][..], Some("laptop")),
            // `self` is satisfied by nothing being connected, so no rule
            // after it is ever reached.
            (&["mac-at-the-office", "self", "laptop"][..], None),
            (&["self", "laptop"][..], None),
            (&["self"][..], None),
        ] {
            assert_eq!(
                choose_desktop(&terms(written), &desktops, None)
                    .expect("satisfiable")
                    .map(|desktop| desktop.device_id.as_str()),
                chosen,
                "{written:?}"
            );
        }
    }

    /// The old config's truthy value still goes to the desktop the user
    /// is at: the one that sent a keepalive most recently, which is the
    /// order [`list_desktops`] returns them in.
    #[test]
    fn the_old_truthy_value_takes_the_most_recently_seen_connected_desktop() {
        let desktops = [
            desktop("just-woke-up", false),
            desktop("here-now", true),
            desktop("idle-but-connected", true),
        ];
        assert_eq!(
            choose_desktop(&[ProxyTerm::LegacyAnyDesktop], &desktops, None)
                .expect("satisfiable")
                .map(|desktop| desktop.device_id.as_str()),
            Some("here-now")
        );
        // And fails the same way when none of them is connected.
        let err = choose_desktop(&[ProxyTerm::LegacyAnyDesktop], &[], None)
            .expect_err("nowhere to send it");
        assert!(err.contains("no desktop is connected"), "{err}");
    }

    /// Rules that call for a desktop and find none are an error, not a
    /// request let out from this machine instead: the operator asked for
    /// a different source address on purpose.
    #[test]
    fn rules_no_desktop_can_satisfy_are_an_error() {
        // One desktop, asleep, and the same with no desktop at all.
        for desktops in [&[desktop("mac-at-the-office", false)][..], &[][..]] {
            for written in [
                &["mac-at-the-office"][..],
                &["laptop", "mac-at-the-office"][..],
                // Written as an empty list: nowhere to go, deliberately.
                &[][..],
            ] {
                let err = choose_desktop(&terms(written), desktops, None)
                    .expect_err("nowhere to send it");
                assert!(
                    err.contains("no desktop is connected"),
                    "{written:?}: {err}"
                );
            }
            // The same rules with `self` at the end have somewhere to go.
            assert_eq!(
                choose_desktop(
                    &terms(&["laptop", "mac-at-the-office", "self"]),
                    desktops,
                    None
                )
                .expect("satisfiable"),
                None
            );
        }
    }

    /// The caller may name the desktop itself, and gets it whether or not
    /// the rules would have chosen it, and whether or not it is the one
    /// seen most recently.
    #[test]
    fn the_device_header_names_the_desktop_within_what_the_rules_admit() {
        let desktops = [
            desktop("laptop", true),
            desktop("mac-at-the-office", true),
            desktop("gone-to-sleep", false),
        ];
        for (written, requested) in [
            (&["laptop", "mac-at-the-office"][..], "mac-at-the-office"),
            (&["mac-at-the-office", "self"][..], "mac-at-the-office"),
            // Last in the rules, and the rule before it would have
            // answered: admissibility is not the walk.
            (
                &["laptop", "self", "mac-at-the-office"][..],
                "mac-at-the-office",
            ),
        ] {
            assert_eq!(
                choose_desktop(&terms(written), &desktops, Some(requested))
                    .expect("admissible")
                    .map(|desktop| desktop.device_id.as_str()),
                Some(requested),
                "{written:?}"
            );
        }
        // A desktop that has not been heard from recently is still the
        // one asked for: the request fails at its port rather than here.
        assert_eq!(
            choose_desktop(
                &terms(&["gone-to-sleep", "laptop"]),
                &desktops,
                Some("gone-to-sleep")
            )
            .expect("admissible")
            .map(|desktop| desktop.device_id.as_str()),
            Some("gone-to-sleep")
        );
        // The old config's truthy value admits whichever desktop is
        // named, since it would have used whichever was connected.
        assert_eq!(
            choose_desktop(
                &[ProxyTerm::LegacyAnyDesktop],
                &desktops,
                Some("mac-at-the-office")
            )
            .expect("admissible")
            .map(|desktop| desktop.device_id.as_str()),
            Some("mac-at-the-office")
        );
    }

    /// A desktop the rules do not admit is refused, and so is a value
    /// that is not the id of a device with a record here — a wildcard, a
    /// list, a rule name, an empty header.
    #[test]
    fn the_device_header_is_refused_unless_the_rules_admit_a_known_device() {
        let desktops = [desktop("laptop", true), desktop("mac-at-the-office", true)];
        for (written, requested) in [
            (&["self"][..], "laptop"),
            (&[][..], "laptop"),
            (&["laptop"][..], "mac-at-the-office"),
            (&["laptop", "self"][..], "mac-at-the-office"),
        ] {
            let err = choose_desktop(&terms(written), &desktops, Some(requested))
                .expect_err("not admitted");
            assert!(err.contains(DESKTOP_DEVICE_HEADER_NAME), "{err}");
            assert!(err.contains(requested), "{written:?}: {err}");
        }
        // The old config's truthy value admits any device, so these get
        // as far as the lookup and are refused for not naming a device
        // with a record here.
        for requested in [
            "*",
            "",
            "self",
            "any-desktop",
            "laptop,mac-at-the-office",
            "LAPTOP",
            "tablet",
        ] {
            let err = choose_desktop(&[ProxyTerm::LegacyAnyDesktop], &desktops, Some(requested))
                .expect_err("unknown");
            assert!(err.contains(DESKTOP_DEVICE_HEADER_NAME), "{err}");
            assert!(err.contains("known device"), "{requested:?}: {err}");
        }
    }

    #[test]
    fn rewrites_a_matched_invocation_onto_the_desktop_gateway() {
        // `main` drops latchkey's header before rewriting: it is of no use
        // to the desktop gateway, which would forward it to the third party.
        let invocation =
            without_headers(&gateway_invocation("slack"), &[MATCHED_SERVICE_HEADER_NAME]);
        let rewritten = rewrite_for_desktop_proxy(&invocation, &gateway_with_secrets())
            .expect("rewrite succeeds");
        assert_eq!(
            rewritten,
            argv(&[
                "-H",
                "X-Latchkey-Gateway-No-Credentials: 1",
                "-H",
                "X-Latchkey-Gateway-Password: hunter2",
                "-H",
                "X-Latchkey-Gateway-Permissions-Override: override.jwt",
                "-sS",
                "-D",
                "/tmp/headers",
                "-X",
                "POST",
                "-H",
                "User-Agent: curl/8.7.1",
                "-H",
                "X-Imbue-Impersonate: 1",
                "-H",
                "Authorization: Bearer injected-on-the-vps",
                "--data-binary",
                "@-",
                "http://127.0.0.1:1988/gateway/https://slack.com/api/conversations.history?channel=C1&limit=100",
            ])
        );
    }

    #[test]
    fn desktop_proxy_rewrite_sends_no_secret_headers_when_none_are_configured() {
        let rewritten = rewrite_for_desktop_proxy(
            &argv(&["https://example.com/x"]),
            &gateway_without_secrets(),
        )
        .expect("rewrite succeeds");
        assert_eq!(
            rewritten,
            argv(&[
                "-H",
                "X-Latchkey-Gateway-No-Credentials: 1",
                "http://127.0.0.1:1988/gateway/https://example.com/x",
            ])
        );
    }

    /// The gateway slices its prefix back off the raw path, so anything
    /// that re-encoded or normalized the target here would change the
    /// request the third party actually receives.
    #[test]
    fn desktop_proxy_rewrite_keeps_the_target_url_verbatim() {
        for url in [
            "https://slack.com/files/a%20b?u=x%2Fy",
            "https://a.example.com/x?q=https://b.example.com/y",
            "http://a.example.com/a/../b",
        ] {
            let rewritten = rewrite_for_desktop_proxy(&argv(&[url]), &gateway_without_secrets())
                .expect("rewrite succeeds");
            assert_eq!(
                rewritten.last().map(String::as_str),
                Some(format!("http://127.0.0.1:1988/gateway/{url}").as_str())
            );
        }
    }

    /// The shape the latchkey gateway hands us — its client's
    /// `User-Agent: curl/...` included — becomes a curl-impersonate
    /// invocation: the profile flags in front, the marker and the UA
    /// gone, everything else untouched and in order.
    #[test]
    fn impersonate_rewrite_adds_the_profile_flags_and_strips_our_headers() {
        let rewritten = impersonate_args(
            &argv(&[
                "-sS",
                "-D",
                "-",
                "-o",
                "/tmp/body",
                "-X",
                "POST",
                "-H",
                "User-Agent: curl/8.7.1",
                "-H",
                "Accept: application/json",
                "-H",
                "X-Imbue-Impersonate: 1",
                "--data-binary",
                "@-",
                "https://claude.ai/api/organizations",
            ]),
            "chrome150",
        );
        assert_eq!(
            rewritten,
            argv(&[
                "--compressed",
                "--noproxy",
                "*",
                "--impersonate",
                "chrome150",
                "-sS",
                "-D",
                "-",
                "-o",
                "/tmp/body",
                "-X",
                "POST",
                "-H",
                "Accept: application/json",
                "--data-binary",
                "@-",
                "https://claude.ai/api/organizations",
            ])
        );
    }

    /// Every spelling the marker and a User-Agent can arrive in is
    /// dropped: curl matches header names case-insensitively and accepts
    /// both the `Name: value` and the valueless `Name;` forms.
    #[test]
    fn impersonate_rewrite_strips_every_spelling_of_our_headers() {
        for header in [
            "X-Imbue-Impersonate: 1",
            "X-Imbue-Impersonate:",
            "X-Imbue-Impersonate;",
            "x-imbue-impersonate: 1",
            "User-Agent: curl/8.7.1",
            "user-agent: curl/8.7.1",
            "USER-AGENT;",
        ] {
            let rewritten =
                impersonate_args(&argv(&["-H", header, "https://example.com/"]), "chrome150");
            assert_eq!(
                rewritten,
                argv(&[
                    "--compressed",
                    "--noproxy",
                    "*",
                    "--impersonate",
                    "chrome150",
                    "https://example.com/",
                ]),
                "{header:?} survived"
            );
        }
    }

    /// Credentials and other caller headers are not ours to touch, and a
    /// value that merely looks like one of our headers is a value.
    #[test]
    fn impersonate_rewrite_keeps_every_other_header_pair() {
        let rewritten = impersonate_args(
            &argv(&[
                "-H",
                "Cookie: sessionKey=secret",
                "-H",
                "X-Echo: -H",
                "-H",
                "X-User-Agent-Hint: User-Agent: fake",
                "https://example.com/",
            ]),
            "chrome131",
        );
        assert_eq!(
            rewritten,
            argv(&[
                "--compressed",
                "--noproxy",
                "*",
                "--impersonate",
                "chrome131",
                "-H",
                "Cookie: sessionKey=secret",
                "-H",
                "X-Echo: -H",
                "-H",
                "X-User-Agent-Hint: User-Agent: fake",
                "https://example.com/",
            ])
        );
    }

    #[test]
    fn impersonate_rewrite_tolerates_a_dangling_header_flag() {
        let rewritten = impersonate_args(&argv(&["https://example.com/", "-H"]), "chrome150");
        assert_eq!(
            rewritten,
            argv(&[
                "--compressed",
                "--noproxy",
                "*",
                "--impersonate",
                "chrome150",
                "https://example.com/",
                "-H",
            ])
        );
    }

    /// A record holds the tunnel's loopback port and the desktop gateway's
    /// secrets; the gateway is on this machine's loopback and nowhere else.
    #[test]
    fn device_record_gives_the_gateway_and_its_secrets() {
        let parsed = DesktopGateway::parse(
            r#"{
                "device_id": "mac-1",
                "port": 41231,
                "gateway_password": "hunter2",
                "permissions_override": "override.jwt",
                "last_seen": "2026-09-28T08:00:00Z"
            }"#,
        )
        .expect("parses");
        assert_eq!(
            parsed,
            DesktopGateway {
                base_url: "http://127.0.0.1:41231".to_string(),
                password: Some("hunter2".to_string()),
                permissions_override: Some("override.jwt".to_string()),
            }
        );
    }

    /// A secret the desktop did not put in its record is not sent, under
    /// either spelling of "none".
    #[test]
    fn device_record_without_secrets_sends_none() {
        for text in [
            r#"{"port": 1988}"#,
            r#"{"port": 1988, "gateway_password": null, "permissions_override": null}"#,
        ] {
            assert_eq!(
                DesktopGateway::parse(text).expect("parses"),
                DesktopGateway {
                    base_url: "http://127.0.0.1:1988".to_string(),
                    password: None,
                    permissions_override: None,
                },
                "{text}"
            );
        }
    }

    /// A record that cannot name a gateway, or asks for a secret it does
    /// not hold, is an error rather than a guess.
    #[test]
    fn device_record_that_cannot_be_used_is_an_error() {
        for text in [
            "",
            "{",
            "[]",
            "null",
            r#"{"gateway_password": "hunter2"}"#,
            r#"{"port": null}"#,
            r#"{"port": "1988"}"#,
            r#"{"port": 0}"#,
            r#"{"port": -1}"#,
            r#"{"port": 65536}"#,
            r#"{"port": 1988.5}"#,
            r#"{"port": 1988, "gateway_password": ""}"#,
            r#"{"port": 1988, "gateway_password": 42}"#,
            r#"{"port": 1988, "permissions_override": ""}"#,
            r#"{"port": 1988, "permissions_override": false}"#,
        ] {
            assert!(
                DesktopGateway::parse(text).is_err(),
                "unexpectedly parsed {text:?}"
            );
        }
    }

    /// A secret never appears in the message about it.
    #[test]
    fn device_record_errors_do_not_leak_the_value() {
        let err = DesktopGateway::parse(r#"{"port": 1988, "gateway_password": 12345678}"#)
            .expect_err("not a string");
        assert!(!err.contains("12345678"), "{err}");
    }

    /// A directory of device records, with their modification times set
    /// relative to a fixed "now", so the newest-first choice is testable.
    struct DevicesDir {
        dir: PathBuf,
        now: SystemTime,
    }

    impl DevicesDir {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "latchkey-curl-router-devices-{}-{name}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self {
                dir,
                now: SystemTime::now(),
            }
        }

        /// A file last touched `age` before now.
        fn touch(&self, name: &str, age: Duration) -> PathBuf {
            let path = self.dir.join(name);
            std::fs::write(&path, "{}").unwrap();
            let file = std::fs::File::options().write(true).open(&path).unwrap();
            file.set_modified(self.now - age).unwrap();
            path
        }

        /// The desktops the router sees here, most recently touched
        /// first.
        fn list(&self) -> Vec<Desktop> {
            list_desktops(&self.dir, self.now)
        }

        /// Their device ids, in that order.
        fn device_ids(&self) -> Vec<String> {
            self.list()
                .into_iter()
                .map(|desktop| desktop.device_id)
                .collect()
        }
    }

    impl Drop for DevicesDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    const SECS: fn(u64) -> Duration = Duration::from_secs;

    /// The desktops come back most recently touched first: the one
    /// touching its record last is the one the user is at, whatever its
    /// name and whenever it first connected.
    #[test]
    fn the_most_recently_touched_record_comes_first() {
        let devices = DevicesDir::new("newest");
        devices.touch("aaa-first-connected.json", SECS(50));
        devices.touch("mmm-current.json", SECS(5));
        devices.touch("zzz-idle.json", SECS(120));
        assert_eq!(
            devices.device_ids(),
            ["mmm-current", "aaa-first-connected", "zzz-idle"]
        );
    }

    /// The record's name is the device id a rule names it by, and its
    /// path is where its gateway is read from.
    #[test]
    fn a_record_is_a_desktop_named_after_its_file() {
        let devices = DevicesDir::new("device-id");
        let path = devices.touch("mac-at-the-office.json", SECS(5));
        assert_eq!(
            devices.list(),
            [Desktop {
                device_id: "mac-at-the-office".to_string(),
                path,
                active: true,
            }]
        );
    }

    /// Only `<device_id>.json` files are records: a lock file, a backup
    /// or a subdirectory is not a desktop, however fresh. Neither is a
    /// record under a reserved name, which no rule could name.
    #[test]
    fn only_json_files_are_device_records() {
        let devices = DevicesDir::new("only-json");
        devices.touch("mac-1.json", SECS(30));
        devices.touch("mac-2.json.tmp", SECS(0));
        devices.touch("mac-2.json~", SECS(0));
        devices.touch("notes.txt", SECS(0));
        devices.touch("self.json", SECS(0));
        devices.touch("any-desktop.json", SECS(0));
        std::fs::create_dir(devices.dir.join("nested.json")).unwrap();
        assert_eq!(devices.device_ids(), ["mac-1"]);
    }

    /// Two records touched in the same instant order the same way every
    /// time, rather than by directory order.
    #[test]
    fn a_tie_on_the_modification_time_is_broken_by_name() {
        let devices = DevicesDir::new("tie");
        devices.touch("a.json", SECS(10));
        devices.touch("b.json", SECS(10));
        assert_eq!(devices.device_ids(), ["b", "a"]);
    }

    /// A desktop is connected as long as its keepalives keep arriving. One
    /// that stopped is still listed — the caller may name it outright —
    /// but no rule is satisfied by it.
    #[test]
    fn a_record_not_touched_recently_is_not_connected() {
        let devices = DevicesDir::new("active");
        devices.touch("here.json", SECS(0));
        devices.touch("keepalive-missed.json", DESKTOP_ACTIVE_WINDOW - SECS(1));
        devices.touch("gone.json", DESKTOP_ACTIVE_WINDOW + SECS(1));
        devices.touch("long-gone.json", SECS(30 * 24 * 3600));
        let active: Vec<(String, bool)> = devices
            .list()
            .into_iter()
            .map(|desktop| (desktop.device_id, desktop.active))
            .collect();
        assert_eq!(
            active,
            [
                ("here".to_string(), true),
                ("keepalive-missed".to_string(), true),
                ("gone".to_string(), false),
                ("long-gone".to_string(), false),
            ]
        );
    }

    /// No records, and no directory at all, are both "no desktop", which
    /// the rules — another desktop, or `self` — may well have an answer
    /// for. It is [`choose_desktop`] that decides whether that is an
    /// error.
    #[test]
    fn no_record_means_no_desktop() {
        let devices = DevicesDir::new("empty");
        assert_eq!(devices.list(), []);
        assert_eq!(
            list_desktops(&devices.dir.join("does-not-exist"), devices.now),
            []
        );
    }

    #[test]
    fn desktop_proxy_rewrite_refuses_an_invocation_that_does_not_end_in_a_url() {
        for tokens in [
            argv(&[]),
            argv(&["-H", "Accept: */*"]),
            argv(&["https://example.com/x", "-H", "Accept: */*"]),
            argv(&["ftp://example.com/x"]),
        ] {
            let result = rewrite_for_desktop_proxy(&tokens, &gateway_without_secrets());
            assert!(result.is_err(), "unexpectedly rewrote {tokens:?}");
        }
    }
}
