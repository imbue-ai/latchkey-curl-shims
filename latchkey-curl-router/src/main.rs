//! `latchkey-curl-router` — a drop-in `curl` that routes each
//! invocation to one of two real implementations, and optionally to a
//! different destination. Impersonation is asked for by a private marker
//! header in the arguments; the desktop proxy is chosen by looking up the
//! service latchkey matched the request to, which it reports in another
//! header, in a config file named in the environment. It exists
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

use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

/// Name of the private routing marker header. Namespaced so it can't
/// collide with a header a caller legitimately wants to set or strip.
const MARKER_HEADER_NAME: &str = "X-Imbue-Impersonate";

/// Env var naming the JSON file that says which requests leave from the
/// user's own computer rather than from this machine. The file holds one
/// object; each key is a latchkey service name, and a request latchkey
/// matched to a service whose value is truthy (in the JavaScript sense: not
/// `false`, `0`, `""` or `null`) is routed through the desktop proxy. Unset
/// or empty: nothing is proxied. Set but unreadable or malformed: an error,
/// since the operator asked for routing they are not getting.
const DESKTOP_PROXY_CONFIG_ENV: &str = "LATCHKEY_DESKTOP_PROXY_CONFIG";

/// The header latchkey reports the matched service in, when it runs with
/// `LATCHKEY_DIAGNOSTIC_HEADERS=1`. Latchkey decides which service a URL
/// belongs to (by prefix or by pattern), so we take its answer rather than
/// matching URLs a second time. Latchkey puts its header ahead of the
/// caller's arguments and leaves a copy the caller supplied in place, so the
/// first occurrence is the one read. The header is for us alone: every
/// occurrence is dropped before curl runs.
const MATCHED_SERVICE_HEADER_NAME: &str = "X-Latchkey-Matched-Service";

/// Env var holding the base URL of the latchkey gateway on the user's
/// computer, as reachable from this machine (in minds, a reverse tunnel
/// into the VPS loopback). It is the variable minds already gives the
/// VPS gateway for its own desktop-forwarding extension; the gateway
/// runs us as a child, so we inherit it rather than needing one of our
/// own. Required whenever a request matches the desktop-proxy config; a
/// matched request with no gateway to send it to is an error, not a
/// silent direct request, since the operator asked for a different source
/// address on purpose.
const DESKTOP_PROXY_GATEWAY_URL_ENV: &str = "LATCHKEY_EXTENSION_DESKTOP_GATEWAY_URL";

/// Env var naming the file that holds the password to send as
/// [`GATEWAY_PASSWORD_HEADER_NAME`]: the desktop gateway's own listen
/// password. It is not the password the gateway running us listens with.
/// In minds that one is fixed by whichever of the user's computers created
/// the workspace, while the desktop's belongs to whichever computer is
/// connected now, and is rewritten in this file when that changes. It is
/// the variable minds already gives the VPS gateway's forwarding extension.
/// Unset or empty: no password header is sent, for a gateway that requires
/// none. Set but unreadable or empty: an error.
const DESKTOP_PROXY_GATEWAY_PASSWORD_FILE_ENV: &str =
    "LATCHKEY_EXTENSION_DESKTOP_GATEWAY_PASSWORD_FILE";

/// Env var naming the file that holds the JWT to send as
/// [`GATEWAY_PERMISSIONS_OVERRIDE_HEADER_NAME`]. The desktop gateway checks
/// a request against the permissions file this JWT names instead of its
/// default one, which in minds denies everything. Same source and same
/// unset/unreadable handling as [`DESKTOP_PROXY_GATEWAY_PASSWORD_FILE_ENV`].
const DESKTOP_PROXY_PERMISSIONS_OVERRIDE_FILE_ENV: &str =
    "LATCHKEY_EXTENSION_DESKTOP_GATEWAY_PERMISSIONS_OVERRIDE_FILE";

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

/// The latchkey services whose requests go through the desktop proxy: the
/// keys of the config file with a truthy value.
#[derive(Debug, Default, PartialEq, Eq)]
struct DesktopProxyRules {
    service_names: Vec<String>,
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
        Ok(Self {
            service_names: entries
                .into_iter()
                .filter(|(_, value)| is_truthy(value))
                .map(|(service_name, _)| service_name)
                .collect(),
        })
    }

    fn matches(&self, service_name: &str) -> bool {
        self.service_names.iter().any(|name| name == service_name)
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
    /// Rewritten onto the desktop latchkey gateway and run by the system
    /// curl.
    DesktopProxy,
    /// Handed to the Chrome-impersonating curl.
    Impersonate,
    /// Handed to the system curl.
    SystemCurl,
}

fn choose_route(argv: &[String], desktop_proxy: Option<&DesktopProxyRules>) -> Route {
    // The desktop proxy is decided first: a request that also carries the
    // impersonation marker must keep it for the desktop gateway's own
    // curl, which the impersonator here would strip.
    let proxied = header_value(argv, MATCHED_SERVICE_HEADER_NAME)
        .is_some_and(|service_name| desktop_proxy.is_some_and(|rules| rules.matches(service_name)));
    if proxied {
        Route::DesktopProxy
    } else if has_header(argv, MARKER_HEADER_NAME) {
        Route::Impersonate
    } else {
        Route::SystemCurl
    }
}

/// The desktop latchkey gateway a matched request is sent to, read from
/// the environment inherited from the gateway that runs us.
struct DesktopGateway {
    /// Base URL without a trailing slash, so the endpoint path can be
    /// appended directly.
    base_url: String,
    password: Option<String>,
    permissions_override: Option<String>,
}

impl DesktopGateway {
    fn from_env() -> Result<Self, String> {
        let base_url = match std::env::var(DESKTOP_PROXY_GATEWAY_URL_ENV) {
            Ok(value) if !value.is_empty() => value,
            _ => {
                return Err(format!(
                    "request matches {DESKTOP_PROXY_CONFIG_ENV} but \
                     {DESKTOP_PROXY_GATEWAY_URL_ENV} is not set"
                ))
            }
        };
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            password: read_secret_file(DESKTOP_PROXY_GATEWAY_PASSWORD_FILE_ENV)?,
            permissions_override: read_secret_file(DESKTOP_PROXY_PERMISSIONS_OVERRIDE_FILE_ENV)?,
        })
    }
}

/// The trimmed contents of the file `env_name` names. `None` when the
/// variable is unset or empty; an error when it names a file that cannot
/// be read or holds nothing, since the operator asked for a secret to be
/// sent and the desktop gateway would refuse the request without it.
fn read_secret_file(env_name: &str) -> Result<Option<String>, String> {
    let path = match std::env::var(env_name) {
        Ok(value) if !value.is_empty() => value,
        _ => return Ok(None),
    };
    let content = std::fs::read_to_string(&path)
        .map_err(|err| format!("cannot read {env_name}={path}: {err}"))?;
    let secret = content.trim();
    if secret.is_empty() {
        return Err(format!("{env_name}={path} is empty"));
    }
    Ok(Some(secret.to_string()))
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

    let desktop_proxy = DesktopProxyRules::from_env().unwrap_or_else(|message| die(message));
    let route = choose_route(&argv, desktop_proxy.as_ref());
    // Read above, and of no use to anyone after us: not to the desktop
    // gateway, which would forward it, nor to the third party.
    argv = without_headers(&argv, &[MATCHED_SERVICE_HEADER_NAME]);
    let target = match route {
        Route::DesktopProxy => {
            let gateway = DesktopGateway::from_env().unwrap_or_else(|message| die(message));
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

    fn rules(service_names: &[&str]) -> DesktopProxyRules {
        DesktopProxyRules {
            service_names: service_names.iter().map(|n| n.to_string()).collect(),
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

    /// Only a key with a truthy value is a rule; truthiness is
    /// JavaScript's, since the file is written by JavaScript.
    #[test]
    fn config_keeps_the_keys_with_truthy_values() {
        let parsed = DesktopProxyRules::parse(
            r#"{
                "slack": true,
                "github": 1,
                "gitlab": "yes",
                "on-a": [],
                "on-b": {},
                "on-c": 0.5,
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
            rules(&["github", "gitlab", "on-a", "on-b", "on-c", "slack"])
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

    /// A service name is matched whole and as written: latchkey's names
    /// are case-sensitive identifiers, and one may be a prefix of another
    /// (`fastmail`, `fastmail-dav`).
    #[test]
    fn a_service_name_matches_exactly() {
        let rules = rules(&["fastmail", "google-docs"]);
        for service_name in ["fastmail", "google-docs"] {
            assert!(rules.matches(service_name), "{service_name:?} should match");
        }
        for service_name in [
            "fastmail-dav",
            "fast",
            "Fastmail",
            "google",
            "",
            " fastmail",
        ] {
            assert!(
                !rules.matches(service_name),
                "{service_name:?} should not match"
            );
        }
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

    /// A matched request goes to the desktop proxy even when it also
    /// carries the impersonation marker, so the marker reaches the
    /// desktop gateway's own curl intact.
    #[test]
    fn desktop_proxy_is_decided_before_impersonation() {
        let slack = rules(&["slack"]);
        assert_eq!(
            choose_route(&gateway_invocation("slack"), Some(&slack)),
            Route::DesktopProxy
        );
        assert_eq!(
            choose_route(&gateway_invocation("slack"), None),
            Route::Impersonate
        );
        assert_eq!(
            choose_route(&gateway_invocation("slack"), Some(&rules(&["claude-ai"]))),
            Route::Impersonate
        );
        assert_eq!(
            choose_route(
                &argv(&[
                    "-H",
                    "X-Latchkey-Matched-Service: slack",
                    "https://slack.com/api/users.list"
                ]),
                Some(&slack)
            ),
            Route::DesktopProxy
        );
    }

    /// The decision is latchkey's statement of the service and nothing
    /// else: a URL that happens to belong to a routed service is not
    /// proxied when latchkey did not say so, which is the case for a
    /// request it injected nothing into.
    #[test]
    fn only_the_matched_service_header_decides() {
        let slack = rules(&["slack"]);
        for tokens in [
            argv(&["--version"]),
            argv(&[]),
            argv(&["-H", "Accept: */*", "https://slack.com/api/users.list"]),
            argv(&[
                "-H",
                "X-Latchkey-Matched-Service: github",
                "https://slack.com/api/users.list",
            ]),
            argv(&[
                "-H",
                "X-Latchkey-Matched-Service;",
                "https://slack.com/api/users.list",
            ]),
            argv(&[
                "-o",
                "X-Latchkey-Matched-Service: slack",
                "https://slack.com/api/users.list",
            ]),
        ] {
            assert_eq!(
                choose_route(&tokens, Some(&slack)),
                Route::SystemCurl,
                "{tokens:?}"
            );
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
