//! End-to-end check of the router's exec path, which the unit tests
//! cannot reach: a marked invocation execs the `curl-impersonate`
//! sibling with the impersonation flags in front and our headers
//! stripped, an unmarked one execs the `curl` on PATH untouched, and one
//! matching the desktop-proxy config execs that `curl` against the
//! gateway. Both targets are fake scripts that print their argv.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const ROUTER: &str = env!("CARGO_BIN_EXE_latchkey-curl-router");

fn write_fake(dir: &Path, name: &str, banner: &str) {
    let path = dir.join(name);
    fs::write(
        &path,
        format!("#!/bin/sh\necho \"{banner}\"\nprintf '%s\\n' \"$@\"\n"),
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// A fresh directory holding a copy of the router next to fake
/// `curl-impersonate` and `curl` scripts. The router resolves
/// its impersonator as a sibling of its own canonical path, so the copy
/// is what makes the fake visible to it.
struct Sandbox {
    dir: PathBuf,
}

impl Sandbox {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "latchkey-curl-router-exec-{}-{name}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::copy(ROUTER, dir.join("latchkey-curl-router")).unwrap();
        write_fake(&dir, "curl-impersonate", "impersonator");
        write_fake(&dir, "curl", "system-curl");
        Self { dir }
    }

    fn router(&self) -> Command {
        let mut command = Command::new(self.dir.join("latchkey-curl-router"));
        command.env_remove("DATALIB_IMPERSONATE_PROFILE");
        command.env_remove("LATCHKEY_DESKTOP_PROXY_CONFIG");
        command.env_remove("LATCHKEY_EXTENSION_DESKTOP_GATEWAY_URL");
        command.env_remove("LATCHKEY_GATEWAY_LISTEN_PASSWORD");
        command
    }

    /// A router whose PATH starts with the sandbox, so the fake `curl`
    /// is the system curl it finds.
    fn router_with_fake_system_curl(&self) -> Command {
        let path = std::env::var_os("PATH").unwrap_or_default();
        let mut dirs = vec![self.dir.clone()];
        dirs.extend(std::env::split_paths(&path));
        let mut command = self.router();
        command.env("PATH", std::env::join_paths(dirs).unwrap());
        command
    }

    fn write_desktop_proxy_config(&self, name: &str, json: &str) -> PathBuf {
        let path = self.dir.join(name);
        fs::write(&path, json).unwrap();
        path
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn run(command: &mut Command) -> Vec<String> {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "router failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect()
}

fn lines(tokens: &[&str]) -> Vec<String> {
    tokens.iter().map(|t| t.to_string()).collect()
}

#[test]
fn marked_invocation_execs_the_impersonator_with_the_explicit_profile() {
    let sandbox = Sandbox::new("explicit-profile");
    let got = run(sandbox
        .router()
        .env("DATALIB_IMPERSONATE_PROFILE", "chrome131")
        .args([
            "-sS",
            "-H",
            "User-Agent: curl/8.7.1",
            "-H",
            "X-Imbue-Impersonate: 1",
            "-H",
            "Accept: */*",
            "https://example.com/",
        ]));
    assert_eq!(
        got,
        lines(&[
            "impersonator",
            "--compressed",
            "--noproxy",
            "*",
            "--impersonate",
            "chrome131",
            "-sS",
            "-H",
            "Accept: */*",
            "https://example.com/",
        ])
    );
}

#[test]
fn marked_invocation_execs_the_impersonator_with_the_default_profile() {
    let sandbox = Sandbox::new("default-profile");
    let got = run(sandbox
        .router()
        .args(["-H", "X-Imbue-Impersonate;", "https://example.com/"]));
    assert_eq!(
        got,
        lines(&[
            "impersonator",
            "--compressed",
            "--noproxy",
            "*",
            "--impersonate",
            "chrome150",
            "https://example.com/",
        ])
    );
}

#[test]
fn unmarked_invocation_execs_the_curl_on_path_untouched() {
    let sandbox = Sandbox::new("system-curl");
    let got = run(sandbox.router_with_fake_system_curl().args([
        "-sS",
        "-H",
        "User-Agent: curl/8.7.1",
        "https://example.com/",
    ]));
    assert_eq!(
        got,
        lines(&[
            "system-curl",
            "-sS",
            "-H",
            "User-Agent: curl/8.7.1",
            "https://example.com/",
        ])
    );
}

#[test]
fn request_matching_the_desktop_proxy_config_execs_the_system_curl_against_the_gateway() {
    let sandbox = Sandbox::new("desktop-proxy");
    let config = sandbox.write_desktop_proxy_config(
        "desktop-proxy.json",
        r#"{"https://slack.com/api/": true, "https://claude.ai/": false}"#,
    );
    let got = run(sandbox
        .router_with_fake_system_curl()
        .env("LATCHKEY_DESKTOP_PROXY_CONFIG", &config)
        .env(
            "LATCHKEY_EXTENSION_DESKTOP_GATEWAY_URL",
            "http://127.0.0.1:1988/",
        )
        .env("LATCHKEY_GATEWAY_LISTEN_PASSWORD", "hunter2")
        .args([
            "-sS",
            "-H",
            "X-Imbue-Impersonate: 1",
            "https://slack.com/api/users.list",
        ]));
    assert_eq!(
        got,
        lines(&[
            "system-curl",
            "-H",
            "X-Latchkey-Gateway-No-Credentials: 1",
            "-H",
            "X-Latchkey-Gateway-Password: hunter2",
            "-sS",
            "-H",
            "X-Imbue-Impersonate: 1",
            "http://127.0.0.1:1988/gateway/https://slack.com/api/users.list",
        ])
    );

    // A URL under a falsy key, or under no key, is routed as if there
    // were no config: this one carries the marker, so it impersonates.
    for url in [
        "https://claude.ai/api/organizations",
        "https://example.com/",
    ] {
        let got = run(sandbox
            .router_with_fake_system_curl()
            .env("LATCHKEY_DESKTOP_PROXY_CONFIG", &config)
            .env(
                "LATCHKEY_EXTENSION_DESKTOP_GATEWAY_URL",
                "http://127.0.0.1:1988/",
            )
            .args(["-H", "X-Imbue-Impersonate: 1", url]));
        assert_eq!(got[0], "impersonator", "{url}: {got:?}");
    }
}

#[test]
fn desktop_proxy_config_that_cannot_be_used_is_an_error_not_a_direct_request() {
    let sandbox = Sandbox::new("desktop-proxy-errors");
    let malformed =
        sandbox.write_desktop_proxy_config("malformed.json", r#"["https://slack.com/api/"]"#);
    let missing = sandbox.dir.join("does-not-exist.json");
    let matched_without_gateway =
        sandbox.write_desktop_proxy_config("matched.json", r#"{"https://slack.com/api/": true}"#);
    for (config, needle) in [
        (malformed, "expected a JSON object"),
        (missing, "cannot read"),
        (
            matched_without_gateway,
            "LATCHKEY_EXTENSION_DESKTOP_GATEWAY_URL is not set",
        ),
    ] {
        let output = sandbox
            .router_with_fake_system_curl()
            .env("LATCHKEY_DESKTOP_PROXY_CONFIG", &config)
            .args(["https://slack.com/api/users.list"])
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "{config:?}: {stderr}");
        assert!(stderr.contains(needle), "{config:?}: {stderr}");
        assert!(
            output.stdout.is_empty(),
            "{config:?}: nothing should have been exec'd"
        );
    }
}
