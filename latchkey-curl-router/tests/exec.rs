//! End-to-end check of the router's exec path, which the unit tests
//! cannot reach: a marked invocation execs the `curl-impersonate`
//! sibling with the impersonation flags in front and our headers
//! stripped, an unmarked one execs the `curl` on PATH untouched, and one
//! matching the desktop-proxy config execs that `curl` against the
//! gateway of the most recently active desktop. Both targets are fake
//! scripts that print their argv.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

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
        command.env_remove("LATCHKEY_GATEWAY_LISTEN_PASSWORD");
        // Never the real one: a desktop connected to the machine running
        // the tests must not be where a test request goes.
        command.env("LATCHKEY_EXTENSION_DEVICES_DIR", self.devices_dir());
        command
    }

    /// The sandbox's own device-records directory, created on first use.
    fn devices_dir(&self) -> PathBuf {
        let dir = self.dir.join("devices");
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A device record for a desktop that last sent a keepalive `age`
    /// seconds ago.
    fn write_device_record(&self, device_id: &str, json: &str, age: Duration) -> PathBuf {
        let path = self.devices_dir().join(format!("{device_id}.json"));
        fs::write(&path, json).unwrap();
        fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(SystemTime::now() - age)
            .unwrap();
        path
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

    fn write_file(&self, name: &str, content: &str) -> PathBuf {
        let path = self.dir.join(name);
        fs::write(&path, content).unwrap();
        path
    }

    fn write_desktop_proxy_config(&self, name: &str, json: &str) -> PathBuf {
        self.write_file(name, json)
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
fn unmarked_invocation_execs_the_curl_on_path_without_the_matched_service_header() {
    let sandbox = Sandbox::new("system-curl");
    let got = run(sandbox.router_with_fake_system_curl().args([
        "-H",
        "X-Latchkey-Matched-Service: slack",
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
        r#"{"slack": true, "claude-ai": false}"#,
    );
    // Two desktops are connected; the one that sent a keepalive most
    // recently is where the request goes, secrets and all.
    sandbox.write_device_record(
        "mac-at-the-office",
        r#"{"port": 40001, "gateway_password": "office", "permissions_override": "office.jwt"}"#,
        Duration::from_secs(90),
    );
    sandbox.write_device_record(
        "laptop-at-home",
        r#"{"port": 40002, "gateway_password": "hunter2", "permissions_override": "override.jwt"}"#,
        Duration::from_secs(20),
    );
    let got = run(sandbox
        .router_with_fake_system_curl()
        .env("LATCHKEY_DESKTOP_PROXY_CONFIG", &config)
        // The password the gateway running the router listens with is not
        // the desktop's, and must not be the one sent.
        .env("LATCHKEY_GATEWAY_LISTEN_PASSWORD", "the-machines-own")
        .args([
            "-H",
            "X-Latchkey-Matched-Service: slack",
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
            "-H",
            "X-Latchkey-Gateway-Permissions-Override: override.jwt",
            "-sS",
            "-H",
            "X-Imbue-Impersonate: 1",
            "http://127.0.0.1:40002/gateway/https://slack.com/api/users.list",
        ])
    );

    // A desktop whose record asks for no secrets gets none, and how long
    // ago it was last heard from does not matter: once the laptop's record
    // is gone, the office desktop is the newest, however old.
    fs::remove_file(sandbox.devices_dir().join("laptop-at-home.json")).unwrap();
    sandbox.write_device_record(
        "mac-at-the-office",
        r#"{"port": 40001, "gateway_password": null}"#,
        Duration::from_secs(3 * 24 * 3600),
    );
    let got = run(sandbox
        .router_with_fake_system_curl()
        .env("LATCHKEY_DESKTOP_PROXY_CONFIG", &config)
        .args([
            "-H",
            "X-Latchkey-Matched-Service: slack",
            "https://slack.com/api/users.list",
        ]));
    assert_eq!(
        got,
        lines(&[
            "system-curl",
            "-H",
            "X-Latchkey-Gateway-No-Credentials: 1",
            "http://127.0.0.1:40001/gateway/https://slack.com/api/users.list",
        ])
    );

    // A service under a falsy key, a service under no key, and a request
    // latchkey matched to no service are routed as if there were no config:
    // these carry the marker, so they impersonate. Latchkey's header is
    // dropped on that route too.
    for matched_service_header in [
        Some("X-Latchkey-Matched-Service: claude-ai"),
        Some("X-Latchkey-Matched-Service: github"),
        None,
    ] {
        let mut command = sandbox.router_with_fake_system_curl();
        command.env("LATCHKEY_DESKTOP_PROXY_CONFIG", &config);
        if let Some(header) = matched_service_header {
            command.args(["-H", header]);
        }
        let got = run(command.args([
            "-H",
            "X-Imbue-Impersonate: 1",
            "https://slack.com/api/users.list",
        ]));
        assert_eq!(
            got[0], "impersonator",
            "{matched_service_header:?}: {got:?}"
        );
        assert!(
            !got.iter()
                .any(|line| line.contains("X-Latchkey-Matched-Service")),
            "{matched_service_header:?}: {got:?}"
        );
    }
}

#[test]
fn desktop_proxy_config_that_cannot_be_used_is_an_error_not_a_direct_request() {
    let sandbox = Sandbox::new("desktop-proxy-errors");
    let malformed = sandbox.write_desktop_proxy_config("malformed.json", r#"["slack"]"#);
    let missing = sandbox.dir.join("does-not-exist.json");
    for (config, needle) in [
        (malformed, "expected a JSON object"),
        (missing, "cannot read"),
    ] {
        let output = sandbox
            .router_with_fake_system_curl()
            .env("LATCHKEY_DESKTOP_PROXY_CONFIG", &config)
            .args([
                "-H",
                "X-Latchkey-Matched-Service: slack",
                "https://slack.com/api/users.list",
            ])
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

/// A matched request with no desktop to send it to fails, whichever way
/// the desktop is missing: no records at all, no directory, or a record
/// that cannot name a gateway or hold its secret.
#[test]
fn desktop_that_cannot_be_reached_is_an_error_not_a_direct_request() {
    /// One way for the desktop to be missing: the record to write (with
    /// the age of its last keepalive), an env var to set, and what the
    /// router must say about it.
    struct Case {
        name: &'static str,
        record: Option<(&'static str, u64)>,
        env: Option<(&'static str, String)>,
        needle: &'static str,
    }
    let sandbox = Sandbox::new("desktop-errors");
    let config = sandbox.write_desktop_proxy_config("matched.json", r#"{"slack": true}"#);
    let no_such_dir = sandbox.dir.join("no-such-devices");
    let cases = [
        Case {
            name: "no records",
            record: None,
            env: None,
            needle: "no desktop is connected",
        },
        Case {
            name: "no directory",
            record: None,
            env: Some((
                "LATCHKEY_EXTENSION_DEVICES_DIR",
                no_such_dir.to_str().unwrap().to_string(),
            )),
            needle: "no desktop is connected",
        },
        Case {
            name: "record without a port",
            record: Some((r#"{"gateway_password": "x"}"#, 10)),
            env: None,
            needle: "missing field `port`",
        },
        Case {
            name: "record that is not JSON",
            record: Some(("{", 10)),
            env: None,
            needle: "not a device record",
        },
        Case {
            name: "record with an empty password",
            record: Some((r#"{"port": 40001, "gateway_password": ""}"#, 10)),
            env: None,
            needle: "\"gateway_password\"",
        },
        Case {
            name: "record with a non-string permissions override",
            record: Some((r#"{"port": 40001, "permissions_override": 7}"#, 10)),
            env: None,
            needle: "\"permissions_override\"",
        },
    ];
    for case in cases {
        if let Some((json, age)) = case.record {
            sandbox.write_device_record("desktop", json, Duration::from_secs(age));
        }
        let mut command = sandbox.router_with_fake_system_curl();
        if let Some((name, value)) = case.env {
            command.env(name, value);
        }
        let output = command
            .env("LATCHKEY_DESKTOP_PROXY_CONFIG", &config)
            .args([
                "-H",
                "X-Latchkey-Matched-Service: slack",
                "https://slack.com/api/users.list",
            ])
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        let name = case.name;
        assert_eq!(output.status.code(), Some(2), "{name}: {stderr}");
        assert!(stderr.contains(case.needle), "{name}: {stderr}");
        assert!(
            output.stdout.is_empty(),
            "{name}: nothing should have been exec'd"
        );
        let _ = fs::remove_dir_all(sandbox.devices_dir());
    }
}
