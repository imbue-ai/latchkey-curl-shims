//! End-to-end check of the router's exec path, which the unit tests
//! cannot reach: a marked invocation execs the `curl-impersonate`
//! sibling with the impersonation flags in front and our headers
//! stripped, and an unmarked one execs the `curl` on PATH untouched. Both
//! targets are fake scripts that print their argv.

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
        command
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
    let path = std::env::var_os("PATH").unwrap_or_default();
    let mut dirs = vec![sandbox.dir.clone()];
    dirs.extend(std::env::split_paths(&path));
    let got = run(sandbox
        .router()
        .env("PATH", std::env::join_paths(dirs).unwrap())
        .args([
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
