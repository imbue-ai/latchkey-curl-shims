# latchkey-curl-shims

The two `curl` binaries that sit between [latchkey](https://github.com/imbue-ai/latchkey)
and hosts behind Cloudflare's bot wall. Each release ships one tarball
per platform holding both, under the names everything that uses them
expects:

| binary | what it is |
|---|---|
| `latchkey-curl-router` | The `curl` that `LATCHKEY_CURL` points at. A small Rust program: an invocation for a service listed in the desktop-proxy config (below) is rewritten onto the latchkey gateway on the user's own computer. Otherwise, an invocation carrying the private `X-Imbue-Impersonate` header is rewritten (that header and any `User-Agent` dropped, `--compressed --noproxy '*' --impersonate <profile>` put in front) and handed to the impersonating curl next to it. Anything else goes to the system `curl` untouched. |
| `curl-impersonate` | Upstream [curl-impersonate](https://github.com/lexiforest/curl-impersonate), unmodified: a curl with a patched BoringSSL and a built-in `--impersonate <browser>` flag that presents Chrome's TLS and HTTP/2 fingerprint. **On its own it does not impersonate**: without `--impersonate` it is a plain curl 8.x and gets the same `403` a stock curl does. The router is what adds the flag. |

Some of the hosts datalib mirrors, `claude.ai` and `chatgpt.com` today,
reject any client whose TLS handshake does not look like a browser's. A
stock `curl` gets a `403` with `cf-mitigated: challenge`, whatever
cookies it carries. Requests to those hosts go out through the
impersonating curl instead.

Only the router understands the marker headers, so **point
`LATCHKEY_CURL` at the router, never at the impersonator directly.**
The router finds the impersonator as a sibling of its own canonical
path, so the two must be installed in the same directory. A hand-run
impersonating request looks like this:

```sh
LATCHKEY_CURL=/path/to/latchkey-curl-router \
    latchkey curl -sS -H 'X-Imbue-Impersonate: 1' https://claude.ai/api/organizations
```

The `--impersonate` target is `DATALIB_IMPERSONATE_PROFILE`, default
`chrome150`. It is passed through as-is; a name curl-impersonate does
not know fails the request with exit 43 and a message naming a valid
one.

## The desktop proxy

A request can be made to leave from the user's own computer instead of
the machine the router runs on: the router hands it to the system curl,
addressed to the `/gateway/<url>` endpoint of the latchkey gateway on
that computer, with everything else in the invocation kept as it was.
Which requests get this is a JSON file, and four environment variables
say where things are:

| variable | meaning |
|---|---|
| `LATCHKEY_DESKTOP_PROXY_CONFIG` | Path of the config file. Unset or empty: nothing is proxied. Set but missing, unreadable or not a JSON object: every invocation fails with exit 2, since routing was asked for and is not happening. |
| `LATCHKEY_EXTENSION_DESKTOP_GATEWAY_URL` | Base URL of the desktop gateway as reachable from this machine. Required once a request matches. |
| `LATCHKEY_EXTENSION_DESKTOP_GATEWAY_PASSWORD_FILE` | Path of a file holding the desktop gateway's listen password, sent as `X-Latchkey-Gateway-Password`. Unset or empty: no password is sent. Set but unreadable or empty: exit 2. |
| `LATCHKEY_EXTENSION_DESKTOP_GATEWAY_PERMISSIONS_OVERRIDE_FILE` | Path of a file holding a permissions-override JWT, sent as `X-Latchkey-Gateway-Permissions-Override`, so the desktop gateway checks the request against the permissions file the JWT names instead of its default one. Same unset and unreadable handling as the password file. |

All but the first are the variables minds already gives the VPS gateway
for its desktop-forwarding extension; the gateway runs the router as a
child, so the router inherits them. The secrets are files read on every
invocation because they belong to whichever of the user's computers is
connected, and change when the user moves to another one. The password
the VPS gateway itself listens with (`LATCHKEY_GATEWAY_LISTEN_PASSWORD`)
is a different one and is not used.

The request is sent with `X-Latchkey-Gateway-No-Credentials: 1`. The
desktop gateway then injects nothing, since the gateway that ran the
router already did, but it still runs its permission check, and it
refuses the header with a `403` unless it runs with
`LATCHKEY_PASSTHROUGH_UNKNOWN`. Its check sees no `account` metadata, so
a rule allowing these requests cannot be an account-scoped one.

The file holds one object. Each key is a latchkey service name and each
value is anything; a request is proxied when latchkey matched it to a
service whose value is truthy in the JavaScript sense (not `false`, `0`,
`""` or `null`).

```json
{
  "slack": true,
  "github": false
}
```

The router does not match URLs itself. Latchkey decides which service a
URL belongs to, by prefix or by pattern, and reports it in the
`X-Latchkey-Matched-Service` header when it runs with
`LATCHKEY_POPULATE_HEADERS_FOR_CURL=X-Latchkey-Matched-Service`. Without
that setting there is no header and nothing is proxied. Latchkey sets
the header only for a request it injected credentials into, and removes
any copy the caller supplied. The router drops the header from every
invocation, whichever route it takes, so it reaches neither the desktop
gateway nor the third party.

The rewritten request is addressed to the last argument of the
invocation, which is where `latchkey curl` and the gateway both put the
URL. The proxy decision comes before the impersonation one: a proxied
request keeps its `X-Imbue-Impersonate` header for the desktop gateway's
own router.

## Layout

```
latchkey-curl-router/  the router, a Cargo crate
  src/main.rs          the program, with its unit tests
  tests/exec.rs        the exec path, against fake curl scripts
curl-impersonate/
  pin.env              the upstream tag and commit we build
  build.sh             upstream's CMake build plus our flags
  cc-static-cxx        the C compiler wrapper the musl legs need
.github/workflows/
  ci.yml               fmt, clippy, test on every push and PR
  release.yml          builds both binaries for six triples; publishes on a v* tag
```

```sh
cd latchkey-curl-router
cargo test                     # the router's unit and exec tests
cargo build --release          # target/release/latchkey-curl-router
```

## Where the impersonating curl comes from

**We build it from source, in our own CI, and pin what we built.**
Upstream publishes prebuilt binaries, and they are fine, but there is
no attestation tying those bytes to the source, and this binary is the
last process to hold a user's session cookie before it leaves the
machine. Building it ourselves makes every byte traceable to a commit
we named and a run whose log we own. It is also cheap: about two
minutes per leg, from a clean tree, with distro compilers.

The pieces, in the order they run:

1. `curl-impersonate/pin.env` names the upstream tag **and commit**
   (the tag alone can move).
2. `release.yml` clones that commit on each of six runners and runs
   `curl-impersonate/build.sh`: upstream's CMake build plus our flags.
   The musl legs run the same script inside an `alpine:3.21` container.
   Upstream's CMake fetches curl, BoringSSL, nghttp2, nghttp3, ngtcp2,
   brotli, zstd and zlib by URL **with a pinned sha256 each**, so
   nothing in the build is unpinned.
3. The same job builds the router with cargo and stages both binaries,
   with the license notices of everything linked into the impersonator,
   as `latchkey-curl-shims-<triple>.tar.gz`. On a `v*` tag the tarballs are
   published as a GitHub release with a `SHA256SUMS`; a
   `workflow_dispatch` run only uploads them as workflow artifacts.

Every tarball, and the two binaries inside it, carries a build
provenance attestation: a [SLSA](https://slsa.dev) statement that the
job signs through Sigstore with its GitHub OIDC identity and that
GitHub stores with this repo. It ties the file's digest to this
workflow, the commit it ran at and the run that produced it, so a
tarball someone hands you can be checked against GitHub rather than
trusted:

```sh
gh attestation verify latchkey-curl-shims-aarch64-apple-darwin.tar.gz -R imbue-ai/latchkey-curl-shims
```

The same command works on an extracted `latchkey-curl-router` or
`curl-impersonate`. The build job verifies its own attestations right
after signing and the publish job verifies every tarball again before
creating the release, so a release exists only if the check passes.
Each tarball's `SOURCE` file names this repo's commit and the upstream
curl-impersonate commit as plain text, for readers without `gh`.

The six triples: `aarch64-apple-darwin`, `x86_64-apple-darwin`,
`x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`,
`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`. The musl
tarballs are fully static and run on any Linux.

`build.sh` runs by hand too (`build.sh <triple> <upstream checkout> <out
dir>`; a mac leg takes about two minutes and needs cmake, ninja and go).

Two build choices worth knowing about:

- **IDN is off** (`-DUSE_LIBIDN2=OFF`). We never fetch an
  internationalized hostname, and libidn2 is LGPL, the one component in
  upstream's own Linux builds that would have kept an MIT release from
  being clean.
- **The musl legs use a wrapper C compiler**,
  `curl-impersonate/cc-static-cxx`, which appends `-lstdc++` to link
  lines. BoringSSL is C++, curl is C, and upstream's CMake puts the C++
  runtime *before* the objects: fine for a shared libstdc++, fatal for
  a static one. Upstream builds its musl legs with zig, whose driver
  orders the runtime itself; we prefer the distro gcc and order it in
  the wrapper.

Linux binaries read the host's CA store (`/etc/ssl/certs`), the way the
system curl does; `SSL_CERT_FILE` overrides it. macOS binaries use the
system trust store through Apple's Security framework.

**The musl legs are reproducible.** The `aarch64-unknown-linux-musl`
binary of upstream v2.2.2, built on a GitHub arm64 runner, is
byte-for-byte identical to one built the same way in Docker on a Mac.
So the pin is checkable by anyone, not only trusted:

```sh
git clone --depth 1 --branch v2.2.2 https://github.com/lexiforest/curl-impersonate.git upstream
docker run --rm -v "$PWD:/work" -w /work -e UPSTREAM_COMMIT=<commit from pin.env> alpine:3.21 sh -c '
    apk add --no-cache bash ninja cmake make patch linux-headers build-base perl go file tar >/dev/null
    curl-impersonate/build.sh aarch64-unknown-linux-musl upstream out'
sha256sum out/curl-impersonate-aarch64-unknown-linux-musl/curl-impersonate   # compare with the release's
```

The Alpine image tag is what pins the compiler; a new `alpine:3.21`
point release could move the bytes. The darwin and linux-gnu legs were
not checked for this and are not expected to reproduce (Xcode and Ubuntu
toolchains move with the runner image).

## Bumping the upstream pin

Chrome moves, and a stale profile eventually stops being camouflage.
When upstream tags a version with a newer `chromeNNN`:

1. **Read the delta.** The whole difference between this binary and
   stock curl + BoringSSL is `patches/` in the upstream repo. Diff those
   between the old and new tags. `boringssl.patch` is the one to read
   line by line: it is under a thousand lines, almost all in `ssl/`
   (extension order, GREASE, cipher lists), and anything under `crypto/`
   deserves a hard look. `curl.patch` is larger, but most of it is the
   profile table in `lib/impersonate.c`.
2. Edit `curl-impersonate/pin.env`: new `UPSTREAM_TAG` and
   `UPSTREAM_COMMIT`.
3. Bump `DEFAULT_PROFILE` in `latchkey-curl-router/src/main.rs` if the point was a newer
   Chrome, and the JA4 in `release.yml`'s smoke test: load
   `https://tls.browserleaks.com/json` in Chrome and compare with what
   `curl-impersonate --impersonate chromeNNN` gets from the
   same URL. JA4 is stable across handshakes (JA3 is not, because Chrome
   shuffles extension order); the `akamai_hash` is the HTTP/2
   fingerprint and should match too.
4. Run `release.yml` by hand against the branch (`gh workflow run
   release.yml --ref <branch>`) and check every leg builds.
5. Bump the version in `Cargo.toml`, merge, and tag `v<version>`. The
   release job refuses a tag that disagrees with `Cargo.toml` and a
   release that already exists.

A change to the router alone is released the same way, from step 5.
