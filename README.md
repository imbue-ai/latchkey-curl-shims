# latchkey-curl-shims

The two `curl` binaries that sit between [latchkey](https://github.com/imbue-ai/latchkey)
and hosts behind Cloudflare's bot wall. Each release ships one tarball
per platform holding both, under the names everything that uses them
expects:

| binary | what it is |
|---|---|
| `latchkey-curl-router` | The `curl` that `LATCHKEY_CURL` points at. A small std-only Rust program: an invocation carrying the private `X-Imbue-Impersonate` header is rewritten (that header and any `User-Agent` dropped, `--compressed --noproxy '*' --impersonate <profile>` put in front) and handed to the impersonating curl next to it. An invocation carrying `X-Imbue-Desktop-Proxy` is rewritten onto the latchkey gateway on the user's own computer. Anything else goes to the system `curl` untouched. |
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

## Layout

```
src/main.rs            latchkey-curl-router, with its unit tests
tests/exec.rs          the exec path, against fake curl scripts
curl-impersonate/
  pin.env              the upstream tag and commit we build
  build.sh             upstream's CMake build plus our flags
  cc-static-cxx        the C compiler wrapper the musl legs need
.github/workflows/
  ci.yml               fmt, clippy, test on every push and PR
  release.yml          builds both binaries for six triples; publishes on a v* tag
```

```sh
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
3. Bump `DEFAULT_PROFILE` in `src/main.rs` if the point was a newer
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
