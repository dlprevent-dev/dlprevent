# Dependencies

Every package this project pulls in directly, grouped by the artifact that
ships it. Purpose: before updating an app, see which packages that update
touches.

Snapshot: 2026-09-11, workspace version 0.1.3. Declared = the range in the
manifest, Resolved = what `Cargo.lock` / `package-lock.json` currently pin.
Regenerate with the commands at the bottom.

Transitive packages are not listed: 384 crates in `Cargo.lock`, 85 entries in
`apps/web/package-lock.json`.

## Artifacts

| Artifact | Manifest | Runs on |
|---|---|---|
| `deelpe` (CLI/agent) | `crates/deelpe/Cargo.toml` | macOS, Linux |
| `deelpe-winagent` (service) | `crates/deelpe-winagent/Cargo.toml` | Windows |
| `deelpe-server` (central) | `crates/deelpe-server/Cargo.toml` | Linux / Docker |
| `deelpe-web` (dashboard UI) | `apps/web/package.json` | compiled into the server binary |
| `DeelpeBar` (menu bar) | `apps/macos/DeelpeBar/Package.swift` | macOS 14+ |

Two crates are libraries only, shared by the agents and the server:
`deelpe-core` and `deelpe-sensors`.

## Workspace-wide (`Cargo.toml`, `[workspace.dependencies]`)

Bumping one of these hits **every** crate that lists it — see the reverse
index below.

| Package | Declared | Resolved | Features |
|---|---|---|---|
| anyhow | 1 | 1.0.104 | |
| serde | 1 | 1.0.229 | derive |
| serde_json | 1 | 1.0.151 | |
| thiserror | 1 | 1.0.69 | |
| tokio | 1 | 1.53.1 | rt-multi-thread, macros, process, io-util, net, time, sync, signal |
| tracing | 0.1 | 0.1.44 | |
| tracing-subscriber | 0.3 | 0.3.23 | env-filter |
| chrono | 0.4 | 0.4.45 | serde |

Rust toolchain: `stable` (`rust-toolchain.toml`), MSRV `1.90`, edition 2021.

## deelpe-core (library — feeds all three agents and the server)

Workspace: anyhow, serde, serde_json, thiserror, chrono, tracing.

Behind the `net` feature (agents only; the server does not enable it):

| Package | Declared | Resolved | Features |
|---|---|---|---|
| reqwest | 0.13 | 0.13.4 | rustls, json (no default) |
| rcgen | 0.14 | 0.14.10 | ring, pem (no default) |
| rustls-pemfile | 2 | 2.2.0 | |
| sha2 | 0.11.0 | 0.11.0 | |
| x509-parser | 0.18 | 0.18.1 | |
| time | 0.3 | 0.3.55 | |
| tracing-subscriber | 0.3 | 0.3.23 | |

## deelpe-sensors (library — both agents)

Workspace: anyhow, serde_json, tokio, tracing, chrono. Plus `deelpe-core`.

| Package | Declared | Resolved | Target |
|---|---|---|---|
| async-trait | 0.1 | 0.1.92 | all |
| windows | 0.62.2 | 0.62.2 | `cfg(windows)` |

`windows` features here: Win32_Foundation, Win32_System_Diagnostics_Etw,
Win32_System_Diagnostics_ToolHelp, Win32_System_Time, Win32_System_Threading,
Win32_Storage_FileSystem, Win32_Security, Win32_Security_WinTrust,
Win32_Security_Cryptography.

## deelpe (CLI/agent, macOS + Linux)

Workspace: anyhow, serde, serde_json, tokio, tracing, tracing-subscriber,
chrono. Plus `deelpe-core` (feature `net`) and `deelpe-sensors`.

| Package | Declared | Resolved | Note |
|---|---|---|---|
| clap | 4 | 4.6.6 | derive |
| owo-colors | 4 | 4.4.0 | terminal colour |
| comfy-table | 7 | 7.2.2 | terminal tables |
| libc | 0.2 | 0.2.189 | |
| sha2 | 0.11.0 | 0.11.0 | |
| tempfile | 3 | — | dev-dependency only |

## deelpe-winagent (Windows service)

Workspace: anyhow, serde, serde_json, tokio, tracing, chrono. Plus
`deelpe-core` (feature `net`) and `deelpe-sensors`.

| Package | Declared | Resolved | Target |
|---|---|---|---|
| clap | 4 | 4.6.6 | all |
| quick-xml | 0.42 | 0.42.0 | all |
| sha2 | 0.11 | 0.11.0 | all |
| windows | 0.62.2 | 0.62.2 | `x86_64-pc-windows-gnu` |
| windows-service | 0.8.1 | 0.8.1 | `x86_64-pc-windows-gnu` |

`windows` features here (different set than deelpe-sensors):
Win32_Foundation, Win32_Security, Win32_Security_Authorization,
Win32_System_EventLog, Win32_System_Threading, Win32_System_SystemServices,
Win32_System_SystemInformation, Win32_Security_Authentication_Identity,
Win32_NetworkManagement_NetManagement, Win32_Storage_FileSystem,
Win32_Storage_InstallableFileSystems, Win32_System_Pipes,
Win32_System_Registry, Win32_NetworkManagement_WindowsFilteringPlatform,
Win32_NetworkManagement_IpHelper, Win32_System_Rpc.

After touching this crate or `crates/deelpe-sensors/src/windows`, run
`cargo win` — a host `cargo check` does not typecheck these modules.
Build toolchain: mingw-w64 plus the `x86_64-pc-windows-gnu` rustup target.

## deelpe-server (central server)

Workspace: anyhow, serde, serde_json, tokio, tracing, tracing-subscriber,
chrono. Plus `deelpe-core` (without `net`).

| Package | Declared | Resolved | What it carries |
|---|---|---|---|
| axum | 0.8 | 0.8.9 | HTTP (macros, json, http1) |
| hyper | 1 | 1.11.1 | server, http1 |
| hyper-util | 0.1 | 0.1.20 | server, server-auto, service, tokio, http1 |
| tower | 0.5 | 0.5.3 | util |
| tower-http | 0.7 | 0.7.1 | cors, trace |
| sqlx | 0.9 | 0.9.0 | Postgres (runtime-tokio, tls-rustls, uuid, chrono, json, migrate, macros) |
| rustls | 0.23 | 0.23.43 | ring, std, tls12 |
| tokio-rustls | 0.26 | 0.26.5 | ring |
| rustls-pemfile | 2 | 2.2.0 | |
| rustls-pki-types | 1 | 1.15.1 | std |
| rcgen | 0.14 | 0.14.10 | x509-parser |
| x509-parser | 0.18 | 0.18.1 | agent certificates |
| ring | 0.17 | 0.17.14 | ed25519 release signatures |
| argon2 | 0.6 | 0.6.0 | password hashes (getrandom) |
| hmac | 0.13 | 0.13.0 | TOTP (RFC 6238) |
| sha1 | 0.11 | 0.11.0 | TOTP |
| sha2 | 0.11 | 0.11.0 | |
| qrcode | 0.14 | 0.14.1 | svg, no default |
| webauthn-rs | 0.5 | 0.5.5 | passkeys — **links OpenSSL dynamically** |
| reqwest | 0.13 | 0.13.4 | AbuseIPDB (rustls-no-provider, json) |
| lettre | 0.11 | 0.11.23 | SMTP (smtp-transport, builder, tokio1, tokio1-rustls-tls, hostname) |
| rust-embed | 8 | 8.12.0 | serves the built dashboard |
| mime_guess | 2 | 2.0.5 | |
| uuid | 1 | 1.26.0 | v4, serde |
| rand | 0.10 | 0.10.2 | |
| clap | 4 | 4.6.6 | derive, env |
| tokio-util | 0.7 | 0.7.19 | |
| time | 0.3 | 0.3.55 | |
| chrono-tz | 0.10.4 | 0.10.4 | std, no default |

Two crypto constraints worth keeping in mind when bumping:

- `reqwest` uses `rustls-no-provider`; the provider (ring) is installed in
  `main.rs`. The full feature set would drag in aws-lc-rs and the build image
  would then need cmake.
- `webauthn-rs` is the only dynamic OpenSSL link — the Docker image and the
  `.deb` need `libssl3t64` / `libssl3` for it.

## deelpe-web (dashboard UI)

Compiled into the server binary via `rust-embed`, so a UI update means
rebuilding the server image — see the Docker build below.

| Package | Declared | Resolved | Kind |
|---|---|---|---|
| svelte | ^5.57.0 | 5.57.0 | devDependency |
| @sveltejs/vite-plugin-svelte | ^7.3.0 | 7.3.0 | devDependency |
| vite | ^8.2.2 | 8.2.2 | devDependency |
| typescript | ^7.0.2 | 7.0.2 | devDependency |

No runtime dependencies. Tests run on the Node built-in test runner
(`node --test`), no framework.

## DeelpeBar (macOS menu bar app)

`Package.swift`, swift-tools-version 5.9, platform macOS 14+. **No external
packages** — targets `DeelpeProtocol` and `DeelpeBar` only, plus the test
target. Updating it means updating Swift/Xcode, nothing else.

## System and runtime packages

| Where | Package | Version | Note |
|---|---|---|---|
| `packaging/docker/Dockerfile` | `node` | 24-alpine | UI build stage |
| | `rust` | 1-trixie | server build stage |
| | `debian` | trixie-slim | runtime base |
| | `ca-certificates`, `libssl3t64` | from trixie | libssl for webauthn-rs |
| `docker-compose.yml` | `postgres` | 18 | the server needs 18 or newer |
| `.deb` (`[package.metadata.deb]`) | `$auto`, `adduser` | | `$auto` resolves libssl3 |
| Windows cross build | mingw-w64 | brew | plus rustup target `x86_64-pc-windows-gnu` |

## Reverse index — one bump, how many artifacts

| Package | deelpe | winagent | server |
|---|---|---|---|
| anyhow, serde_json, tokio, tracing, chrono | ✅ | ✅ | ✅ |
| serde | ✅ | ✅ | ✅ |
| tracing-subscriber | ✅ | ✅ (via core/net) | ✅ |
| thiserror (via deelpe-core) | ✅ | ✅ | ✅ |
| clap | ✅ | ✅ | ✅ |
| sha2 | ✅ | ✅ | ✅ |
| reqwest, rcgen, rustls-pemfile, x509-parser, time | ✅ (core/net) | ✅ (core/net) | ✅ (direct) |
| async-trait (via deelpe-sensors) | ✅ | ✅ | — |
| windows | — | ✅ | — |

So: a `tokio` or `serde` bump means rebuilding and re-testing all three
binaries plus the Windows target build. A `sqlx`/`axum`/`webauthn-rs` bump
only touches the server. A `windows`/`windows-service` bump only touches the
Windows agent — and can only be verified with `cargo win`.

## Regenerating this list

```sh
cargo tree --depth 1 -e normal --workspace          # direct crates, resolved
cargo tree --depth 1 -e normal -p deelpe-sensors \
  --target x86_64-pc-windows-gnu                    # the Windows-only ones
cargo update --dry-run                              # what would move
cd apps/web && npm outdated                         # UI packages
```

`cargo tree` needs `--target x86_64-pc-windows-gnu` to show anything under
`cfg(windows)`; on a Mac those dependencies are otherwise invisible.
