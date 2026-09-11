# Development

## Requirements

- Xcode Command Line Tools (macOS app, `eslogger`/`nettop` sensors).
- Rust, stable channel per `rust-toolchain.toml`.
- Node and npm for `apps/web` (the Svelte interface, embedded into the server binary).
- A development Postgres with the `CREATEDB` right for the server's HTTP tests.
- For the Windows agent: `brew install mingw-w64` and
  `rustup target add x86_64-pc-windows-gnu` (see `.cargo/config.toml`).

## How it works

```
deelpe daemon (root)              DLPrevent.app / deelpe CLI (no root)
  eslogger  → file access    ─┐
  nettop    → bytes sent     ─┴→ correlation → warning → unix socket → table, export
```

On macOS the sensors are Apple's own tools (`eslogger`, `nettop`), so no
kernel extension and no entitlement are needed. On Windows they are event
tracing (Kernel-File, Kernel-Network), which likewise needs no driver — only
blocking does. The service has no outbound network access of its own; the one
exception is the connection to a central server, once the device has been
enrolled. The menu-bar app reaches out only to the system resolver, for the
reverse DNS of a destination address (`HostResolver`). The IP reputation
check is not in the app: it has been the central server's job since
2026-09-08.

## Layout

| Path | Contents |
|---|---|
| `crates/deelpe-core` | Event model, configuration, correlation (platform-independent) |
| `crates/deelpe-sensors` | macOS: eslogger, nettop. Windows: ETW (Kernel-File, Kernel-Network). Linux: fanotify, /proc/net |
| `crates/deelpe` | Service, CLI, unix socket protocol, export, link to the central server |
| `crates/deelpe-winagent` | Windows agent: workstation and file server roles |
| `crates/deelpe-server` | Central server: dashboard API, agents, syslog, Postgres |
| `apps/macos/DeelpeBar` | Menu-bar app (Swift) |
| `apps/web` | Central server interface (Svelte), embedded into the server binary |
| `packaging` | LaunchDaemon, LaunchAgent, systemd units, Dockerfile, .deb |

The access meter (a fixed emergency brake plus a learned baseline) and the
wire format between agent and central server live in `deelpe-core`: syslog
aggregation in the server and the Windows agent share the same logic, so that
NAS boxes and file servers behave alike.

## Building

CLI and service:

```bash
cargo build --release          # target/release/deelpe
```

macOS app (builds the service too, bundles it with the plists):

```bash
apps/macos/DeelpeBar/build.sh  # → apps/macos/DeelpeBar/build/DLPrevent.app
```

Central server with the embedded web interface:

```bash
(cd apps/web && npm ci && npm run build) && cargo build --release -p deelpe-server
```

Windows agent, cross-compiled from the Mac (alias in `.cargo/config.toml`):

```bash
cargo win-build                # target/x86_64-pc-windows-gnu/release/
```

### After a `git pull`: the new agent into your own central server

Anyone who clones the repository and builds it does not want to push the
freshly built agent through a file dialog in the browser. One command:

```bash
git pull && scripts/publish-agent.sh
```

It builds the Windows agent and puts it into the store of the running central
server. It then shows up in the dashboard under *Agents*, and the agents fetch
it on their next report — if *Update agents from here* is on, otherwise it
waits there for the button.

It expects a central server from this repository's `docker-compose.yml`
(container `dlp-server-1`). Other setups:

```bash
DEELPE_CONTAINER=my-central            scripts/publish-agent.sh   # other container
DEELPE_DATA_DIR=/var/lib/deelpe-server scripts/publish-agent.sh   # without Docker
```

The file goes straight into the store, without signing in. That is not a hole:
whoever can run this script operates the central server anyway and could just
as well log in. A password for the monitoring system sitting in a file on a
development machine would be the worse answer to the same problem. The price
is a missing entry in the audit log — if you need that, keep uploading through
the browser.

**For installations that do not build themselves** there is the opposite
route: a signed release that every central server finds by itself
(`scripts/release-agent.sh`, [INSTALL.md](INSTALL.md)). Both end up in the
same store.

Docker image and packages: [INSTALL.md](INSTALL.md).

## Tests

```bash
cargo test --workspace && (cd apps/macos/DeelpeBar && swift test)
```

Wire formats are contracts, pinned in literal tests: service against app in
`crates/deelpe/tests/wire_format.rs` and the Swift tests, agent against
central server in `crates/deelpe-server/tests/central_wire.rs`. The central
server's HTTP tests need `DATABASE_URL` pointing at a development Postgres
with the `CREATEDB` right (only `central_wire.rs` runs without one); see
[SERVER.md](SERVER.md#development) for a local setup.
`crates/deelpe/tests/central_live.rs` runs only with `DEELPE_TEST_CENTRAL_*`
set, against a real instance, and is skipped otherwise.

**Whoever touches `crates/deelpe-winagent` or `crates/deelpe-sensors/src/windows`
runs `cargo win`.** Eleven of the workstation agent's thirteen modules carry
Windows-only code, and two of them (`rights`, `service`) do not exist off
Windows at all; `cargo check` and `cargo test` on a development machine
therefore never type-check the bulk of it. Without the target build, any
change there is blind.

Bitdefender: add an exception for `/usr/local/bin/deelpe`.

## Migrations

`crates/deelpe-server/migrations/*.sql` are applied once and then frozen.
SQLx stores a checksum per migration in `_sqlx_migrations` and compares it at
every start; the checksum covers the **whole file**, comments included. Edit
an applied migration and every central server that already ran it refuses to
start with `migration N was previously applied but has been modified` — the
operator's, not just yours, and there is nobody at that installation to
repair the table by hand.

So: a change to the schema is a new file, never an edit to an old one. That
includes rewording a comment. This is why the comments in the applied
migrations are still German and have to stay that way: translating them
changed the checksums and stopped the lab server (2026-09-11). A new
migration file is written in English like everything else.

German also still lingers in a scattering of **test assertion messages**
across the workspace (`mail.rs`, `wfp.rs`, `enforce.rs` and others). Those
are not frozen — translate them when you next touch the test.

## Branches and CI

Work happens on `dev`; `main` carries what has been released. A pull request
from `dev` to `main` merges it, and `main` takes nothing else.

`.github/workflows/ci.yml` runs on every push and pull request to either
branch, in three jobs: the workspace (`cargo check` plus `cargo test` against
a Postgres service container), the Windows agent (`cargo win`, the same
target triple as on a development machine), and `apps/web` (`npm test`,
`tsc --noEmit`, `npm run build`).

The Swift tests are not part of it — they need a macOS runner. Run them
locally, as above. `cargo fmt` and `cargo clippy` are not gates either; the
tree does not satisfy them today, and making it do so is a separate job.
