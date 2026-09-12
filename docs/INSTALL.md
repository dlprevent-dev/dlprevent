# Operations: install, roll out, uninstall, move

What this covers: how much machine the whole thing takes, setting up the
central server on a production Linux box, connecting the agents on macOS and
Windows, rolling them out to many machines at once, removing everything
cleanly again, and what to do when the central server changes address.

What the tool detects and how, is in the [README](../README.md); dashboard,
rules and syslog are in [docs/SERVER.md](SERVER.md).

## Overview

| Role | Software | Runs as | Ports |
|---|---|---|---|
| Central server | `deelpe-server` + Postgres 18+ | systemd or Docker, Linux | inbound 8443 (dashboard), 8444 (agents), 514 (syslog) |
| Mac workstation | `DLPrevent.app` + `deelpe` service | LaunchDaemon (root) | outbound to 8444 only |
| Windows workstation / file server | `deelpe-winagent.exe` | Windows service | outbound to 8444 only |

Agents always open the connection themselves. The central server never calls
an agent; it needs no route into the client network.

Where the data lives — this is also the checklist for uninstalling:

| Role | Paths |
|---|---|
| Central server | `DEELPE_DATA_DIR` (default `/var/lib/deelpe-server`: `ca.pem`, `ca.key`, `server.pem`, `server.key`, `agents/` with the installers the enrollment command hands out), Postgres database `deelpe`, `/etc/deelpe-server/env` |
| Mac | `/usr/local/bin/deelpe`, `/Library/LaunchDaemons/ch.deelpe.daemon.plist`, `~/Library/LaunchAgents/ch.deelpe.bar.plist`, `/etc/deelpe/` (`config.json`, `central.json`), `/var/lib/deelpe/` (warnings, state, learning phase, `agent.log`), `/var/log/deelpe.log`, `/var/run/deelpe.sock`, `/Applications/DLPrevent.app` |
| Linux | `/usr/bin/deelpe`, `/lib/systemd/system/deelpe.service`, `/etc/deelpe/` (`config.json`, `central.json`), `/var/lib/deelpe/` (warnings, state, learning phase, `agent.log`), `/var/run/deelpe.sock` |
| Windows | the EXE (recommended `C:\Program Files\deelpe\`), service `deelpe-winagent`, `C:\ProgramData\deelpe\` (`central.json`, `state.json`, `agent.log`, `agent.log.1`), registry key `HKLM\SOFTWARE\Policies\Mozilla\Firefox\ContentAnalysis` |

---

## What the machines need

Measured on the lab installation (3 agents, Docker Compose, Postgres 18);
the per-warning figure is what the extrapolation below rests on.

| Role | CPU | RAM | Disk |
|---|---|---|---|
| Central server, up to ~200 agents | 2 cores | 4 GB | 20 GB + database (see below) |
| Central server, beyond that | 4 cores | 8 GB | 40 GB + database |
| Build machine (once, for Docker or the `.deb`) | 4 cores | 8 GB | 25 GB free |
| Mac workstation | — | ~90 MB | ~200 MB |
| Windows workstation / file server | — | ~20 MB | ~100 MB |

The server is small and stays small: the binary is 7 MB, the process sits at
about 30 MB, Postgres at about 110 MB. An agent sends one report every 30
seconds (`report_interval_secs`, adjustable from 10 to 3600), so 200 agents
make roughly 7 small requests per second — the CPU line above is headroom,
not need. The Windows service used 0.4 seconds of CPU in 8 minutes of
running, well under a tenth of one core.

**Disk is what grows, and only through the database.** Everything else is
fixed: `DEELPE_DATA_DIR` holds the CA, the server certificate and the agent
installers — a few megabytes plus up to 64 MB per uploaded installer. Under
Docker, the two images take about 850 MB.

A warning costs about **2.5 KB** in the database, indexes included, and lives
for **730 days** by default (`alert_retain_days`, Settings). So:

```
agents × warnings per agent per day × 2.5 KB × retention days
```

200 agents at 10 warnings a day come to roughly 3.6 GB over the full two
years. The other tables clean themselves up long before they matter: the
agent log (about 0.45 KB per line) after 14 days, the access counts after 30.
If the estimate comes out uncomfortable, shorten the retention rather than
buying disk — but check first whether the warnings are needed as evidence.

**The build machine is not the server.** Building needs Rust and Node and
about 25 GB: `target/release` alone is 1.2 GB, the rest is the crate registry
and Docker's layer cache. A development checkout that also carries the debug
build and the Windows target needs about 20 GB in `target/` by itself. None
of that has to exist on the production server — put the `.deb` or the image
together elsewhere and carry it over.

**Postgres 18 or newer** on the server, and it does not need tuning; the
stock configuration handles this load. Linux with systemd for the `.deb`
(the unit uses `StateDirectory` and `CAP_NET_BIND_SERVICE`), or Docker with
the Compose plugin.

---

## 1. Central server on production Linux

### Decide first: under which name is the server reachable?

These names go into the server certificate (`DEELPE_SERVER_NAMES`), and
agents connect under exactly one of them. **Use a DNS name, not an IP**
(`dlp.company.local`). A DNS name can be repointed later; an IP baked into
the certificate and into every agent configuration cannot — see chapter 5.

Every name and address under which browsers *or* agents reach the server
belongs in the list, comma-separated. More does no harm.

### Option A: Docker Compose (recommended)

Needs Docker with the Compose plugin on the server. It builds from the repo;
Compose brings Postgres along.

```bash
git clone <repo> /opt/dlp && cd /opt/dlp
cp packaging/deelpe-server.env.example .env
```

For Compose, three lines in `.env` are enough — the rest of the template
applies to option B and is ignored here (Compose sets the database URL
itself):

```
POSTGRES_PASSWORD=<long random password>
DEELPE_SERVER_NAMES=dlp.company.local,10.0.0.10
DEELPE_LOG=info,sqlx=warn
```

```bash
docker compose up -d --build
docker compose logs server | grep -i password     # initial password for 'admin'
```

Compose binds 8443, 8444 and 514/udp plus 514/tcp (5514 inside the
container) and creates two named volumes: `dlp_db` (database) and
`dlp_server` (CA, certificates and agent installers).

### Option B: .deb with systemd

Building needs Rust and Node — not necessarily on the production server. On
the **build machine**:

```bash
cargo install cargo-deb
(cd apps/web && npm ci && npm run build)   # the interface is embedded into the binary
cargo deb -p deelpe-server                 # → target/debian/deelpe-server_*.deb
```

On the **production server**:

```bash
sudo apt install postgresql-18             # or the package source from postgresql.org
sudo -u postgres psql -c "CREATE USER deelpe PASSWORD '<password>'" \
                      -c "CREATE DATABASE deelpe OWNER deelpe"
sudo apt install ./deelpe-server_*.deb
sudo cp /etc/deelpe-server/env.example /etc/deelpe-server/env
sudo chmod 600 /etc/deelpe-server/env
sudo editor /etc/deelpe-server/env
```

At minimum, in that file:

```
DEELPE_DATABASE_URL=postgres://deelpe:<password>@localhost/deelpe
DEELPE_SERVER_NAMES=dlp.company.local,10.0.0.10
DEELPE_SYSLOG_ADDR=0.0.0.0:514
```

Port 514 works without root: the unit carries `CAP_NET_BIND_SERVICE`. The
service runs as user `deelpe-server`, and systemd creates its data directory
as a `StateDirectory` (`/var/lib/deelpe-server`, 0700).

```bash
sudo systemctl enable --now deelpe-server
sudo journalctl -u deelpe-server | grep -i password    # initial password for 'admin'
```

### After the first start

1. Open the dashboard at `https://<server>:8443`, sign in as `admin` with the
   password from the log, and change it immediately under **Users →
   Password**. Create further users there (role *Admin* or *Read only*).
2. **Make the CA known to the browser**, otherwise it warns on every visit.
   Fetch the CA and check the fingerprint against the dashboard (Agents →
   Enroll agent):

   ```bash
   curl -k https://<server>:8444/agent/ca > deelpe-ca.pem
   openssl x509 -in deelpe-ca.pem -noout -fingerprint -sha256
   ```

   Distribute that file into the trusted root certificates by group policy or
   MDM. Alternatively put a reverse proxy with a publicly trusted certificate
   in front of the dashboard — see *Behind a reverse proxy* below.
3. **Upload the agent installers** under Agents → Enroll agent (the dialog
   offers it when nothing is stored yet). From then on the enrollment command
   fetches the program onto the device itself, instead of somebody carrying
   the file around. See chapter 4.
4. Firewall: 8443 to the administration networks, 8444 to the agent networks,
   514 **internal only**. Syslog is unauthenticated and the sender address
   can be forged. Which networks those are is a segmentation decision, and it
   is yours — see [Scope, limits and your obligations](../README.md#scope-limits-and-your-obligations).

### Behind a reverse proxy

Only the **dashboard** goes behind a proxy. The agent port 8444 speaks mTLS
and terminates the client certificate in the server itself; syslog on 514 is
not HTTP. Both stay reachable directly, or pass through as a TCP stream.

The dashboard has to sit at the **root of its own (sub)domain**. A subpath
(`https://proxy/dlp/`) does not work: the interface fetches `/api/…` and its
assets from the root.

```nginx
server {
  listen 443 ssl;
  server_name dlp.company.local;
  client_max_body_size 128m;            # agent installers: the server takes 64 MB

  location / {
    proxy_pass https://127.0.0.1:8443;  # leave the dashboard's own TLS on
    proxy_ssl_verify off;               # its certificate comes from the built-in CA
    proxy_set_header Host $http_host;
    proxy_set_header X-Forwarded-Host $http_host;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_read_timeout 300s;            # AI assistance: a local model may need minutes
  }
}
```

Then, in the server environment — `.env` next to `docker-compose.yml`, or
`/etc/deelpe-server/env` for the `.deb`:

```
DEELPE_TRUST_PROXY=true
```

Switch that on **only** when a proxy really sits in front. Without one,
anyone dodges the lockout after failed logins with a forged header.

What the three headers are for — all three, or something breaks:

| Header | Without it |
|---|---|
| `Host` / `X-Forwarded-Host` (`$http_host`, with the port) | writing requests get 403 (origin check), passkeys stop working, and the enrollment command shows the wrong host name |
| `X-Forwarded-For` | every user shares the proxy address, and with it the lockout |

`$http_host`, not `$host`: the check compares the browser's `Origin` verbatim,
including a non-standard port.

Two further points:

- **Passkeys need a DNS name** at the proxy, not an IP, and the name has to
  stay — it is the key's identity. Same for the server certificate list
  (`DEELPE_SERVER_NAMES`). A key is bound to the address it was registered
  under: whoever then opens the dashboard by IP is not offered it and signs in
  with a password, or registers a second key under that address.
- The **enrollment command** (Agents → Enroll agent) builds its URL from the
  name in the address bar plus port 8444. If the proxy runs on a different
  machine than the server, that name has to resolve to the server for the
  agents as well — or correct the host name in the command by hand.
  Shortcut for a lab where only the IP resolves: open the dashboard directly
  under `https://<ip>:8443`, past the proxy, and the command comes out with
  the IP already in it. The IP has to be in `DEELPE_SERVER_NAMES` for that —
  enrolment verifies the certificate against the CA.

`DEELPE_UI_HTTP=true` serves the dashboard as plain HTTP for the proxy to
pick up. It saves the proxy the `proxy_ssl_verify off`, and costs nothing as
long as proxy and server share a machine — the session cookie keeps its
`Secure` flag either way once `DEELPE_TRUST_PROXY` is on.

### Backup

Two things, and the first matters more:

- **`DEELPE_DATA_DIR`** — it holds `ca.key`. If the CA is gone, every agent
  certificate is worthless and **all** devices have to be enrolled again. The
  file never changes; backing it up once is enough.
- **The database** — warnings, rules, users, agent list.

Write both **outside the checkout**. A dump holds every warning, rule, user
and agent; the checkout is a git repository on a shared server, and a stray
`git add -A` would publish it. `BACKUP` below is any directory that is not
the repository — `.gitignore` also covers `*.sql.gz`, but do not rely on it.

```bash
BACKUP=/var/backups/deelpe   # not the checkout
mkdir -p "$BACKUP"

# Docker
docker compose exec -T db pg_dump -U deelpe deelpe | gzip > "$BACKUP/deelpe-$(date +%F).sql.gz"
docker compose cp server:/var/lib/deelpe-server "$BACKUP/deelpe-ca-backup"

# .deb
sudo -u postgres pg_dump deelpe | gzip > "$BACKUP/deelpe-$(date +%F).sql.gz"
sudo tar czf "$BACKUP/deelpe-ca-backup.tgz" -C /var/lib deelpe-server
```

### Updating

Migrations run at startup on their own; there is no path back to an older
version. Back up first.

```bash
# Docker
cd /opt/dlp && git pull && docker compose up -d --build

# .deb
sudo apt install ./deelpe-server_<new>.deb && sudo systemctl restart deelpe-server
```

Agents do not have to be updated at the same time; the wire format carries a
version and older agents keep reporting.

### Admin password lost

There is no reset command. If no second admin is left: delete all users and
restart the service — with no users at startup it creates `admin` with a new
random password and writes it to the log. Sessions, attributions in warnings
and tokens hang off that (cascade); the warnings themselves stay.

```bash
docker compose exec -T db psql -U deelpe -d deelpe -c "DELETE FROM users;"
docker compose restart server && docker compose logs server | grep -i password
```

### Uninstalling the central server

**Disconnect the agents first** (chapters 2 and 3), otherwise they run into
the void: the Mac service keeps the last distributed folders and strict
folders in its local configuration and goes on blocking, with nobody left who
could switch the rule off.

```bash
# Docker: containers gone, data stays
docker compose down
# Docker: everything gone, including CA and database — irreversible
docker compose down -v

# .deb
sudo systemctl disable --now deelpe-server
sudo apt purge deelpe-server
sudo rm -rf /var/lib/deelpe-server /etc/deelpe-server
sudo -u postgres psql -c "DROP DATABASE deelpe" -c "DROP USER deelpe"
sudo deluser --system deelpe-server
```

`docker compose down -v` takes the containers, the network and the named
volumes — the database and `DEELPE_DATA_DIR` with the CA are gone at that
point and no backup restores what was not backed up. What it does **not**
take: the two images (about 850 MB) and the clone in `/opt/dlp`, whose `.env`
still holds `POSTGRES_PASSWORD` and `DEELPE_SERVER_NAMES`.

```bash
docker image rm deelpe-server:latest postgres:18
rm -rf /opt/dlp                                # clone with .env — nothing of yours in it?
```

Nothing left over — all four must come back empty:

```bash
docker ps -a --filter name=deelpe             # no container
docker volume ls | grep dlp_                  # dlp_db and dlp_server gone
sudo -u postgres psql -lqt | grep deelpe      # no database (option B)
ss -lntp | grep -E ':(8443|8444|514)'         # nothing listening any more
```

A `.deb` install leaves nothing beyond those paths: no logrotate snippet, no
cron entry, and the journal keeps the old log lines until it rotates them out
by itself (`journalctl --vacuum-time=1d -u deelpe-server` if they should go
now).

---

## 2. Agent on the Mac

### Installing

Requirements for building: Xcode Command Line Tools, Rust (see
`rust-toolchain.toml`).

```bash
apps/macos/DeelpeBar/build.sh
```

Result: `apps/macos/DeelpeBar/build/DLPrevent.app` — the app contains the
service and the plists and can install itself — and next to it
`build/DLPrevent.zip`, the same bundle packed for the dashboard (see
"Into the dashboard" below). Copy it to the target device
(remote support, MDM, USB), then:

```bash
cp -R DLPrevent.app /Applications/ && open /Applications/DLPrevent.app
```

Build and install on the same Mac in one go:

```bash
apps/macos/DeelpeBar/build.sh && rm -rf /Applications/DLPrevent.app && cp -R apps/macos/DeelpeBar/build/DLPrevent.app /Applications/ && open /Applications/DLPrevent.app
```

### Into the dashboard

So that the enrollment command fetches the app from the central server
instead of somebody carrying it over by hand, upload `build/DLPrevent.zip`
as an administrator: **Agents → the macOS row → Upload/Replace**. As long as
nothing is stored for macOS the row is hidden; then the dialog under
**Agents → Enroll agent → macOS** offers "Upload it now". The server checks
the `PK` header and keeps the file as `DLPrevent.zip`; the local file name
does not matter.

What the zip has to look like is decided by the enrollment command: it
unpacks it with `unzip -d /Applications`, so `DLPrevent.app` has to be the
top level of the archive. `build.sh` packs it with `zip -y` for that reason
and not with `ditto -c -k`: ditto writes AppleDouble entries which unzip
drops inside the bundle, and the signature of the unpacked app is then
broken ("a sealed resource is missing or invalid").

Two limits: `build.sh` builds for the architecture of the build machine, so
a zip from an Apple-Silicon Mac does not run on an Intel one. And macOS
agents do not update themselves — the upload serves the enrollment
download, nothing goes out to devices already enrolled.

In the app (lock icon in the menu bar):

1. **Install service…** — asks once for the admin password, creates
   `/usr/local/bin/deelpe` and the LaunchDaemon, and starts it. Enrolment
   comes after this step, never before: until here the program sits inside
   the app bundle, and `sudo deelpe central enroll` answers `command not
   found`.
2. Red bar "Full Disk Access missing": **Open System Settings**, add
   `/usr/local/bin/deelpe` there with `+` and ⌘⇧G, then **Restart service…**
   back in the app. Without it the service sees no file access
   (`ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED`).
3. If antivirus is running, add an exception for `/usr/local/bin/deelpe`
   (needed with Bitdefender).
4. Protect a folder with `+`. Asks for the admin password: the service accepts
   changes to the protection and exception lists only from root, so no
   program running as the user can quietly switch protection off.
5. If a service reports constantly, click **Ignore this process** in the
   warning. The list is in the gear menu.
6. On first start macOS asks whether DLPrevent may show notifications. New
   warnings arrive as notifications; a click opens the window.
7. In the gear menu: "Start at login" and "Reinstall service…" (after an app
   update). The IP reputation check is not configured here — it runs on the
   central server, under Settings → Reputation in the dashboard.
8. The table loads the most recent 500 warnings. The filter field above it:
   every word must occur (process, file, IP, path, ID), `-word` excludes,
   e.g. `-claude`. The "All stored" checkbox loads everything.
9. Export: "Export" above the warning list, CSV or JSON. Always contains all
   stored warnings.

Test: upload a file from the folder somewhere with `curl -F`. The icon turns
red and the warning appears in the table. "How" shows the route the data took
to the sender.

Warnings are kept in `/var/lib/deelpe/alerts.jsonl` (one JSON line per
warning, readable by root only). Retention is `alert_retain_days` in
`/etc/deelpe/config.json`, default 365, `0` = unlimited. Alongside it:
`state.json` (the correlator's memory, survives a service restart),
`learned.json` (learning phase and pairs) and `changes.log` (every change to
the protection, exception and pair lists). If a sensor dies, the service
restarts it with a growing pause; meanwhile the error is shown in the app.
The service remembers checksums of `config.json` and `learned.json`; if a
file is edited behind its back, the app shows a red bar and `changes.log`
gets a line.

### Connecting to the central server

In the dashboard: **Agents → Enroll agent**, give it a label, **Device:
macOS**, create the token. The command shown contains address, token and CA
fingerprint — and a download link for the app bundle if one has been
uploaded.

> The address in the command is the name **you used to reach the dashboard**.
> Open the dashboard under the name the agents will use — otherwise correct
> the address in the command by hand; the fingerprint stays the same.

In DLPrevent under gear → **Central server** paste the command and click
**Connect…**, or on the command line:

```bash
sudo deelpe central enroll https://dlp.company.local:8444 <token> --ca-sha256 <fingerprint>
deelpe central status
```

A token is good for exactly one enrollment. From then on the service reports
every 30 seconds and picks up the absolute rule paths from the central
server.

### CLI only (without the app)

```bash
cargo build --release
sudo ./target/release/deelpe daemon        # needs FDA for the terminal program
sudo ./target/release/deelpe watch add ~/Taxes     # changes only as root
./target/release/deelpe status             # also shows sensor health
./target/release/deelpe alerts             # latest 500, --all for everything
./target/release/deelpe show 3
./target/release/deelpe export -o alerts.csv            # or --format json
./target/release/deelpe ignore list                     # add / remove TEAM/signing-id (with sudo)
./target/release/deelpe learn status                    # phase and learned pairs
sudo ./target/release/deelpe learn confirm              # forget <key> / remember <id> / flag <id> / restart
./target/release/deelpe central status                  # link to the central server
sudo ./target/release/deelpe central enroll https://server:8444 <token> --ca-sha256 <fp>
sudo ./target/release/deelpe central remove
```

Started from a terminal, Full Disk Access goes to the terminal program
(iTerm, Terminal.app), not to the binary — see
[TROUBLESHOOTING.md](TROUBLESHOOTING.md).

### Updating

Build the new app, replace `/Applications/DLPrevent.app`, then in the app
gear → **Reinstall service…**. Enrollment, warnings and learning phase stay —
they live in `/etc/deelpe` and `/var/lib/deelpe`, not in the app.

### Uninstalling

Order matters: disconnect first, wait a minute, then remove. The service
releases the central server's folders and their strict locks by itself on the
next round — as long as it is still running. Switch it off beforehand and you
have to take the remains out of `/etc/deelpe/config.json` by hand.

```bash
sudo deelpe central remove          # credentials and reporting state gone
sleep 70
sudo deelpe watch list              # only locally protected folders left
sudo deelpe watch remove /path      # per folder, if anything remains
```

Remove service and app (the app has no button for this):

```bash
sudo launchctl bootout system /Library/LaunchDaemons/ch.deelpe.daemon.plist
sudo rm -f /Library/LaunchDaemons/ch.deelpe.daemon.plist /usr/local/bin/deelpe /var/run/deelpe.sock
rm -f ~/Library/LaunchAgents/ch.deelpe.bar.plist          # start at login
rm -rf /Applications/DLPrevent.app
```

Leftover data — the warnings are the record, so delete them deliberately:

```bash
sudo rm -rf /etc/deelpe /var/lib/deelpe /var/log/deelpe.log
```

Finally, remove the `deelpe` entry under System Settings → Privacy → Full
Disk Access, and in the dashboard **Revoke** the agent, then **Delete**.

---

## 3. Agent on Windows

Applies to both roles: **workstation** (`--endpoint`, sees what processes
read from protected folders and where they send it) and **file server**
(without `--endpoint`, reads the security event log). The role is fixed at
enrollment and can only be changed by enrolling again. **Both roles use the
same EXE.**

What the role decides:

| | File server | Workstation (`--endpoint`) |
|---|---|---|
| Sees | the security event log (4663/5145), SACLs on the rule folders | its own file and network events (ETW) |
| Reports | accesses per user against the hard limit, and files that land in a rule folder | correlated flows out of a protected folder, files that land in one, learning phase |
| Acts | no intervention against a flow — it observes and reports (it does set the audit policy and the SACLs it needs) | strict folder: removes the copy, cages the sender, asks before a browser upload |
| Gets rules | as they stand — it resolves a share name itself | translated: `GL` becomes `\\srv01\GL`; a rule it cannot resolve is skipped and reported |

**Check the role after enrolling.** A wrong role is silent: the agent reports,
the dashboard turns green, and the wrong loop runs. The first log lines after
`service start` say which one it is — `endpoint agent running` for a
workstation, `rules received, starting to read` for a file server:

```powershell
.\deelpe-winagent.exe status
Get-Content C:\ProgramData\deelpe\agent.log -Tail 5
```

### Installing

The quickest way is the command from the dashboard: Agents → **Enroll agent**
→ Device → create the token. If an installer has been uploaded, the command
shown downloads the EXE onto the machine, checks its SHA-256, enrolls,
installs the service and starts it — one paste, as administrator. The manual
route below is what it does step by step.

To build the EXE yourself:

```bash
cargo win-build
# → target/x86_64-pc-windows-gnu/release/deelpe-winagent.exe
```

Eleven of the agent's thirteen modules carry `cfg(windows)` code, so a plain
`cargo check` on a Mac or Linux box never type-checks the bulk of it. After
touching `crates/deelpe-winagent` or `crates/deelpe-sensors/src/windows`,
run the target build:

```bash
cargo win
```

Both are aliases in `.cargo/config.toml`. They need the toolchain once:
`rustup target add x86_64-pc-windows-gnu` and a mingw-w64 linker
(`brew install mingw-w64`, or `apt install gcc-mingw-w64-x86-64`).

On the target machine **as administrator**, PowerShell (separate with `;`,
not `&&`):

```powershell
New-Item -ItemType Directory -Force "C:\Program Files\deelpe"
Copy-Item deelpe-winagent.exe "C:\Program Files\deelpe\"
cd "C:\Program Files\deelpe"
```

The EXE has to be in its final place before the service is set up: the
service points at exactly that path. From a temp folder, `service install`
refuses to work.

**Check once per Windows version** that event tracing delivers (workstation
role only) — while it runs, open a file on the share and upload something:

```powershell
.\deelpe-winagent.exe trace --seconds 30
```

Both `file` **and** `net` lines must appear. If one kind is missing, the
output names the place in the code that holds the keywords.

Enroll and install as a service (the command is shown in the dashboard under
Agents → Enroll agent → **Device: Windows workstation** or **Windows file
server**):

```powershell
.\deelpe-winagent.exe enroll https://dlp.company.local:8444 <token> --ca-sha256 <fingerprint> --endpoint
.\deelpe-winagent.exe service install
.\deelpe-winagent.exe service start
.\deelpe-winagent.exe status
```

Without `--account` the service runs as LocalSystem — more privilege than
needed. Better a dedicated account, and on a domain file server a gMSA:

```powershell
.\deelpe-winagent.exe service install --account "DOMAIN\deelpe-svc$"
.\deelpe-winagent.exe rights grant --account "DOMAIN\deelpe-svc$"
```

The two commands do different jobs, and the order above matters:

- `service install --account` registers the service **and** fixes the file
  permissions: read and execute on the EXE, modify on
  `C:\ProgramData\deelpe`. `service start` does it again, because every
  update sets the same trap (see *Updating* below).
- `rights grant --account` grants exactly what the agent needs and nothing
  more: `SeServiceLogonRight`, `SeSecurityPrivilege`, and membership in
  **Event Log Readers**. Deliberately not: Administrators.

One thing neither of them does: membership in **Performance Log Users**,
which the account needs for event tracing (workstation role). Add that by
hand or by group policy.

Two commands help when a rule stays silent on site: `check` verifies the
audit policy and the SACL of every rule folder (file server role), `probe
--back 500 --limit 15` dumps the last records the agent actually sees in the
security event log with their fields, so you can tell whether events arrive
at all. `shares` lists the server's shares as the dashboard would show them.

**Rule paths must be complete.** A workstation cannot resolve `GL`; there the
rule needs `\\srv01\GL` or `G:\GL`. Skipped rules are reported by the agent
in the dashboard, with the reason.

**The browser upload is blocked in Firefox only** (workstation role).
`service install` also writes the content-analysis policy under
`HKLM\SOFTWARE\Policies\Mozilla\Firefox\ContentAnalysis`, which is what makes
Firefox ask the agent before an upload and wait for the verdict — the only
mechanism that acts before the bytes move. **Firefox reads the policy at
start-up, so restart it once after the install.** Chrome and Edge are not
covered: Chrome needs its own policy keys, which the agent does not write
yet, and Edge only accepts DLP connectors from partners onboarded by
Microsoft. An upload out of a strict folder in Chrome or Edge is reported
afterwards, not blocked — see the connector section in
[SERVER.md](SERVER.md).

### Updating

Run this from any directory, not from `C:\Program Files\deelpe` — a shell
standing in that folder holds it open. `Stop-Service` is used instead of
`service stop` on purpose: it returns only once the service really is
stopped, while `service stop` returns as soon as the stop was requested and
the next `Copy-Item` then hits "the process cannot access the file".

```powershell
$exe = "C:\Program Files\deelpe\deelpe-winagent.exe"
Stop-Service deelpe-winagent
Copy-Item -Force <new>\deelpe-winagent.exe $exe
icacls $exe /reset
& $exe service start
& $exe status
```

**`icacls $exe /reset` is not optional on a machine whose service runs under
a dedicated account** (file server, domain controller — see chapter 4). A file
copied out of `C:\temp` brings that folder's access list with it, the service
account is not on it, and the service then does not start — with no error, no
entry in `agent.log`, nothing but a service that stays stopped. `/reset` puts
the inherited rights of `C:\Program Files\deelpe` back. Under LocalSystem it
costs nothing, so it stays in the block either way.

## Processes without alerts

Dashboard → **Settings → Detection → Allowed processes**: one program name
per line, `#` starts a comment.

```
# backup and sync clients: they read the share by design
onedrive.exe
backup-agent.exe
```

The list goes to every agent with its next report — nothing to edit on the
machine, no restart. Matching is by program name, case-insensitive.

Those processes produce no learning-phase, `new` or `deviation` alert. A
**strict folder still applies**: a forbidden destination stays a `denied`
alert and the intervention still happens. The list only removes the noise of
a process you already know — which is also why a piece of malware calling
itself `teams.exe` gets past the list but not past a strict folder.

Enrollment and state live in `C:\ProgramData\deelpe` and stay. Only if the
service path changes: `service uninstall`, then `service install`.

### Uninstalling

Again from any directory except the install folder itself:

```powershell
$exe = "C:\Program Files\deelpe\deelpe-winagent.exe"
Stop-Service deelpe-winagent
& $exe service uninstall
Remove-Item -Recurse -Force C:\ProgramData\deelpe      # credentials, state, log
Remove-Item -Recurse -Force "C:\Program Files\deelpe"
```

`Remove-Item` on the program folder fails with "access denied" as long as the
service still exists — then `service uninstall` did not run. Check with
`Get-Service deelpe-winagent`.

If the program was deleted before `service uninstall` ran, the binary that
cleans up is gone and two remnants stay behind. Remove them by hand:

```powershell
sc.exe delete deelpe-winagent
Remove-Item -Recurse -Force 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\ContentAnalysis'
```

The second one is the Firefox content-analysis policy. Left in place, Firefox
keeps asking an agent that no longer answers and waits for the timeout on
every upload — restart it once after removing the key.

Nothing left over — all four must answer this way:

```powershell
Get-Service deelpe-winagent                    # → "Cannot find any service"
Test-Path "C:\Program Files\deelpe", C:\ProgramData\deelpe   # → False, False
Test-Path 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\ContentAnalysis'  # → False
& "C:\Program Files\deelpe\deelpe-winagent.exe" --version    # → not recognized
```

**The service is still in `services.msc`.** Two different cases, and
`sc.exe query deelpe-winagent` tells them apart:

| Answer | Meaning | What helps |
|---|---|---|
| 1060, "does not exist" | gone, the console is showing a stale view | close every `services.msc` window and open it again — F5 does not do it |
| `STOPPED`, or 1072 "marked for deletion" | the deletion is waiting on an open handle | close the consoles, then `sc.exe delete deelpe-winagent` again |

The open handle is usually `services.msc` itself. On a machine with a
dedicated service account also look for a process of that account that is
still running (`Get-Process -IncludeUserName deelpe-winagent`). If 1072
survives all of that, only a restart clears it — deleting
`HKLM\SYSTEM\CurrentControlSet\Services\deelpe-winagent` by hand takes the
registration away while the SCM keeps the service in memory, which is worse
than waiting.

The blocking ends with the service, and removing `C:\ProgramData\deelpe`
takes the stored rule set with it — the workstation agent keeps its last
accepted rules there so that it protects from the first second after a
restart, even without the central server (see docs/SERVER.md). Leave that
folder in place and the rules come back with the service. Afterwards
**Revoke** in the dashboard, then **Delete**.

With a dedicated service account, take the privileges back as well:

```powershell
& "C:\Program Files\deelpe\deelpe-winagent.exe" rights revoke --account "DOMAIN\deelpe-svc$"
```

Before deleting the program, obviously — afterwards only `ntrights` or the
group policy editor can take them back.

What does **not** disappear by itself (file server role only): the audit
policy and the audit entries (SACL) the agent set on the rule folders. To
undo them, if nothing else needs them:

```powershell
# GUIDs rather than names: the names are localised, the GUIDs are not.
auditpol /set /subcategory:"{0CCE921D-69AE-11D9-BED3-505054503030}" /success:disable
auditpol /set /subcategory:"{0CCE9244-69AE-11D9-BED3-505054503030}" /success:disable
```

Those are "File System" and "Detailed File Share". Only switch them off if no
other auditing builds on them.

Remove the SACL itself through folder properties → Security → Advanced →
Auditing (entry "Everyone", Read).

---

## 4. Agent on Linux

The same program as on the Mac — `deelpe`, one binary, service plus CLI.
Underneath it is **fanotify** for file access and **`ss`** for the bytes
sent. No kernel module, but root: fanotify needs `CAP_SYS_ADMIN`.

### Building the package

```bash
scripts/build-agent-deb.sh          # → dist/deelpe_<version>-1_amd64.deb + SHA-256
scripts/build-agent-deb.sh arm64    # Raspberry Pi, Graviton, Ampere
```

Runs in Docker and works from a Mac as well. **Not** `cargo deb -p deelpe`
straight away: a `.deb` carries a Linux binary, and its architecture comes
from where it was built. On a Mac that packages a macOS binary; in Docker on
Apple Silicon without `--platform` it packages arm64, which no amd64 server
installs — and `dpkg` only says so at the far end, after the rollout. The
script spells the architecture out every time.

### Installing

```bash
# The architecture is in the glob on purpose: with both builds in one
# directory, a plain deelpe_*.deb takes whichever comes first.
sudo apt install ./deelpe_*_amd64.deb            # Debian/Ubuntu, pulls iproute2
sudo systemctl enable --now deelpe
deelpe status
```

On any other distribution the same binary works on its own:

```bash
sudo install -m 755 deelpe /usr/local/bin/deelpe
sudo install -m 644 packaging/deelpe.service /etc/systemd/system/
sudo sed -i 's#/usr/bin/deelpe#/usr/local/bin/deelpe#' /etc/systemd/system/deelpe.service
sudo systemctl daemon-reload && sudo systemctl enable --now deelpe
```

The package does not start the service: without a folder or an enrollment
the agent watches nothing, and a service running for nothing hides that.

### Connecting to the central server

**Agents → Enroll agent → Linux.** The dialog hands out the token and this
command; install the `.deb` first, because nothing is downloaded from the
server here:

```bash
sudo deelpe central enroll https://dlp.company.local:8444 <token> --ca-sha256 <fingerprint>
```

The platform button only picks which command is offered. The token itself is
bound to no platform — the agent says what it is when it enrolls — so a
token created before this button existed works just as well.

Then:

```bash
sudo deelpe watch add /srv/GL      # or let the dashboard distribute folders
deelpe alerts
```

Only the token and the fingerprint come from the dashboard, never the
program: there is no Linux installer stored there and no update it can order
(`binaries::platform_for` returns `None`). The `.deb` goes out through your
own channel, and an update is `apt install` plus a restart.

### What Linux sees and what it does not

| | Linux | Windows workstation |
|---|---|---|
| Read from a protected folder | ✅ fanotify | ✅ ETW |
| The copy elsewhere | ✅ | ✅ |
| Bytes sent per process | ✅ TCP, out of `tcp_info` | ✅ TCP and UDP |
| Upload over QUIC/HTTP/3 | ❌ no byte counter in the kernel for UDP | ✅ |
| A connection that opens and closes between two polls | ❌ (as on the Mac) | ✅ |
| Rename, hard link as such | ❌ (a copy still shows as read + write) | ✅ |
| Mounted CIFS/NFS share | depends on the kernel | ✅ |
| Blocking, network cage, killing the sender | ❌ | ✅ |
| USB / external volume | ❌ | ✅ |

Whether a share was covered is not a guess: the first log line after every
start names the filesystems that took a mark (`journalctl -u deelpe`). A
protected folder on a filesystem missing from that list is not watched.

### Updating and uninstalling

```bash
sudo apt install ./deelpe_<new>.deb && sudo systemctl restart deelpe
```

```bash
sudo systemctl disable --now deelpe && sudo apt purge deelpe
sudo rm -rf /etc/deelpe /var/lib/deelpe /var/run/deelpe.sock
```

Revoke the agent in the dashboard afterwards.

---

## 5. Mass rollout

### Read this first: enrollment does not scale yet

Deploying the software scales fine. **Enrollment does not.** A token is good
for exactly one enrollment and is burned afterwards
(`enroll_tokens.used_at`). For 200 machines that means 200 tokens created by
hand in the dashboard — there is no bulk token today.

So a rollout has two halves, and only the first one automates cleanly:

| Step | Automatable today |
|---|---|
| Distribute the EXE / app bundle / `.deb`, install the service | **yes** — GPO, Ansible, Intune, SCCM |
| Enroll (token, certificate) | **no** — one token per device, by hand |

Two ways to live with that until bulk tokens exist:

- **Staged rollout.** Deploy the software to everything, then enroll in
  batches: create a token, run one command per machine. An agent without
  enrollment does nothing and harms nothing — it simply stays offline.
- **Enroll at provisioning time.** Where machines are set up individually
  anyway (new hire, re-image), the enrollment is one more line in that
  runbook and costs nothing extra.

Do **not** try to bake one enrollment into an image: `central.json` holds the
device's private key. Clone it and every clone shares one identity — one
`Revoke` then kills all of them, and the central server cannot tell them
apart.

> **Open item.** Bulk enrollment (a token with a use count and an expiry,
> optionally bound to a network) is the missing piece. Until then, plan the
> enrollment effort per device.

### Windows via group policy

There is no MSI; the agent is a single EXE plus a service. The reliable route
is a **computer startup script** (Computer Configuration → Policies →
Windows Settings → Scripts → Startup), which runs as SYSTEM before anyone
logs in.

Put the EXE on a share every computer account can read (`Domain Computers`,
read only), then this script:

```powershell
# deelpe-install.ps1 — computer startup script, runs as SYSTEM
$src  = '\\srv01\software$\deelpe\deelpe-winagent.exe'
$dir  = 'C:\Program Files\deelpe'
$exe  = Join-Path $dir 'deelpe-winagent.exe'

New-Item -ItemType Directory -Force $dir | Out-Null

# Only copy when it differs, so the script can run at every boot.
$need = -not (Test-Path $exe) -or
        (Get-FileHash $src).Hash -ne (Get-FileHash $exe).Hash
if ($need) {
    if (Get-Service deelpe-winagent -ErrorAction SilentlyContinue) {
        & $exe service stop | Out-Null
        Start-Sleep -Seconds 3
    }
    Copy-Item $src $exe -Force
}

# Install the service once; enrollment stays manual (see above).
if (-not (Get-Service deelpe-winagent -ErrorAction SilentlyContinue)) {
    & $exe service install | Out-Null
}
& $exe service start | Out-Null
```

The same script also serves as the **update** mechanism: it compares hashes,
so it is idempotent and can run at every boot.

### Updating from the dashboard instead

> **Under a dedicated service account, replacing has to be allowed first.**
> The swap writes the new file next to the running one and renames twice —
> changes to the *folder*, not to the file. Under LocalSystem that works
> anyway; a service account (gMSA, domain account) has nothing there:
>
> ```powershell
> & "C:\Program Files\deelpe\deelpe-winagent.exe" rights allow-self-update --account "CORP\deelpe-svc"
> ```
>
> Without it the agent's **`self-update`** sensor in the dashboard turns red,
> naming the folder and the missing right, and an order stays on "not picked
> up". Anyone still rolling the agent out by GPO or a script does not need
> this and should not grant it: the account may change the contents of its
> program folder afterwards.

> **The agent does not swap if nobody would start it again.** Before
> downloading it checks that a recovery action with *restart* is configured
> **and** that it also applies to a clean stop with an error code — which is
> exactly how it signs off after the swap. If either is missing it stays as it
> is and writes down which line is missing. An outdated running agent beats an
> up-to-date dead one.
>
> A service account may not reconfigure its own service, so an administrator
> sets this once (one line, it must not wrap):
>
> ```
> sc.exe failure deelpe-winagent reset= 600 actions= restart/5000/restart/30000/restart/120000//0
> sc.exe failureflag deelpe-winagent 1
> ```
>
> Under LocalSystem the service catches this up itself on every start.

> **The first version has to go onto the device by hand.** An agent can only
> replace itself if it already contains the code for it. One running a version
> from **before** self-update cannot see the central server's order at all:
> the agent list shows "not picked up" and nothing happens, however often you
> press. That one version goes the usual way (startup script, GPO, Intune, a
> manual copy) — from then on the central server rolls out.
>
> How to spot it: the agent reports (the "Last report" column is fresh) but
> stays "outdated", and there is **no** line about the program in its log. An
> agent that tries and fails writes there.

### Another file server, with a dedicated service account

The enrollment command from the dashboard installs the service as
**LocalSystem**; then there is nothing else to do and self-update works right
away. Anyone using a dedicated account instead (gMSA or domain account — the
better choice on a domain controller) needs three commands afterwards, run
elevated:

```powershell
$exe = "C:\Program Files\deelpe\deelpe-winagent.exe"
& $exe rights grant --account "CORP\deelpe-svc"              # privileges + Event Log Readers
& $exe rights allow-self-update --account "CORP\deelpe-svc"  # may replace its own program
sc.exe failure deelpe-winagent reset= 600 actions= restart/5000/restart/30000/restart/120000//0
sc.exe failureflag deelpe-winagent 1
```

Without the first, local auditing stays silent (`set SACL … WIN32_ERROR(5)`) —
SMB access is recorded, local access is not. Without the second and third the
agent refuses updates and says so on the `self-update` sensor.

All three can be checked:

```powershell
& $exe rights show --account "CORP\deelpe-svc"
icacls "C:\Program Files\deelpe"
sc.exe qfailure deelpe-winagent
```

### Where the program comes from

Three routes into the central server's store, and all of them end there — from
there it reaches the devices by the routes below. Which one fits depends on a
single question: **who compiles**. Windows and macOS, that is: the Linux
`.deb` is not kept here and takes your own channel, see section 4.

| Who builds | Route | Effort per version |
|---|---|---|
| Every installation itself, from the cloned repository | `scripts/publish-agent.sh` | one command, then the dashboard |
| Nobody on site — the publisher builds once | release + *Fetch* | two clicks in the dashboard |
| By hand, one-off or to roll back | upload in the browser | file dialog |

**The central server builds nothing itself, and that is deliberate.** It is a
runtime image with a single program in it — no compiler, no toolchain, no
source. Equipping it with those would mean that a system holding the alerts
and evidence of an entire workforce compiles and runs foreign code on a click
in the browser. A compromised dashboard account would then be a compromised
build server. Compiling happens where the compiler is; the central server only
distributes.

- **Built yourself, from the cloned repository:** `scripts/publish-agent.sh`
  builds the agent and puts it straight into the store of your own central
  server — on the build machine itself, or with `DEELPE_SSH=user@host` on the
  server over there. The route for everyone who stays current with `git pull`
  — see [DEVELOPMENT.md](DEVELOPMENT.md).
- **Upload** under *Agents → agent program*. Always possible, nothing else
  needed.

  **Upload first, then create the enrollment token.** The command carries the
  checksum of the program that was in place when the token was created and
  checks it on the device. Upload a new version afterwards and the command
  aborts with `checksum mismatch` — correct, but annoying. A new token costs
  nothing.
- **Fetch from a release.** Under *Settings → Interfaces* enter the repository
  (`owner/repo` for GitHub, or the full API address of your own Gitea) and the
  public signing key. The central server then looks every six hours and says
  on the agent page when there is a newer version; *Fetch* downloads it,
  checks the signature and stores it. **Nothing is rolled out by that.**

If the repository is **private** — a self-hosted Gitea usually is, and a
GitHub repository may well be — a **release access token** belongs in
*Settings → Interfaces* as well. Without it the server answers 404, including
for the files themselves. Read access is enough (on GitHub: a fine-grained
token with *Contents: read* on that one repository); it only goes to the
address entered there.

### Publishing a new version

One command on the development machine builds, signs and attaches both files
to the release:

```bash
scripts/release-agent.sh                    # GitHub, signed in with `gh auth login`
GITEA_TOKEN=… scripts/release-agent.sh      # a Gitea of your own
```

Then in the dashboard *Agents → Check now → Fetch* — and it rolls out as
configured. Once, beforehand:

```bash
deelpe-sign keygen ~/.deelpe/release.key    # public key into the dashboard
```

Going via the release is deliberate. Uploading straight into the dashboard
would take an administrator account of the central server — and then a
password for the monitoring system would sit in a file on a development
machine. The git token only opens the repository, and the signature makes the
central server independent of who it trusts.

The signatures come from `deelpe-sign`, which is in this repository
(`cargo build -p deelpe-server`):

```bash
deelpe-sign keygen release.key                      # once; prints the public key
deelpe-sign sign release.key deelpe-winagent.exe    # writes deelpe-winagent.exe.sig
```

Both files belong to the release. The **private** key stays with whoever
publishes — not in the repository, not on the central server; otherwise the
separation that makes the signature worth anything is gone. Without a key
stored, the central server fetches nothing, and it says so.

An enrolled agent can also fetch a new program by itself. Upload the EXE
under **Agents → agent program** and check the checksum shown there. From
then on there are two ways to send it out:

- **One agent — the `Update` button** in its row in the agent list. It
  appears on agents that run something other than the uploaded program. Use
  this first: update one device, watch it come back, then do the rest. The
  order goes out with that agent's next report and clears itself once the
  agent runs the uploaded program.
- **All of them — the switch** under **Settings → Interfaces → "Update
  agents from here"**.

Either way the agent fetches the program over the same mTLS connection as
its report, verifies the checksum against the one the central announced,
replaces itself and restarts into the new program. Agents show up as
**outdated** in the agent list regardless — the button and the switch only
decide whether anything is sent, so the list is worth watching even if you
keep rolling out via GPO or Intune.

Three things to know before switching it on:

- The restart runs through the service manager's **recovery action**. It is
  set up by `service install` and brought up to date at every
  `service start` — an agent installed before this version needs one
  `deelpe-winagent service start` (or a reboot) before it can update itself.
  Without it the agent replaces its program and then stays down.
- Every replacement is logged as a **service failure** in the Windows event
  log (exit code 100). That is how the restart is triggered; it is not an
  error you need to chase.
- If a new program does not come up, the service manager retries three
  times (after 5 s, 30 s and 120 s) and then stops. The agent shows as
  offline, and the previous version is still there as
  `deelpe-winagent.exe.old` — copy it back over `deelpe-winagent.exe` and
  start the service. The old copy is removed only once the new program has
  had a report accepted by the central, so it is still there for a program
  that starts and *then* fails.

If you prefer not to use a startup script, Group Policy Preferences work too:
a *File* item to copy the EXE and a *Scheduled Task* (run as SYSTEM, trigger
"at startup") to install and start the service.

**Distribute the CA with the same policy** — Computer Configuration →
Windows Settings → Security Settings → Public Key Policies → Trusted Root
Certification Authorities → import `deelpe-ca.pem`. Without it the dashboard
warns in the browser; the agents themselves pin the CA by fingerprint and do
not need it.

### Windows via Intune or SCCM

Package the EXE with the install script above as a Win32 app
(`IntuneWinAppUtil`). Sensible settings:

- **Install command:** `powershell.exe -ExecutionPolicy Bypass -File deelpe-install.ps1`
- **Uninstall command:** `"C:\Program Files\deelpe\deelpe-winagent.exe" service stop; ... service uninstall`
- **Detection rule:** file `C:\Program Files\deelpe\deelpe-winagent.exe`
  exists — or better, check its version so an update is detected.
- **Context:** system, not user.

### Windows via Ansible

```yaml
- name: DLPrevent agent
  hosts: windows
  tasks:
    - name: Create directory
      ansible.windows.win_file:
        path: C:\Program Files\deelpe
        state: directory

    - name: Copy agent
      ansible.windows.win_copy:
        src: files/deelpe-winagent.exe
        dest: C:\Program Files\deelpe\deelpe-winagent.exe
      register: copied
      notify: restart deelpe

    - name: Install service
      ansible.windows.win_command: >
        "C:\Program Files\deelpe\deelpe-winagent.exe" service install
      args:
        creates: C:\ProgramData\deelpe

    - name: Service running and automatic
      ansible.windows.win_service:
        name: deelpe-winagent
        start_mode: auto
        state: started

  handlers:
    - name: restart deelpe
      ansible.windows.win_service:
        name: deelpe-winagent
        state: restarted
```

Enrollment stays out of the playbook on purpose — a token in a playbook is a
token in version control, and it only works once anyway.

Check afterwards, across all machines:

```yaml
- name: Status
  ansible.windows.win_command: '"C:\Program Files\deelpe\deelpe-winagent.exe" status'
  register: st
  changed_when: false
- debug: var=st.stdout_lines
```

### macOS via MDM (Jamf, Intune, Kandji)

Three parts, and the third is the one people forget:

1. **App bundle** — deploy `DLPrevent.app` to `/Applications` as a package.
2. **Service** — the app installs it interactively, which does not work
   unattended. For MDM, have a post-install script place
   `/usr/local/bin/deelpe` and `packaging/ch.deelpe.daemon.plist` directly and
   load it with `launchctl bootstrap system …`.
3. **Full Disk Access** — this **cannot** be granted by script. It needs a
   **PPPC profile** (Privacy Preferences Policy Control) from the MDM,
   granting `SystemPolicyAllFiles` to `/usr/local/bin/deelpe` with its code
   requirement. Without that profile the service starts and sees nothing:
   `ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED`. Deploy the profile *before* the
   service, then it is allowed from the first start and no user is ever
   prompted.

Enrollment again per device:
`sudo deelpe central enroll https://… <token> --ca-sha256 <fp>`.

### Linux via Ansible (or your own apt repo)

Nothing comes from the dashboard here — there is no Linux artefact in its
store, see "Where the program comes from". The `.deb` travels the way your
other packages do.

Build it with `scripts/build-agent-deb.sh` (see section 4 — the architecture
is the part that goes wrong silently). If you already run an internal apt
repository, put it in there and the whole job is `ansible.builtin.apt:
name=deelpe state=latest`. Without one, copy the file:

```yaml
- name: DLPrevent agent
  hosts: linux
  become: true
  tasks:
    - name: Copy package
      ansible.builtin.copy:
        src: files/deelpe_0.1.3-1_amd64.deb
        dest: /tmp/deelpe.deb
      register: copied

    - name: Install
      ansible.builtin.apt:
        deb: /tmp/deelpe.deb
      notify: restart deelpe

    - name: Service enabled and running
      ansible.builtin.systemd_service:
        name: deelpe
        enabled: true
        state: started

  handlers:
    - name: restart deelpe
      ansible.builtin.systemd_service:
        name: deelpe
        state: restarted
```

`apt` pulls `iproute2` along; the package itself does not start the service,
which is why the play enables it explicitly.

Enrollment stays out of the playbook for the same reason as on Windows: a
token in a playbook is a token in version control, and it only works once.

Check afterwards, across all machines:

```yaml
- name: Status
  ansible.builtin.command: deelpe status
  register: st
  changed_when: false
- debug: var=st.stdout_lines
```

What to look for in that output is below, under "After the rollout".

### After the rollout: what to check

- Dashboard → Agents: every device online, with a plausible **address**.
  Agents that report `via <ip>` are on an older build that does not report its
  own addresses.
- The **version** column: as long as it is identical everywhere, it tells you
  nothing about who is out of date — worth watching when you update.
- Workstation role: sensor `etw` green. `rule <path>` in red means a relative
  rule path that an endpoint cannot resolve.
- Sensor `network cage` green. Red means the agent could not install its
  network filters for a program that had just read from a strict folder: the
  cage stays **open**, so that upload is no longer stopped. Reporting and
  deleting the copy are unaffected. See
  [TROUBLESHOOTING.md → Windows](TROUBLESHOOTING.md#windows).
- Run `trace --seconds 30` on one machine per Windows version, once.
- Linux: both sensors green (`fanotify`, `procnet` — a red `procnet` is
  usually a missing `ss`), and `journalctl -u deelpe | grep 'filesystems
  marked'` on one machine per filesystem layout. A protected folder on a
  filesystem missing from that line is not being watched.

---

## 6. The central server gets a different address

Three things hang off the address, and you only have to touch the first two:

| What | Depends on it | Must be changed |
|---|---|---|
| Server certificate | `DEELPE_SERVER_NAMES` — the name from the agent URL must be in it, otherwise the TLS handshake fails | **yes** |
| Agent configuration | `url` in `central.json` on every device | **yes** |
| CA and agent certificates | do **not** depend on the address | no |

That is why moving is not a re-enrollment: as long as `DEELPE_DATA_DIR`
survives, the CA, its fingerprint and all agent certificates stay valid.

> With a DNS name in `DEELPE_SERVER_NAMES` and in the agent URL, an IP change
> is a non-event: repoint the DNS record, done. Everything below concerns the
> case where the **name** changes or an IP is entered directly.

### Procedure without downtime

**1. New address into the certificate, keep the old one.** Both at once, so
the agents can be moved over at leisure.

```bash
# Docker: adjust .env
DEELPE_SERVER_NAMES=dlp.company.local,10.0.0.10,10.0.5.10
docker compose up -d

# .deb: adjust /etc/deelpe-server/env
sudo systemctl restart deelpe-server
```

At startup the server issues a new certificate as soon as a name from the
list is missing — with the same CA. The fingerprint shown in the dashboard
does **not** change.

**2. Move the server** (new IP, firewall rules, DNS). Open the dashboard
under the new address and sign in — that also proves the certificate fits.

**3. Move the agents over.** The clean way is to enroll again (`central
remove`, then `enroll` with a new token) — but it is not necessary. Changing
the URL in the configuration is enough:

*Mac:*

```bash
sudo launchctl bootout system /Library/LaunchDaemons/ch.deelpe.daemon.plist
sudo sed -i '' 's#https://old:8444#https://new:8444#' /etc/deelpe/central.json
sudo launchctl bootstrap system /Library/LaunchDaemons/ch.deelpe.daemon.plist
deelpe central status
```

*Windows (as administrator):*

```powershell
$exe = "C:\Program Files\deelpe\deelpe-winagent.exe"
Stop-Service deelpe-winagent
(Get-Content C:\ProgramData\deelpe\central.json) -replace 'https://old:8444','https://new:8444' |
  Set-Content C:\ProgramData\deelpe\central.json
& $exe service start
& $exe status
```

In both cases the new address then shows up in `status`, and "Last seen" in
the dashboard jumps within a minute. With many machines this is one line in
the Ansible playbook or the startup script from chapter 4.

**4. Verify, then drop the old address.** Only once no device in the agent
list is stale, remove the old name from `DEELPE_SERVER_NAMES`. The
certificate is **not** reissued automatically for that — it still contains
the old names, and the check only asks whether all required ones are present.
If the old name really has to go:

```bash
# Docker
docker compose exec server rm /var/lib/deelpe-server/server.pem /var/lib/deelpe-server/server.key
docker compose restart server
# .deb
sudo rm /var/lib/deelpe-server/server.pem /var/lib/deelpe-server/server.key
sudo systemctl restart deelpe-server
```

Do **not** touch `ca.pem` and `ca.key` while doing this.

**5. Do not forget the NAS boxes.** The syslog destinations on the devices
(Synology, QNAP, TrueNAS) point at the old address and have to be changed by
hand. The source in the dashboard is recognised by the NAS's *sender*
address — that does not change when the server moves, so the source stays.

### When it goes wrong anyway

| Symptom | Cause | Remedy |
|---|---|---|
| Agent reports "certificate verify failed" / "not reachable" | new name missing from the server certificate | add the name to `DEELPE_SERVER_NAMES`, restart the service |
| `CA fingerprint does not match` during enrollment | wrong address — or somebody in between | check the address; compare the fingerprint in the dashboard |
| Agent shows `expired` | no report for over two years; renewal needs a certificate that still works | enroll again with a fresh token, then revoke + delete the old entry |
| All agents fail at once, their certificates are valid | server certificate expired (825 days). It is reissued **at startup**, once fewer than 30 days remain — a server running for years never gets there | restart the service; restarting once a year prevents it |
| `DEELPE_DATA_DIR` lost, no backup | CA gone | no recovery: new CA, enroll all agents again, delete the old entries |
