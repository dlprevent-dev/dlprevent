# DLPrevent central server (deelpe-server)

Dashboard and collection point for agents and NAS syslog. Outwardly the
product is called DLPrevent; binaries, services and paths keep the name
`deelpe` (decision of 2026-09-05). Stage Z1 (2026-09-06): observe, do not
intervene — with the strict folder as the first exception. Decisions:
`docs/DESIGN.md`, section "Central server and server agents".

## What is in it

- One binary, Postgres 18+, interface embedded (Svelte).
- Three ports: dashboard 8443 (HTTPS), agents 8444 (HTTPS with client
  certificate), syslog on UDP and TCP. The binary listens on 5514 by
  default; Docker Compose publishes it as 514, and the .deb needs
  `DEELPE_SYSLOG_ADDR=0.0.0.0:514` in `/etc/deelpe-server/env` (the unit
  carries `CAP_NET_BIND_SERVICE` for that).
- Its own CA in `DEELPE_DATA_DIR` (`ca.pem`, `ca.key`; the directory is
  0700, root only). The server
  certificate is issued from it for `DEELPE_SERVER_NAMES`. Browsers warn
  until `ca.pem` is imported, or until a reverse proxy with its own
  certificate sits in front (`--ui-http`).
- On first start `admin` is created with a random password; it is in the log
  (`journalctl -u deelpe-server` or `docker compose logs server`). Change it
  after signing in under Users → "Password". Interface, command line,
  protocol, documentation and the comments in the source are English.
- The agent installers, under `DEELPE_DATA_DIR/agents/`, offered for download
  in the dashboard.

## Roles

**Read only** may read the overview, alerts and access counts. Rules, agents,
sources, groups, enrollment tokens, users, settings and the audit log are for
**Admin** only — including through direct API calls.

Read-only may not close warnings and may not send learning instructions.
Signing in, signing out, changing one's own password and setting up one's
own second factor stay possible.

### Second factor

Every account can add a second factor under **Account**, both roles alike:

- **Authenticator app** (TOTP, RFC 6238): after the password, a six-digit
  code from Google Authenticator, Microsoft Authenticator, Aegis, 1Password
  or any other app. The setup shows a QR code and the secret to type by
  hand; the first correct code switches it on. One code opens one session:
  a code that has been used is refused until the next one.
- **Passkeys** (WebAuthn): sign in with the user name and the device's
  fingerprint, face or PIN, no password. A passkey is bound to the host name
  the browser sees in the address bar, so open the dashboard by name and
  keep using that name; an IP address does not work, browsers do not allow
  it. Adding a passkey asks for the current password once, because a passkey
  is a lasting way in. Behind a reverse proxy set `DEELPE_TRUST_PROXY` so the
  name comes from `X-Forwarded-Host`.

The TOTP secret is stored as it is in the database (it has to be, the server
computes the same code as the app); passkeys store only public keys. Someone
who can read the database and crack a password therefore also has the app's
codes — keep backups as private as the CA key.

Under **Settings → Sign-in** an administrator can **require** a second factor
for administrators, for read-only accounts, or both. An account without one
then reaches only its Account page after signing in, until it has set one
up (own password change included); the server enforces this on every
request, not just the interface. An account that has only passkeys is then
refused the password on its own and sent down the passkey route. The switch
for administrators only goes on when the administrator saving it has a
second factor already — otherwise it would lock them out of Settings.

Lost the phone or the device? An administrator resets the second factor
under **Users → Reset 2FA**: app and passkeys are gone, the password stays,
and every open session of that account ends — the lost device is signed out.
Administrators also set a new password there, for any account. Both actions
are in the audit log (`second_factor_reset`, `password_change`).

Failed codes and refused passkeys count towards the same lockout as wrong
passwords: ten failures from one address, one minute pause.

An **API key** is a read-only account without a browser: see
[API keys](#api-keys-for-a-siem-or-a-script).

Step by step with firewall, backup, mass rollout, uninstall and moving the
server: [INSTALL.md](INSTALL.md).

## The dashboard pages

The pages carry a heading only; what each one means is here.

**Overview** — the open-alerts count holds hard limits and deviations only.
New pairs and other observations stay under Alerts → Notices.

**Alerts and notices** — alerts are hard limits and deviations. Notices are
new pairs and other observations; they do not raise the red counter. The
search covers user, process, folder, target, reason and file names. A click
on a source narrows the list, shift-click selects a range.

Under an expanded alert, **Explain** asks a language model to summarise the
rule, the destination's reputation, the user's week and the agent log in
three paragraphs — for administrators, if AI assistance is switched on; see
"AI assistance".

**Rules** — one protected folder per rule. A relative path such as `GL`
matches every folder of that name on a NAS or file server; an absolute one
such as `/Users/x/GL` or `D:\Shares\GL` only matches there. Workstations
need the full path the machine itself sees, e.g. `\\srv01\GL`, because they
have no share table to resolve a name against (see "Windows workstation").

**Agents** — the devices running the service. They report on the configured
interval and pick up their rules while doing so. A certificate lasts two
years; an agent renews its own within the last 30 days, on its next report.
One that stays offline past the expiry cannot connect again and has to be
enrolled anew: revoke the old entry, then delete it (see "Agent
certificates").

A click on a row opens what the device reports, and under it its **log**.
Every agent writes one locally — `C:\ProgramData\deelpe\agent.log` on
Windows, `/var/lib/deelpe/agent.log` on Mac and Linux, one rollover at 4 MB
— and sends the newest lines along with each report. That includes the
lines from a time when nothing got through: a failed report is retried on
every interval, each attempt is logged, and once the central answers again
the backlog arrives with it. So the dashboard shows *why* a device went
quiet, not only that it did. Filter by severity, search the text. The ring
on the device holds the last 1000 lines and the central keeps them for 14
days (fixed, not a setting); the file on the device is the full record.

**Syslog sources** — NAS devices without an agent send their file-access log
over syslog (UDP or TCP, port 514). The server condenses on receipt and drops
the raw line. A source appears by itself with the first packet.

**Users** — administrators may change everything. "Read only" sees the same
data but creates, changes and closes nothing (see "Roles"). The 2FA column
shows what each account has set up; "Reset 2FA" removes it when a device is
lost.

**Account** — for everyone: own password, authenticator app, passkeys (see
"Second factor").

**Settings** — apply to the whole central server and every agent. Each change
bumps the configuration generation; agents pick it up on their next report. The
**Notifications** tab is the only page that reaches out on its own; see
"Email notifications".

**Audit log** — every change to the central server, with user and time. Never
deleted.

## Docker

```bash
cp packaging/deelpe-server.env.example .env   # set POSTGRES_PASSWORD, DEELPE_SERVER_NAMES
docker compose up -d --build
docker compose logs server | grep password
```

Dashboard: `https://<server>:8443`.

## Ubuntu/Debian (.deb)

```bash
cargo install cargo-deb
(cd apps/web && npm ci && npm run build)
cargo deb -p deelpe-server
sudo apt install ./target/debian/deelpe-server_*.deb
sudo apt install postgresql-18   # or the package source from postgresql.org
sudo -u postgres psql -c "CREATE USER deelpe PASSWORD 'secret'" -c "CREATE DATABASE deelpe OWNER deelpe"
sudo cp /etc/deelpe-server/env.example /etc/deelpe-server/env && sudo chmod 600 /etc/deelpe-server/env
sudo editor /etc/deelpe-server/env
sudo systemctl enable --now deelpe-server
```

## The agent program comes with the enrollment command

An administrator uploads the installer once — in **Agents → Enroll agent**,
where the dialog offers it whenever nothing is stored yet. From then on the
command shown there does everything on the device: download the program from
this server, check its **SHA-256**, enroll, install the service, start it.

The check is by **checksum, not by certificate**. A freshly installed machine
does not know the central server's own CA yet, and a certificate error in the
middle of a one-liner helps nobody. The checksum comes out of the dashboard —
a channel the administrator already trusts — and it binds the file more
tightly than TLS could. Compare it against your own build before rolling out:
whoever may upload here decides what runs on every machine in the company.

The download runs on the **agent port** (8444) and is authenticated by the
enrollment token in the `X-Deelpe-Token` header; the token is not consumed by
it, only by the enrollment itself.

Two artefacts cover three roles:

| File | Covers |
|---|---|
| `deelpe-winagent.exe` | Windows workstation **and** Windows file server — the role is decided at enrollment (`--endpoint`), not by the file |
| `DLPrevent.zip` | the macOS app bundle; the app installs the `deelpe` service itself |

The files live in the data directory, not in the database: they are
megabyte-sized blobs, they belong next to the CA and the server certificate,
and an update is a file swap.

## Enrolling an agent

In the dashboard: Agents → "Enroll agent" → label → device → token. The
dialog shows the command and links the matching program directly.

On the Mac, in DLPrevent (gear → "Central server"), paste the command shown,
or enter the address (IP or host name is enough, port 8444 is appended),
token and CA fingerprint, then "Connect…", admin password. Or on the command
line:

```bash
sudo deelpe central enroll https://<server>:8444 <token> --ca-sha256 <fingerprint>
```

What happens: the agent fetches `ca.pem` from the server and checks the
fingerprint, generates a key locally, sends a CSR with the token, and gets
its certificate. The token is burned afterwards. From then on the service
reports every 30 s (Settings): status, new and updated warnings; it receives
the central rules and takes the absolute paths from them into its protection
list. `sudo deelpe central status` shows the state, `sudo deelpe central
remove` disconnects.

For many machines at once, see the mass rollout chapter in
[INSTALL.md](INSTALL.md) — and read its first paragraph, because enrollment
is the part that does not scale yet.

## Strict folder: everything forbidden except the allow list

In a rule (Rules → **Where data may go**), **Strict folder (block all)**
turns the folder into a one-way street: once a process has read from it,
every destination is forbidden unless it is listed under **Allowed
destinations**. Whether the file is uploaded in a browser, sent to an AI
service or pushed away with PowerShell makes no difference — only the
destination counts. Such warnings carry the verdict `denied`, apply from the
very first byte (no 4 KB threshold) and are **never** learned or silenced;
the learning phase does not change that.

An entry is an IP or a network, each with an optional port, one per line:

```
10.0.0.7            # our file server, any port
192.168.10.0/24:445 # SMB in the server segment
203.0.113.9:443     # the company Nextcloud
```

**No host names.** The service on the endpoint has no outbound network access
of its own (by design) and cannot resolve anything; for a link, put the
network behind it into the list. An empty list means nothing may leave at
all.

**Enforce** (optional) makes the rule act instead of only reporting. Three
levers do that on a Windows workstation, and none of them touches the sending
process itself: the browser connector refuses a file upload out of the folder
**before the first byte** and knows the target URL; the network cage (a WFP
filter at the ALE layer) takes the network away from a process that has read
from the folder, without ending it; and a copy that left the folder is locked
and deleted again. Without the checkbox the folder is watched strictly, but
nothing is stopped. The Mac has no lever of its own yet — it reports;
blocking before the first byte needs the Network Extension there.

**The sending process is never terminated.** That used to be what this
checkbox did, and it is gone since 2026-09-09: on that day it killed a user's
`explorer.exe` twice, over 330 and 446 bytes of Microsoft telemetry. A kill
lands after the bytes are already out and takes the open tabs — or the whole
desktop — with it, so it costs work and stops nothing.

**Leaving the folder is forbidden as well, not just sending.** A copy to
local disk, a USB stick or a network drive out of a strict folder is `denied`
too. On the Windows workstation the agent deletes such a copy again when
**Enforce** is set; the Mac only reports it.

The folder does not have to be in the agent's protection list as well: a
strict folder is always a protected one. If the rule is switched off or
deleted, the lock disappears with the next report.

## Windows workstation (endpoint agent)

The case it exists for: somebody drags a file from the share into a chat with
an AI service in the browser. **The file server cannot see this.** To it, an
authorised user reads a file — exactly as when opening it in Word; it is the
same event. Lockdown and the emergency brake do not help either: the user is
authorised, and it is one file.

It only becomes visible at the workstation, and that is where the lever is.

```powershell
deelpe-winagent enroll https://<server>:8444 <token> --ca-sha256 <fingerprint> --endpoint
deelpe-winagent service install
deelpe-winagent service start
```

The dashboard prints the matching command: Agents → "Enroll agent" →
**Device: Windows workstation**. Without `--endpoint` the device is enrolled
as a file server and reads a security event log that holds nothing for it.

The agent uses the same correlator as the Mac: a process that read from a
protected folder counts as touched; if it then sends outward, a warning
appears. The sensors are the event providers built into Windows,
"Kernel-File" and "Kernel-Network" — no driver, no kernel extension. The
service needs LocalSystem or an account in "Performance Log Users".

**Programs are identified by their signature.** The agent checks the
Authenticode signature of the EXE and takes the publisher from the
certificate (`Google LLC`) together with the `OriginalFilename` from the
version resource (`chrome.exe`). The original name is inside the file itself
— renaming `chrome.exe` to `svchost.exe` changes nothing. Programs without a
valid signature count as unknown and are **always** reported and never
learned, exactly as on the Mac. The check does not go out to the network:
revocation lists are not fetched.

**Rule paths must be complete.** On the server a rule may be called `GL` and
matches any share of that name; a workstation has no share table and cannot
resolve it. There the rule needs the path the machine sees: `\\srv01\GL` or
`G:\GL`. Skipped rules are reported by the agent as a sensor with a reason,
so that no green rule in the dashboard protects nothing.

**What the workstation does not see: share to share.** If somebody copies a
file from `\\srv01\GL` to another share, both paths run through the SMB
redirector in the kernel — the bytes leave under process ID 4 (`System`), not
under the program's. The correlator then sees a touched process with no send
and reports nothing. Measured in the lab on 2026-09-07. What gets reported is
what a program sends itself — the browser upload, the AI service, the script
with its own connection; and that is the case this exists for. The
share-to-share copy is caught by the file server agent instead.

**The copy onto one's own PC.** If somebody drags a file from `\\srv01\GL`
onto the desktop, there is no send to stop — the copier is Explorer. The
sensor therefore passes on the file events of a process that has just read
from a protected folder for five minutes, including **outside** the protected
folders; otherwise the copy would stay invisible (which is exactly what
happened in the lab on 2026-09-07). If the folder is strict and **Enforce**
is set, the agent deletes the copy again — and if the copier still
holds the file open, it keeps trying for ten seconds. Nothing inside the
protected folder itself is ever deleted.

**The rules survive a restart.** The agent writes every rule set it accepts
to `C:\ProgramData\deelpe\state.json` and puts it back in force at start-up
— sensor, network cage and browser connector all stand **before** the first
report goes out. A laptop that boots outside the company network,
or boots while the central server is down, is therefore protected from the
first second, exactly as the Mac service is. Until this was so, such a machine
protected **nothing**: no watched folder, no strict folder, and the browser
connector let every upload through (measured in the lab on 2026-09-09).

The price is deliberate: a stored rule stays in force until the central
server sends a new one. Whoever switches a strict folder off in the dashboard
while the workstation is off has it still in force after switch-on, until the
first report gets through — one report interval at most, and with an
unreachable central server for as long as it stays unreachable. A machine
that was enrolled but has never yet reached the central server has nothing
stored and protects nothing, as before.

One trap that cost a day of searching: event tracing attributes a **cached**
write to the system process (PID 4), not to the copier. The sensor therefore
credits file events to the process that **opened** the handle, not to the one
named in the event header. Without that, a copy to a freshly created folder
went unnoticed while a copy to the desktop happened to work.

### Blocking the browser upload: only Firefox today

Everything else on this page reports **after** the bytes are gone. The one
exception is the browser's own content-analysis connector: before an upload,
a paste or a print job the browser asks the agent over a named pipe and
**waits for the verdict**. A file out of a strict folder is refused there
before it moves, the user sees the browser's own block notice, and the
dashboard gets an alert with the destination URL. This is also the only place
where a host name in the allow list works — the browser hands us the URL,
the network path only ever sees an IP.

**It is set up for Firefox (≥ 137) and for nothing else.** `service install`
writes the policy under
`HKLM\SOFTWARE\Policies\Mozilla\Firefox\ContentAnalysis`; Firefox reads it
at start-up, so a running browser has to be restarted once. Chrome speaks the
same protocol but reads its own policy keys, which the agent does not write
yet. Edge cannot be done at all from here: Microsoft only accepts DLP
connectors from onboarded partners, and `EdgeFileUploadBlockedForUrls` — which
would do exactly this per URL — is not supported on Windows. See
[ADR 0002](adr/0002-upload-blocking-splits-by-egress-channel.md).

So an upload to an AI service **in Chrome or Edge is not blocked**. It is
still reported afterwards, like every other send, and the copy rules above
still apply — but nothing stops it, and the network cage does not step in
either: browsers are deliberately left out of it, because they belong to this
connector. If a strict folder has to hold against a browser upload today,
Firefox is the browser, and the rest belongs at the proxy or in
`URLBlocklist` by group policy.

One more limit worth knowing: paste and drag-and-drop are intercepted, but
only a request that carries a **file path** is judged. Marking cells in a
spreadsheet and pasting them into a chat window carries text and no path, and
is passed through today.

### What the user-mode agent cannot do

An adversarial run on 2026-09-07 tried 14 ways out of a strict folder. Six
were caught and the copy deleted (`copy`, `xcopy`, `robocopy`, `Copy-Item`,
`File::Copy`, `Get-Content|Set-Content` — each under the same file name).
**Eight got through:**

| Way | Why it gets through |
|---|---|
| copy under a **different name** | detection compares file names |
| `type source > target` | the target is opened before the source has been read |
| **ZIP** (`Compress-Archive`) | contents leave under a new name |
| **base64** | likewise, plus a changed format |
| `move` on the same volume | a pure rename, no data events |
| **alternate data stream** | the stream path is not covered |
| `\\127.0.0.1\c$\…` | the write goes through the SMB redirector |
| a target folder starting with a dot | was a Unix rule; since fixed |

On top of that there is the race: the copy exists for a second or two, and
whoever uploads faster than the agent deletes has the data out.

So, plainly: the user-mode agent **catches carelessness, not intent**. That
belongs in what you tell the customer, not in a footnote.

### Why there is no driver

Closing those paths at the file level takes a kernel minifilter. One was
built and measured in the lab on 2026-09-07 — with it loaded, not a single
byte left the folder — and removed again on 2026-09-09. It only ever loaded
with Secure Boot off and testsigning on, and on the test client it had not
been loaded since the day it was measured, while the agent kept pushing its
policy into a port nobody answered. A blocking layer that is dark and says
nothing about being dark is worse than none. Shipping a real one needs an EV
certificate and Microsoft attestation signing; Azure Trusted Signing does not
cover drivers, and cross-signed drivers lost their default trust in April
2026. Cost, timeline, the measurements and the ways out that are open because
of this: [ADR 0001](adr/0001-endpoint-blocking-minifilter.md).

What stops an upload does not need a driver and is unaffected: the browser
connector refuses before the first byte, and the network cage takes the
network from a program that has read from a strict folder (ADR 0002).

### Check once before first use

The event providers are part of Windows, but their keywords and field names
are not identical in every release. A run on the real machine tells you
within a minute whether it fits:

```powershell
deelpe-winagent trace --seconds 30 --filter GL
```

Then open a file on the share and upload it somewhere. Both `file` **and**
`net` lines must appear. If one kind does not come, the output names the
place in the code where the keywords are.

## Working through warnings

**Open alerts**, the red counter and **Latest alerts** only take `denied`,
`hard_limit` and `deviation` into account. The default list shows these
alarms.

Under **Alerts → Notices**, `new`, `flagged`, `no_profile`, `known` and
`learning` stay separately accessible. Open, Done and All exist there too.
The separation neither deletes nor closes anything.

"New" means a process/destination pair that has not been learned yet, not a
confirmed attack. Several flows of the same pair can produce several notices.

The API uses `category=alerts` by default. `category=notices` returns
notices, `category=all` both categories. This applies to `GET /api/alerts`
and to filter-based bulk closing with `POST /api/alerts/ack`.

Tick rows (shift-click selects a range) and **Mark done** closes several at
once; **Close all matching** closes everything that matches the chosen
category and the filter in effect — not just the page that is loaded.
Warnings from the learning phase (`verdict: learning`) arrive already done.

If the same pair of process and destination keeps coming back, closing does
not help: the agent reports an unknown pair again on **every** flow. For that
there is **Remember** in the warning row — the agent memorises the pair and
stays quiet from then on, except on a deviation. The button only appears once
"Let the central server silence a pair on an agent" is switched on under
**Settings → Interfaces**; it is off by default, because it changes the
behaviour of a device from here. The instruction does not go out
immediately but waits until the agent next reports.

## Updating agents from the dashboard

Upload the agent program in the **Agent program** panel at the top of the
Agents page — one row per platform, each with its checksum and a *Replace*
button. The first twelve characters of that checksum are the same value the
agent list shows in the Version column, so you can see at a glance who is
already on it. The list shows
its checksum and marks every agent that runs a different one as
**outdated**. That marking is always there. Sending the program out takes
one of two deliberate acts:

- the **`Update` button** in an outdated agent's row — that one agent, on
  its next report;
- **Settings → Interfaces → "Update agents from here"**, off by default —
  all of them, as they report in.

Either way the agent fetches the program over the same mTLS connection as
its report, verifies it against the checksum the central announced,
replaces itself and restarts into it.

Do one device with the button first and watch it come back. The switch
replaces the program on **every** enrolled device, so check the checksum
before you flip it. Rollout details, the recovery action a
pre-existing installation needs, and what to do if a new program does not
come up: [INSTALL.md](INSTALL.md).

## AI assistance: let a model explain an alert

Judging one alert means looking things up. Which rule matched. Whether the
destination address is known bad. What the same user did the rest of the
week. Whether that process turns up on other machines too. What the agent
logged around that minute. Five places, one alert at a time.

**Settings → Assistant** hands that legwork to a language model. In every
expanded alert an **Explain** button appears; the central server gathers
those five things into one dossier, asks the model to summarise it, and
shows three short paragraphs — what happened, why it was flagged, what to
check next.

It **decides nothing**. No verdict changes, no alert is closed, no agent is
instructed. Nothing is asked on its own either: only what somebody clicks.

The button and the explanations under it are for administrators — reading
one included. That looks like one privilege too many, since a finished
explanation costs nothing to read, but the dossier carries up to sixty lines
from an agent's log, and the log itself is administrators-only
(`/api/agents/{id}/log`). Were the explanation readable by everyone, a
read-only account would reach exactly the lines the route responsible for
them refuses — and the summary retells them anyway.

### Which model

Any endpoint that speaks the OpenAI chat-completions form, which is what
both realistic choices do. There is no provider setting, only a base URL —
**without** `/chat/completions`, the server appends that.

| | Base URL | API key |
|---|---|---|
| **Ollama** in your own network | `http://<host>:11434/v1` | none |
| **Infomaniak AI Tools** | `https://api.infomaniak.com/2/ai/<product_id>/openai/v1` | your API token |

For Ollama, the model is what `ollama list` shows on that machine, e.g.
`llama3.1:8b`. Get the Infomaniak `product_id` from `GET /1/ai`; the models
that endpoint offers come from `GET /2/ai/<product_id>/openai/v1/models`.

**Test connection** on the same page checks base URL, key and model name in
one go. It sends no alert data — just the word "ready". It uses the *saved*
settings, so save first.

A slow local model is normal: on a machine without a GPU one explanation
takes about a minute. The server waits up to three.

### What leaves this network, and where it goes

The dossier holds alert metadata: user name, process, folder and file
*names*, destination address, the rule, and the agent's log lines around the
event. **Never file contents** — the central server does not have them.

Where that goes is decided by the base URL alone:

- **Ollama in your own network:** nothing leaves the house.
- **Infomaniak:** the dossier leaves this network. The provider states the
  data stays in Switzerland and is not used to train third-party models.
- **Anything else** is your own call. Reading this kind of metadata is
  precisely what this tool exists to prevent elsewhere.

The status panel says which of the two you have: an endpoint inside your own
network is marked *stays in your network*, everything else *leaves the
network*.

Every dossier is stored word for word next to the answer it produced, and
can be read back under **What was sent to the model** in the alert. Every
explanation is also written to the audit log with the endpoint it went to.
The question "what exactly went out?" has an answer in this tool.

Two brakes: the master switch is off from the factory, and **Explanations
per day** (50 by default) stops the day once that many were asked for.
Asking the same alert again counts again — it costs again, and so does
**Test connection**. The count comes from the audit log, so restarting the
server does not reset it.

Changing the base URL to a **different host** drops the stored API key. A key
belongs to the service it was issued for; without this, saving a new address
would send your Infomaniak token to whatever now stands there, while the form
still said only "A key is stored".

### What it is not

The model reads a dossier and writes prose. It has no other source, it is
told to invent nothing and to say when the dossier does not answer
something — but a model that gets it wrong will still sound certain. The
chain, the raw data and the agent log stay under the same alert. The
summary is the fast way in, not the evidence.

## Agent certificates

An agent certificate is valid for 730 days. The agent renews it itself: if
expiry is closer than 30 days, it generates a new key on its next report and
has a new certificate signed over the existing connection (`/agent/renew`).
No token is needed — the connection already identifies the agent. Renewal
happens after every round in which the connection stood, not only once the
central server also accepted the report: otherwise a permanently rejected
report would use up the window.

The fingerprint the agent presented stays valid for a week afterwards. That
is the way back for a device that loses the answer or cannot store it: it
comes back in with the old certificate and tries again, repeatedly if need
be.

**Once the certificate has expired, that is the end.** The handshake itself
fails and no request gets through any more — not even the renewal. The device
then shows as "expired" in the list; otherwise the central server could not
tell it apart from a switched-off machine. The way back is a fresh enrollment
with a new token; revoke and delete the old entry afterwards.

For that, a device has to have failed to deliver a single report for two
years — anything reporting regularly renews long before.

## Revoking and deleting an agent

"Revoke" locks the certificate out: the agent cannot get in any more, the
entry stays. Only then does "Delete" appear and clear it away for good. Two
steps, so the list keeps showing whether a device was deliberately retired or
merely tidied up.

What stays on deletion: **the warnings.** They are the record and carry the
device name in the row itself, so they stay readable. What goes with it:
rules that applied only to this device, and its access counts.

## NAS over syslog

Sources appear automatically with the first packet (sender address). What the
parser does not understand counts as "Not understood" (Sources page). Note
for Docker Desktop (Mac/Windows): there all packets arrive with the address
of the Docker gateway (e.g. 192.168.65.1), so several NAS boxes fall into one
source. On Linux with Docker, or as a .deb, the real address is preserved.

**Syslog is unauthenticated.** Sources are recognised by sender address
alone, and UDP packets can be forged: anyone who reaches the network can
invent accesses and raise warnings. So make the syslog port reachable only on
the internal network (firewall, separate VLAN), never from the internet.
Agents are unaffected: they need a client certificate.

If you have no syslog source, switch the receiver off entirely under
**Settings → Interfaces**: then the port is not bound, not merely silent.
That takes effect within seconds, without a restart.

- **Synology DSM:** Log Center → Log Sending → server, port 514, BSD format.
  Control Panel → File Services → SMB → Advanced → enable the transfer log
  (read, download).
- **QNAP:** QuLog Center → Log Sending → syslog server. Enable the SMB
  connection log.
- **TrueNAS / Samba:** `vfs objects = full_audit`, `full_audit:success = open
  pread`, `full_audit:prefix = %u|%I|%m|%S`, forward syslog.

Create a rule: Rules → Path `GL` (relative: matches any folder named "GL") or
`/volume1/GL` (absolute). Hard limit: distinct files per user and window.
After the learning phase (Settings) the baseline reports as well.

## API keys for a SIEM or a script

A SIEM or a cron job that wants the alerts has no browser and no session
cookie. Settings → **API keys** creates a key for it.

- A key is **read only**, and narrower than a read-only account: it reaches
  exactly `/api/me`, `/api/overview`, `/api/alerts` and `/api/counts`. It
  cannot close an alert, change a rule, read the audit log, or fetch the agent
  installer from `/api/binaries` — that one asks only for a signed-in account,
  not an administrator, so the key is held to an explicit list of paths rather
  than to the role alone. A route not on that list is shut to keys until
  someone puts it there.
- The key is shown **once**, at creation. Only its SHA-256 is stored; a lost
  key is replaced, not recovered.
- Validity in days, or `0` for a key that does not expire. Expired keys stay
  in the list, marked, and are refused.
- **Master switch:** Settings → Interfaces → *API keys*. It is **off** from
  the factory, and switching it off refuses every key at once without
  deleting anything — the way to shut all integrations out in one step and
  let them back in later. A key is checked only while it is on.
- Creating and deleting a key is in the audit log; the list shows when each
  key was last used.

```bash
curl -s --cacert ca.pem -H "Authorization: Bearer dlp_…" \
  'https://central:8443/api/alerts?open=true&limit=50'
```

Keys can also be managed with a browser session (administrator):
`GET /api/keys` lists them without the secret, `POST /api/keys` with
`{"label": "siem", "days": 365}` (label 1–64 characters, days 0–3650, 0 =
never expires) answers once with the field `key`, `DELETE /api/keys/{id}`
removes one.

## Email notifications

Nobody sits in front of the dashboard at three in the morning. Settings →
**Notifications** points the central server at an SMTP server and says what
is worth waking someone for.

Any server does: a hosted mailbox on port 587 with STARTTLS, an SMTPS relay
on 465, or a mail bridge running on the same machine on `127.0.0.1:1025`.
Pick the transport security to match — **none** belongs to a relay on this
very machine and nowhere else, because it puts the password on the wire in
the clear. Leave the username empty for a house relay that accepts mail
without signing in. The password is stored on the server and never sent back
to the browser, like the AbuseIPDB key.

Three things trigger an email, each its own switch:

- **Alerts** — forbidden destination, hard limit, deviation from the
  baseline. The same three the overview counts, so the email says what the
  red number says.
- **An agent stops reporting** — no report for *An agent counts as down
  after* (default 10 minutes). This is the one nothing else tells you: a
  silent agent looks exactly like a quiet day. One email when a device falls
  out, one when it comes back, not one a minute in between. The agent list
  colours earlier, after three missed reports; a colour wakes nobody and an
  email does, so the email is the more patient of the two. Raise it if
  laptops going to sleep keep sending you down-and-up pairs.
- **A destination with a bad reputation** — the target address is known bad
  at AbuseIPDB, even if the flow itself stayed under every limit. Needs IP
  reputation switched on (see Settings → Reputation); only the cache is read,
  so this never costs a lookup of its own.

**One email per window, not one per event.** *Collect for* (default 5
minutes) is both the digest window and the rate limit: a mass copy that
raises two hundred alerts costs one email listing them, not two hundred. At
most 50 alerts are listed by name, the rest are counted. The window survives a
restart of the central server (it is kept in `settings`, not in memory), so
restarting does not release a held-back email early.

**An attempted upload does not wait.** It is the one case where an hour
between seen and read is an hour too many: the file is on its way to an
outside service. Such an alert sends on the next sweep (within a minute) and
takes everything else that is pending along with it, rather than sending a
second email shortly after. The subject leads with it. Recognised by the
destination — `upload to <URL>`, the form only the browser connector
produces; an ordinary outbound connection is an address and a port and keeps
collecting. A mass upload of two hundred files still costs one email, because
the worker only looks once a minute. Every email goes out
as text and as HTML, so a client without HTML shows the same thing.

**Time zone** is an IANA name such as `Europe/Zurich`; the default is `UTC`.
It governs the emails **and** every time the dashboard shows. Until
2026-09-09 the dashboard quietly used the zone of the browser looking at it —
right as long as that machine's clock is right, and unprovable the moment two
people read the same alert at two desks and see two different times. One
setting, one answer, for everybody. Summer and winter time follow from the
name, which is why this is a zone and not an offset. The abbreviation is
printed next to every time (`16:01 CEST`), because a bare clock time is
worthless as evidence when nobody can tell what it means. The dashboard picks
the value up at load, so reload after changing it.

**Dashboard address** is the only way the central server can put links in the
email — it does not know under which name you reach it. Leave it empty and
the email carries no links.

With it set, the time in every alert row is a link to **that** alert:
`/alerts?alert=<id>` opens the list showing only that one, unfolded, whatever
its state — an alert someone acknowledged in the meantime is still what the
link points at, so an email from yesterday does not land on "Nothing found".
The list filters on the identifier, not on the search box: a search for `1`
also finds 17 and every name with a one in it. A named row also beats the
category — the reputation trigger mails alerts whose verdict is a *notice*,
and the link has to find those too. "Clear filters", or the other category
tab, brings the whole list back.

**Save and send a test email** uses the *saved* settings, so it saves first
and then sends. What comes back is the mail server's own answer
("authentication failed", "connection refused"), and it is written to the
audit log as `notification_test`.

What has already been reported is remembered in the database, not in memory:
restarting the central server neither repeats an email nor swallows one. The
mark is set **after** a successful send — a mail server that refuses costs a
retry on the next pass, never a lost message.

## HTTP API

Everything the dashboard does goes through `/api/…` with the session cookie;
the four read paths above also take an API key. Administrator-only routes
are marked *(admin)*. Bodies and responses are JSON.

| Route | Purpose |
|---|---|
| `POST /api/login`, `POST /api/logout`, `GET /api/me` | session; login takes `{"name","password"}` and answers with the account, with `{"totp": token}` when a code is still needed, or with `{"passkey": true}` when the role requires a second factor and the account has only passkeys; ten failures lock the source IP for a minute |
| `POST /api/login/totp` | second step: `{"token","code"}` |
| `POST /api/login/passkey`, `POST /api/login/passkey/finish` | passkey sign-in: `{"name"}` gives a WebAuthn challenge; finish takes `{"name","credential"}` (the browser's `PublicKeyCredential.toJSON()`) |
| `GET /api/account` | own second factor: `totp_enabled`, `passkeys` |
| `POST /api/account/totp`, `POST /api/account/totp/enable`, `DELETE /api/account/totp` | authenticator app: start (secret, otpauth URL, QR as SVG), confirm with `{"code"}`, turn off |
| `POST /api/account/passkeys`, `POST /api/account/passkeys/finish`, `DELETE /api/account/passkeys/{id}` | passkeys: start with `{"password"}`, finish with `{"label","credential"}`, remove |
| `GET /api/overview`, `GET /api/counts` | dashboard tiles, reads per folder |
| `GET /api/alerts` | alerts; `category`, `open`, `verdict`, `kind`, `agent`/`source`, `q` text filter |
| `POST /api/alerts/{id}/ack`, `POST /api/alerts/ack` | close one alert, or every alert matching the filter |
| `POST /api/alerts/{id}/learn` | mark a notice's pair as known *(admin)* |
| `GET /api/alerts/{id}/explain` | the stored explanation of an alert, or `null` *(admin: the dossier quotes the agent log)* |
| `POST /api/alerts/{id}/explain` | gather the dossier, ask the model, store the answer *(admin)* |
| `GET /api/assist`, `POST /api/assist/test` | state of the AI assistance; test the endpoint without sending alert data *(admin)* |
| `GET/POST /api/rules`, `PUT/DELETE /api/rules/{id}` | folder rules *(admin)* |
| `GET /api/agents`, `GET /api/groups`, `GET /api/agents/{id}/log` | agents; AD groups seen; agent log *(groups, log: admin)* |
| `DELETE /api/agents/{id}`, `DELETE /api/agents/{id}/delete` | revoke certificate; delete the record *(admin)* |
| `GET /api/sources`, `PUT/DELETE /api/sources/{id}` | syslog sources *(admin)* |
| `GET/POST /api/tokens`, `DELETE /api/tokens/{id}` | enrollment tokens *(admin)* |
| `GET/POST /api/users`, `DELETE /api/users/{id}`, `POST /api/users/{id}/password`, `DELETE /api/users/{id}/second-factor` | dashboard accounts; new password; reset second factor *(admin)* |
| `GET/POST /api/keys`, `DELETE /api/keys/{id}` | API keys *(admin)* |
| `GET/PUT /api/settings` | settings *(admin)* |
| `GET /api/notifications`, `POST /api/notifications/test` | state of the email sending; send a test email *(admin)* |
| `GET /api/audit` | audit log *(admin)* |
| `GET /api/binaries`, `GET/POST/DELETE /api/binaries/{platform}` | agent installers: list; download, upload, remove *(upload/remove: admin)* |

The agent port (8444) speaks a separate, smaller protocol: `GET /agent/ca`
(the CA, no authentication), `POST /agent/enroll` (one-time token in, client
certificate out), `GET /agent/binary/{platform}` (the installer, checked by
the enrollment command against its SHA-256), and with client certificate
`POST /agent/report` and `POST /agent/renew`. The wire format is pinned in
`crates/deelpe-server/tests/central_wire.rs`.

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `DEELPE_DATABASE_URL` | – | Postgres connection (required). The server keeps a pool of up to **50** connections; Postgres allows 100 in its default configuration, so a second instance during an update or a hosted plan with a low connection limit needs `max_connections` checked first. |
| `DEELPE_DATA_DIR` | `/var/lib/deelpe-server` | CA, certificates, agent installers |
| `DEELPE_UI_ADDR` | `0.0.0.0:8443` | dashboard |
| `DEELPE_AGENT_ADDR` | `0.0.0.0:8444` | agents |
| `DEELPE_SYSLOG_ADDR` | `0.0.0.0:5514` | syslog (UDP+TCP) |
| `DEELPE_SERVER_NAMES` | `localhost,127.0.0.1` | names in the server certificate |
| `DEELPE_TRUST_PROXY` | `false` | behind a reverse proxy: client address from `X-Forwarded-For`, host name from `X-Forwarded-Host` (lockout, origin check, passkeys, enrollment command), and the session cookie keeps `Secure`. Only with a real proxy in front, otherwise the headers can be forged. Setup: [INSTALL.md](INSTALL.md) |
| `DEELPE_UI_HTTP` | `false` | dashboard without TLS (behind a proxy) |
| `DEELPE_LOG` | `info,sqlx=warn` | log filter |

## Development

The HTTP regression tests need `DATABASE_URL` pointing at a **development
Postgres** with the `CREATEDB` right. SQLx creates an isolated database with
migrations per test. Do not use a production database.

```bash
# Set DATABASE_URL from the local test environment; do not store it in the repo.
cargo test --workspace
cargo check --workspace --all-targets
(cd apps/web && npm test && npx tsc --noEmit && npm run build)
```

```bash
docker run -d --name deelpe-pg -e POSTGRES_PASSWORD=deelpe -e POSTGRES_USER=deelpe -e POSTGRES_DB=deelpe -p 127.0.0.1:5433:5432 postgres:18
DEELPE_DATABASE_URL=postgres://deelpe:deelpe@127.0.0.1:5433/deelpe DEELPE_DATA_DIR=/tmp/deelpe-srv \
  DEELPE_UI_ADDR=127.0.0.1:18443 DEELPE_AGENT_ADDR=127.0.0.1:18444 DEELPE_SYSLOG_ADDR=127.0.0.1:15514 cargo run -p deelpe-server
(cd apps/web && npm run dev)   # Vite with a proxy to 18443
```

Test line: `printf '<14>Sep  6 10:00:01 NAS01 WinFileService Event: read, Path: /volume1/GL/x.docx, File/Folder: File, Size: 1 MB, User: hans, IP: 10.0.0.5\n' | nc -u -w0 127.0.0.1 15514`

