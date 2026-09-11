# DLPrevent

Lean data-loss detection for macOS and Windows (Linux to follow), with a
central dashboard. You pick the folders; the tool warns when a program reads
from one of them and then sends data outward.

![DLPrevent central dashboard: open alerts, hard-limit verdicts, reads per folder and top readers](docs/images/dashboard.png)

Two parts, usable separately:

- **Standalone.** The **DLPrevent** menu-bar app plus a background service on
  the Mac. Runs on its own, with no outbound network access.
- **Central server.** A dashboard with login that agents report to, syslog
  intake for NAS boxes without an agent (Synology, QNAP, TrueNAS/Samba), and
  rules for business-critical folders with an emergency brake and a learned
  baseline per user.

**Language:** English throughout — app, dashboard, command line, protocol,
this documentation and the comments in the source.

## Scope, limits and your obligations

Read this before the first agent goes out. None of it is a setting in the
dashboard; all of it is the operator's decision.

**It detects. It does not make data loss impossible.** DLPrevent watches the
folders you name and reports when a program reads from one of them and then
sends data outward. What it stops before the bytes move is narrow: a strict
folder deletes the copy and cages the sender, and an upload is refused in
Firefox only. Everything else is reported after the fact, or not seen at
all — a photo of the screen, a private phone, an encrypted container, a
channel nobody monitors. Treat it as one control among several, never as the
one that makes the others unnecessary.

**It is not an antivirus and replaces no part of your security stack.** No
malware detection, no EDR, no backup, no patch management, no access
control, no firewall. A folder the wrong people can read is a permissions
problem, and DLPrevent will do no more than tell you it is being read.

**The network is yours to segment.** The agent port (8444) belongs in the
agent networks, the dashboard (8443) in the administration networks, and
syslog (514) must never leave the internal network — it is unauthenticated
and the sender address can be forged. The central server holds `ca.key`;
whoever takes that can enrol as any agent. Put the server on a segment that
matches what it is worth, keep its backups off the shared drive, and verify
the firewall rules rather than assuming them. The documentation names the
ports. Deciding where they may be reached from is your job, not the tool's.

**Inform and train the people you are watching.** The tool records who read
which file and where it went. In most jurisdictions that is personal data
and monitoring at the workplace, and it is regulated — in Switzerland the
DSG, Art. 26 ArGV 3 and Art. 328b OR, in the EU the GDPR and usually an
agreement with the works council. Inform your staff before the rollout,
obtain whatever approval applies to you, and train the people who read the
alerts: an alert nobody understands is an accusation waiting to be made
against the wrong person. Set `alert_retain_days` to a period you can
justify — the default of two years is a default, not a recommendation. This
paragraph is not legal advice; ask your own counsel.

**No warranty.** The [licence](LICENSE) provides the software as is and
disclaims all warranties, and that is meant literally. False positives,
missed events and a sensor that the next Windows or macOS release changes
underneath you are all possible; the checks built into the agent (`trace`,
`check`, `probe`) exist because of it. Run them, and re-run them after every
operating-system upgrade. Whether the tool is configured, segmented and
staffed well enough for what it is guarding is something only the operator
can judge, and it stays the operator's responsibility.

## Documentation

| Topic | Where |
|---|---|
| Install, update, uninstall, mass rollout, moving the server | [docs/INSTALL.md](docs/INSTALL.md) |
| Central server: dashboard, roles, rules, agents, NAS, API | [docs/SERVER.md](docs/SERVER.md) |
| Something does not work | [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) |
| Building, layout, tests | [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) |
| Design and decisions | [docs/DESIGN.md](docs/DESIGN.md), [docs/adr/](docs/adr/) |

## What it detects

- **Read, then send.** A program reads from a protected folder and then
  sends more than 4 KB outward. Volume is counted per program and
  destination, so slow trickling is caught too. A long upload is one
  warning whose volume grows, not one warning per measurement.
- **Process chains** such as `cat secret.pdf | curl -d @- …`: one program
  reads, another sends. The warning names both. Apps with helper processes
  (Safari reads in one process and sends in another) are merged.
- **Copies and renames.** A copy counts as the original for 24 hours.
  Copying out of the folder is itself a warning, including from Finder or a
  Nextcloud folder; a later upload of the copy is reported as well, naming
  the source.
- **USB sticks and network drives.** A program that read from the folder
  writes or copies to an external or mounted volume. One warning per program
  and volume, with the file count.
- **Strict folders ("block all").** A folder distributed by the central
  server can be declared off-limits: nothing may leave it except to
  explicitly allowed destinations (IP or network, optional port). Browser
  upload, AI service, PowerShell — only the destination counts. Such
  warnings appear from the first byte and are never learned. Optionally the
  service does not just report them but blocks: the browser upload before
  the first byte, the network of the sending program, the copy that left the
  folder.
- **Copying out of a strict folder is forbidden as well** — to local disk,
  a USB stick or a network drive. On a Windows workstation the agent removes
  the copy again when "Enforce" is set; the Mac only reports it.
- **AirDrop and LAN neighbours** are labelled as such.
- **Detours to the same data:** Time Machine snapshots, system firmlinks and
  hard links count as the original.
- **Reputation check (optional).** The central server checks the destination
  IP of every alert against AbuseIPDB and shows how badly the address is
  known — one API key and one cache for the whole fleet, configured under
  Settings → Reputation. Only the IP address leaves the network, never a
  user, process, folder or file name. The Mac app shows the host name of the
  destination; only the DNS query leaves the machine.

System services that read every file and have network access (Spotlight,
Time Machine, iCloud, XProtect, Bitdefender) are on an exception list.
Unsigned programs are always reported.

## In the app

- Warnings arrive as notifications; a click opens the window. The icon turns
  red on a new warning and orange when a protected folder lives inside a
  sync folder (iCloud Drive, Nextcloud, Dropbox, OneDrive), because the sync
  client stays on the exception list.
- "How" in a warning shows the route the data took to the sender.
- Filter field over the warning table: every word must occur, `-word`
  excludes. Export as CSV or JSON.
- "Ignore this process" for a service that reports constantly.
- Changes to the protection and exception lists need the admin password, so
  no program running as the user can quietly switch protection off.
- Warnings are kept for a year by default and survive restarts; every change
  to the lists is logged.

## Learning phase

For the first 7 days the service quietly collects which programs send to
which destination networks. Warnings appear in the table with the verdict
"learning" and no notification. After that the app shows "Review": go
through the list, strike out what you do not recognise, confirm. From then
on only what is new gets reported, what you marked "Always report", or what
deviates: much more volume than ever seen, or a time of day never seen
before. "Remember" in a warning makes a pair known. Unsigned programs are
never learned and always reported.

## Central server (dashboard for several devices)

For environments with file servers, NAS boxes and several workstations. One
installation per customer, deliberately without tenants. Docker or
Ubuntu/Debian package.

- **Dashboard with login:** open alerts, verdicts, reads per folder, top
  readers, working through warnings.
- **Agents enrol with one command.** An administrator uploads the installer
  once; the command shown in the dashboard downloads it onto the device,
  checks its checksum and enrols in one go. The agent generates its own key,
  the dashboard's fingerprint pins the server, and a token is good for
  exactly one enrolment. Enrolled agents report every 30 seconds and pick up
  protected folders from the server.
- **Three roles from two artefacts:** Windows workstation and Windows file
  server share the same EXE, the role is chosen at enrolment; macOS gets the
  app bundle.
- **NAS over syslog:** Synology, QNAP, TrueNAS/Samba send their file access
  log to the server; sources appear with the first packet.
- **Rules for critical folders:** strict folder with allow list, emergency
  brake on mass access, learned baseline per user.
- **Email notifications:** SMTP to any server, with a switch each for
  alerts, an agent that stops reporting, and a destination with a bad
  reputation. One digest per window, not one mail per event.
- **AI assistance (optional).** An **Explain** button in an alert: the server
  gathers what an administrator would otherwise look up by hand — the rule
  that matched, the destination's reputation, the same user's week, the same
  process across the fleet, the agent's log around that minute — and has a
  language model summarise it in three paragraphs. It decides nothing and
  runs only on a click. Any OpenAI-compatible endpoint: Ollama in your own
  network, where nothing leaves the house, or a hosted one such as Infomaniak.
  Off by default; what went out is stored word for word next to the answer.
- **API keys** for a SIEM or a script.

## Blocking on Windows: what is caught and what is not

Detection at the file level is **after the fact**. A copy exists for a second
or two before the agent removes it, and a rename or repackaging escapes the
user-mode agent entirely. Closing that would take a kernel driver; one was
built and measured, and removed again on 2026-09-09 because it never loaded
outside a lab with Secure Boot off. What that costs, and which ways out of a
strict folder are open because of it, is written down in
[ADR 0001](docs/adr/0001-endpoint-blocking-minifilter.md).

What does stop an upload works before the first byte and needs no driver: the
browser connector refuses and knows the target URL, and the network cage takes
the network from a program that has read from a strict folder
([ADR 0002](docs/adr/0002-upload-blocking-splits-by-egress-channel.md)).

## Status

Milestone 1 (macOS, warn) and the learning phase (M2) are in, plus the
central server at stage Z1: observe and report. The first intervention is the
strict folder — on the Mac and on the **Windows workstation**, whose sensors
have run on real hardware (Windows 11 Enterprise, 2026-09-07). That also
catches what a file server fundamentally cannot see: dragging a file from
the share into a browser or an AI service.
Stopping such an upload before it moves needs the browser to ask, and today
only **Firefox** does — Chrome and Edge are reported after the fact, see
[SERVER.md](docs/SERVER.md).

Next up is the Windows server agent (Z2, observe only), then locking down at
the file server (Z3: lockdown by permission, blocking on mass access,
emergency stop). Linux sensors (M3) follow. Blocking at the endpoint on macOS
needs an Apple Developer account and is v2; on Windows the file-level layer
reports and deletes the copy, while the upload itself is stopped by the
browser connector and the network cage.

## Roadmap

- **Windows kernel driver for customers.** A minifilter is the only way to
  refuse a copy *before* it happens. The lab version is removed; a shippable
  one needs an EV certificate and Microsoft attestation signing. See
  [ADR 0001](docs/adr/0001-endpoint-blocking-minifilter.md).
- **macOS app signing.** Developer ID signature and notarization, so
  installation works without Gatekeeper overrides.
- **Cloud hosting on request.** A hosted central server per customer,
  operated by us. Ask via info@dlprevent.ch.
- **Role-based access control.** Today every dashboard login is an
  administrator. Planned: viewer, operator and admin, per agent, agent group
  or whole server.
- **Enterprise Single Sign-On (SSO).** Support for SAML 2.0 and LDAP directory integration. Allows customers to authenticate via their own Identity Provider (Microsoft      Entra ID, Okta, on-prem Active Directory, etc.) for centralized dashboard acces

## License

DLPrevent is open source under the [Apache License 2.0](LICENSE): use it,
change it and pass it on, commercially too, as long as the copyright and
license notices go with it ([NOTICE](NOTICE)).

The [enterprise edition](#enterprise-edition) is licensed separately under
commercial terms and is not part of this repository. Everything in this
repository stays free under Apache 2.0.
