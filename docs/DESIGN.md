# de-el-pe – Design

Lean data-loss detection tool for macOS and Linux. Detects when data leaves the
device out of folders the user picked, and warns.

Status: 2026-09-05. Result of the planning session.

## Scope

**v1 (warn only):**
- The user picks folders ("protected folders").
- A process reads from a protected folder → counts as *touched* from then on.
- A touched process sends data outward → correlation → alert.
- Covers: malware or a compromised process, a legitimate app phoning home,
  remote access with legitimate tools.

**v2:**
- Blocking at the network connection with an allow/deny dialog
  (macOS: Network Extension, needs an Apple Developer account; Linux: nfqueue/eBPF).

**Not in scope:** content classification, encryption, update check.
(Until 2026-09-06 this also listed "blocking at file access", "cloud" and
"telemetry"; lifted by the decision on the central server, see
[Central server and server agents](#central-server-and-server-agents-decision-of-2026-09-06).)

## Architecture

```
┌──────────────────────────────────────────────────────┐
│ deelpe daemon (root: LaunchDaemon / systemd)         │
│                                                      │
│  Sensors (platform-specific)      Engine (shared)    │
│  ┌──────────┐  ┌──────────┐      ┌───────────────┐  │
│  │ file     │─▶│ Event    │─────▶│ Correlation   │  │
│  │ network  │─▶│ Bus      │      │ Learning      │  │
│  └──────────┘  └──────────┘      │ Store (JSON)  │  │
│                                  └───────┬───────┘  │
│                                          │ unix socket
└──────────────────────────────────────────┼───────────┘
                                           ▼
                        deelpe CLI (no root, colour/tables/live view)
                        DLPrevent.app menu bar + window (macOS, Swift)
                        + system notification
```

One binary `deelpe`; `deelpe daemon` is the root service, everything else is
CLI. On macOS there is also a native menu bar app (`apps/macos/DeelpeBar`)
that speaks the same socket: an icon with a counter for unseen alerts, a
window with the alert table, a detail view, and the folder list with a folder
dialog. No dock icon, start at login through a LaunchAgent. Linux gets a tray
counterpart later. The wire format is a contract:
`crates/deelpe/tests/wire_format.rs` and the Swift tests check the same
literals.

Decision of 2026-09-05 (after M1): originally "CLI only", extended by the user
to a menu bar app with a window. A web interface in the root service stays
ruled out; the central server's web interface (2026-09-06) lives in a server
of its own, never in the daemon.

## Sensors

| Platform | File access | Network |
|-----------|---------------|----------|
| macOS     | `eslogger open exec copyfile clone rename exit mount unmount` as a child process, JSON stream | `nettop` batch mode, polling, gives destination + bytes |
| Linux     | fanotify (kernel ≥ 5.1) | `/proc/net/{tcp,udp}` + socket inodes from `/proc/<pid>/fd` |

Sensors deliver normalised events (`deelpe_core::event`); the engine knows no
platform.

## Correlation (M1)

A process that reads from a protected folder counts as *touched* for
`touch_ttl_secs` (default 10 min). If it then sends more than `min_bytes_out`
in total to one destination, there is an alert. Two ways around that have been
covered since 2026-09-05 (the result of a survey of DLP evasions):

- **Process chains.** `cat geheim | curl` reads with `cat` and sends with
  `curl`. A touch is passed up two generations to the parents; when sending,
  the process and two generations of ancestors are checked. Reader and sender
  may therefore be at most four generations apart: shell pipes and scripts
  with a subshell are in, Terminal.app itself (cat → zsh → login → Terminal)
  is not touched. What is reported is the sender, and the alert carries the
  reader in `via` ("read by com.apple.cat (PID 11)"). Inheritance stops at
  PID 1; ignored parents are skipped, not touched. An `exit` forgets the
  process, so that a reused PID inherits nothing. Side effect: after a `cat`
  in the terminal, the shell session reports harmless uploads too for
  10 minutes; the `via` entry explains that.
- **Copies.** A copy, clone or rename of a protected file, and writes by a
  *directly* touched process into ordinary files outside the protected
  folders, mark the target as *derived* for `derived_ttl_secs`
  (default 24 h, 1 h until 2026-09-05). Devices, `/System`, `/Library`,
  `/var`, hidden files and folders do not count as targets: otherwise every
  process would soon inherit a touch through `/dev/null` or the shell history.
  A read of a derived file counts like a read of the source; the alert names
  the source in `files` and the copy in `via`. For that, eslogger also
  subscribes to `clone`, `rename` and `exit`, and `open` reports writes
  through `fflag`. When the store is full (20 000 entries) the older half
  goes, not everything, so that nobody can make their copy be forgotten by
  writing en masse.

- **Trickle and flood** (since 2026-09-05, second round). The threshold
  applied per measurement interval: whoever stayed under 4 KB every 3 s sent
  many megabytes a day unnoticed. The correlator now sums per (sender PID,
  destination IP, port) for as long as the touch holds (`Flow`). The first
  report comes when the sum reaches `min_bytes_out`; after that the same
  alert (same ID, same `at`) is updated whenever the sum has grown by at
  least `min_bytes_out` and by half (`Outcome::Updated`, `last_at` set,
  `bytes_out` = the sum). An upload of 1 GB is thus one line with about 30
  updates instead of thousands of lines. Before that, Claude Code produced
  three alerts every 5 s. The end of the process or the expiry of the touch
  resets the sum.
- **XPC services** (since 2026-09-05, second round). Safari reads in the
  WebContent process and sends in the Networking process; both hang off
  launchd (ppid 1), not off Safari. Through ppid an upload out of Safari was
  invisible. eslogger supplies `responsible_audit_token`; if a process has
  ppid 1 and a different responsible process, that one counts as the parent
  (`effective_parent`). Otherwise ppid stands, so that `cat` in the terminal
  still touches the shell and not Terminal.app.

- **External volumes** (since 2026-09-05, third round; originally v2).
  A destination under `/Volumes/<x>` (snapshots excepted) or under a mount
  point seen at run time (mount events, without `/`, `/System`, `/private`,
  `/dev`). A copy, rename or hard link of a protected or derived file to
  there, or a write by a directly touched process to there, produces an alert
  with `volume` = the mount point, `remote` empty, `bytes_out` 0; the number
  of files stands in `via`. One alert per (PID, mount point) within the touch
  window, and further files update it. On unmount the path is an ordinary
  folder again. The learning phase lists such destinations as `volume:<Mount>`.
- **Copies out** (since 2026-09-05, fourth round; the user's question: "copy
  from Nextcloud locally and upload it afterwards"). A copy, rename or hard
  link of a file out of a protected folder to a place outside it (no volume)
  is an alert of its own with `copy_to` = the target folder, and like the
  volume alert one per (PID, target folder) with a counter in `via`. The copy
  stays derived, and a later upload is reported on top of that. Hidden and
  system targets (the trash, `.DocumentRevisions-V100`, `Library`) do not
  report, as with `write_target_counts`, otherwise every deletion would be an
  alert. Only the first step counts: a copy of a copy is silent (it is derived
  already), and so are writes by touched processes ("Save as"), otherwise
  every editor reports. Exception (2026-09-06, from diagnosing "cp to the
  desktop reported nothing"): if a directly touched process writes a file
  outside with the same name as the one it read, that counts as a copy out.
  `cp` without `-c`, rsync and browser downloads do not clone, they read and
  write; without the rule only `cp -c`, `mv`, `ln` and the Finder would be
  visible. Copies between two protected folders stay silent. The learning
  phase lists the destination as `copy:<Ordner>`, so Finder → Desktop goes
  silent after the learning phase.
- **AirDrop** runs through sharingd and AWDL to link-local addresses; nettop
  counts them. sharingd is not on the ignore list, so the alert already
  exists; it carries the note "link-local peer (AirDrop or local network)" in
  `via`. Not tested live against a second device.
- **Snapshots, firmlinks, hard links** (since 2026-09-05, third round).
  `Config::normalize` maps `/System/Volumes/Data/…` and
  `…/Backups.backupdb/<Mac>/<Zeit>/Data/…` (`Macintosh HD - Data` as well)
  back to the ordinary path; `is_watched` uses that, and the alert names the
  original in `files` and the snapshot path in `via`. Hard links: eslogger
  subscribes to `link`; the target becomes derived and (device, inode) →
  source is remembered. If somebody opens a file with `st_nlink > 1` whose
  inode is known, it counts like the source, even after the derivation has
  expired. The service learns the inodes of existing hard links as soon as the
  source is opened with `nlink > 1`. The inode table lives in the correlator's
  snapshot and does not expire; an inode number reused after a deletion can
  wrongly make an unrelated file with `nlink > 1` count as protected (rare,
  and only one alert too many).

**Ignore list** (`ignored` in the configuration): `TEAM/signing-id`,
`TEAM/prefix.*` or `team:TEAM`; without a team only `signing-id` or
`prefix.*`, which is weaker, because any Developer ID signature may call
itself `com.apple.backupd`. The service refuses `*`, prefixes shorter than
four characters, and `team:apple`. The defaults are Spotlight, Time Machine,
iCloud, XProtect (team `apple` = platform binaries) and Bitdefender (team
GUNFMW623Y), because they read every file and have the network. Unsigned
processes cannot be ignored. Maintained with `deelpe ignore` or in the app
("Ignore this process" in the alert creates `TEAM/signing-id`, the list is
under the gear).

## Process identity

- macOS: team ID + signing ID from the ES event. Unsigned = a category of its
  own, is always reported.
- Linux: path + SHA-256 of the binary. A changed hash → asked about once.

## Learning (model 3, implemented 2026-09-05 in `deelpe-core/src/learn.rs`)

1. A silent learning phase (`learn_days`, default 7): all pairs (process
   identity, destination network:port) are collected. The destination network
   is /24 or /48, because CDN and cloud addresses move around inside a
   network. Alerts from the correlator are stored all the same, with
   `verdict: learning`; the app does not count them as unseen and does not
   report them.
2. After it runs out, *review*: the same behaviour, and the app shows an
   orange bar. The user strikes out what they do not recognise
   (`LearnForget`) and confirms (`LearnConfirm`). On a first start with an
   existing log: alerts from the last `learn_days` count as observations, and
   the phase ends `learn_days` after the oldest.
3. After that, *active*: a new pair → `verdict: new`. In the alert the user
   decides "Remember" (`LearnRemember(id)`, the pair becomes known) or
   "Always report" (`LearnFlag(id)`, `verdict: flagged`).
4. Known pairs are dropped silently (the correlator's ID stays used up, gaps
   are normal), unless there is a deviation (`verdict: deviation`, `reason`):
   a sum above four times the largest *other* flow (from 3 observations on;
   the running flow does not compare itself with itself) or a time of day
   ±1 h never seen before (from 20 observations on, local time). A deviation
   stays visible for updates to the same alert.
5. Unsigned processes are never learned: always `new`.

Every change to the pairs needs root (like the protection list); the app goes
through the admin dialog. Store: `/var/lib/deelpe/learned.json` (0600), saved
on the 30 s tick and on shutdown. No SQLite: JSON is enough for a few hundred
pairs, and everything else in the service is JSON too.

## Storage

- **No database.** Everything the service keeps is a file under
  `/var/lib/deelpe`, mode 0600, owned by root: `alerts.jsonl` (the alerts),
  `state.json` (the correlator's memory), `learned.json` (the learning
  phase), `changes.log` (every change to the lists) and `agent.log`. The
  planning of 2026-09-05 had SQLite here for M2; M2 shipped without it,
  because a few hundred learned pairs and an append-only alert log do not
  need one, and one storage format across the whole service is worth more
  than the query language (see "Learning"). The central server is the one
  that has a database, and it is Postgres.
- Unix socket `/var/run/deelpe.sock` with 0660, group `staff` (macOS) or
  `deelpe`/`users` (Linux): not every local process may read.
- Only root may change things (the protection list, the ignore list) —
  decision of 2026-09-05: the service checks the peer UID on the socket.
  Before that, any program of the user's could send `WatchRemove` for every
  folder or have itself ignored. For that the app calls `deelpe watch add …`
  through the admin dialog (macOS remembers the authorisation for a few
  minutes); the CLI needs `sudo`. Every change goes into
  `/var/lib/deelpe/changes.log` (0600) and into the log.
- `/etc/deelpe/config.json` is 0600: otherwise the list of protected folders
  and exceptions gives away what is watched and what is not.
- Notifications come from the app (UNUserNotificationCenter), not from the
  service: a LaunchDaemon has no login session, and `osascript display
  notification` from root never reached the user. The app remembers the
  highest ID it knows and reports everything above it; from four new ones at
  once it sends one collected notification. Updates do not notify again.
- If a sensor dies (eslogger gone, full disk access missing), the service
  restarts it, with a pause of 5 s doubling up to 60 s; the error stands in
  the status for as long as it lasts. Before that the service carried on blind
  and only displayed the error.
- Integrity (since 2026-09-05): the service remembers the SHA-256 of
  `config.json` and `learned.json` in `state.json`, as it last wrote them
  itself, and checks on start and every 30 s. If the disk differs,
  "<file> changed outside the service" stands in `Status.warnings`, in the log
  and in `changes.log` (`EXTERNAL_EDIT`), and the app shows a red bar. Root
  can fake that too; this is about silent editing and scripts, not about an
  attacker with root.
- Password dialogs: a signed helper with a one-time authorisation needs the
  developer account. Until then the app collects strike-outs in the pair list
  (`pendingForget`) and sends them with the confirmation in one call, so one
  dialog; the strike-outs stay until the call has succeeded. Every other
  single action (Remember, Ignore, folder) is an `osascript` process of its
  own and therefore a dialog of its own.
- Host names: the learning phase knows only networks (/24, /48). A stranger's
  host in the same network as a known service stays a known pair; with nettop
  it cannot be had any better, and SNI would only come with the Network
  Extension. The app resolves destinations by reverse DNS (`HostResolver`,
  cache 7 days in `hosts-cache.json`) and shows the name in the table and the
  detail view, so that the user sees it.
- The correlator's memory (`/var/lib/deelpe/state.json`, 0600): touched
  processes, parents, derived files, inodes of hard links. Saved every 30 s
  when something changed and on SIGTERM, loaded on start. The PID-bound parts
  only if the identifier of the system boot (`kern.boottime`, Linux `boot_id`)
  is the same; derived files always. Otherwise an attacker could copy, wait
  out a restart of the service and then send.
- Raw events are never stored — they are correlated and dropped. Alerts:
  `alert_retain_days`, default 1 year (365), 0 = unlimited. Learned pairs and
  decisions: unlimited. (The central server keeps its own alerts for
  `alert_retain_days` as well, defaulting to 730 there.)
- Alerts live in `/var/lib/deelpe/alerts.jsonl`
  (one JSON line per alert in the wire format, 0600, append only; read on
  start and trimmed of anything older than a year, unreadable lines stay, IDs
  carry on). An updated alert is appended as a further line with the same ID;
  on reading, the last line per ID counts, and the file is compacted
  afterwards. Decision of 2026-09-05: alerts have to survive a restart and be
  exportable.
- Export: `deelpe export --format csv|json [-o file]`, and in the app the
  "Export" button above the alert list (a save dialog, CSV or JSON). Both
  fetch `AlertsAll` over the socket; the table (`Alerts`) loads 500 (since
  2026-09-05, 50 before that: Claude Code produced three alerts every 5 s and
  pushed everything else out). A filter field and "All stored" in the app.
  The column names are the same, the text values follow the language of the
  program in question; both are English. Until 2026-09-08 the
  app appended a column `abuse_score`; the IP reputation now sits in the
  central server (below).
- File names are stored, contents never.
- No outbound network access from the root service, and since 2026-09-08 none
  from the menu bar app either, apart from reverse DNS through the system
  resolver.

## IP reputation (AbuseIPDB, optional)

Decision of 2026-09-05: the destination IP of every alert is checked against
[AbuseIPDB](https://www.abuseipdb.com), so that known attacker addresses stand
out at once.

**Changed on 2026-09-08: the central server does this, not the Mac client any
more.** The old way gave every Mac its own key, its own cache and its own
daily budget; the same address cost ten times the quota across ten devices,
and the Windows agent had no reputation at all. Now there is one key, one
cache and one budget for every device — and the Mac client looks like the
Windows agent again.

- The module `abuseipdb.rs` in `crates/deelpe-server`, with tests against the
  documented response format and against the address ranges.
- Off until an administrator sets the switch in the dashboard (Settings →
  Reputation) **and** stores an API key. Without both, no request goes out.
- The key lives in `settings` and is never handed out again: the API reports
  only `abuseipdb_key_set`, and `skip_serializing` keeps it out of the audit
  log as well. A single hyphen in the field deletes it.
- Only the IP address goes out, never user, process, folder or file names.
- Sparing the quota (free: 1000 queries a day): the result per address for 7
  days in `ip_reputations`, private and reserved addresses are never queried,
  queries run one after another (20 a minute, 300 ms apart), and an invalid
  key or a 429 pauses the worker. The daily budget
  (`abuseipdb_daily_limit`) counts from the table rather than from memory —
  a restart does not set it back to zero and does not run into the block.
- Only what stands as a destination in the alerts of the last 30 days is
  looked up. The column `remote` also carries "volume …" and "copy to …"; the
  filtering happens in Rust (`ip_of`, `is_public`), not in SQL.
- Thresholds as in the AbuseIPDB documentation: from 25 % suspicious
  (orange), from 75 % malicious (red). The alert list shows a "Reputation"
  column, and the expanded row shows country, provider, reports, Tor exit node
  and a link to the report; "Check again" costs exactly one query and is
  reserved for administrators.
- No more popup: from 75 % the Mac client showed a modal NSAlert. In the
  central server the counterpart would be a notification — there is none there
  (yet), and a red cell in the list will do for now.

## Menu bar app (macOS)

- The app's interface is in English (decision of 2026-09-05); so are the
  code comments and the documentation.
- Outwardly the app is called "DLPrevent" (decision of 2026-09-05); bundle ID
  `ch.deelpe.bar`, while the service, the CLI and the data paths keep the name
  `deelpe`.
- Start at login: a checkbox in the settings; a LaunchAgent plist present in
  `~/Library/LaunchAgents` = on.
- Sync folders (decision of 2026-09-05: warn, do not exclude). If a protected
  folder lies under iCloud Drive, `~/Library/CloudStorage` (file providers:
  Nextcloud, OneDrive, Dropbox, Google Drive, Proton Drive), `~/Nextcloud`,
  `~/Dropbox` and so on, or carries the iCloud attribute (Desktop and
  Documents with iCloud sync), the app shows an orange note when it is added
  and an icon in the folder list. The sync client stays on the ignore list,
  otherwise the table is useless; but the user should know that this folder
  leaves the Mac through that client. `SyncDetector` in `DeelpeProtocol`, with
  tests.

## One-time setup (macOS)

- "Full Disk Access" for the `deelpe` binary (eslogger).
- An exception in Bitdefender.

## Central server and server agents (decision of 2026-09-06)

The result of the planning session of 2026-09-06. The goal: a central
dashboard for customer environments with Windows file servers, NAS appliances
and Mac and Windows workstations, which watches business-critical folders
(for example "GL") and stops data leaving them. None of it is built yet.

### The environment this is built for

- File servers: **Windows Server** with SMB shares. No fanotify, no kernel
  driver in the first stage.
- NAS: **various vendors** (Synology, QNAP, TrueNAS, …). No agent runs there;
  the central server receives syslog with one parser per vendor, all mapped
  onto the same internal event. A new brand = a new parser.
- Workstations: **a mix of Mac and Windows**.
- Identity: **not always AD.** Users internally as (source, name, optionally
  SID). With a SID they are merged across sources; without one, `Quelle\Name`
  stays separate. AD features (locking an account, AD groups) only when the
  agent is domain-joined; without AD, the server's local groups, and on a NAS
  an alert only.
- Size: **up to 500 endpoints, up to 10 file servers** per installation.
- **One installation per customer**, with no notion of a tenant in the data
  model. The reason: a bug in tenant filtering could lock accounts of the
  wrong customer. An overview across several customers will later be a
  meta-dashboard that asks only for health data, never for events.

### What "blocking" means (three layers per folder rule)

The server sees no "copy", only `smbd`/`srv` reading file X for user Y from
IP Z. Whether Y opens it in Word or drags it onto a USB stick is identical at
the server. Hence:

1. **Who may get in (lockdown, optional per rule).** Allowed groups, everyone
   else denied by ACL, before the first byte. The agent sets the ACL and
   checks it every minute; a deviation is reset and reported as "ACL drift".
   The agent changes ACLs **only** when the rule explicitly has lockdown,
   never otherwise.
2. **What those allowed in may do.** Edit without restriction. Mass access
   blocks temporarily, the CEO included: close the SMB session and a deny ACL
   for that user on that folder (the default). Locking the AD account is
   opt-in per rule, because it needs domain rights and a false alarm shuts the
   user out entirely; for a NAS it is the only lever. Blocks are kept in the
   central server (not only in the ACL) and lifted there with one click.
   Closing the session alone is not enough: `robocopy` reconnects.
3. **Where it may go from there.** Preventing a copy only works at the
   endpoint. The Mac agent already detects a copy out of `/Volumes/<Share>`
   and an upload after a read, and reports to the central server; blocking
   before the first byte needs the Apple Developer account (Mac) or a
   minifilter (Windows client).

   What is built of that is the **strict folder** (rule fields `strict`,
   `allow_destinations`, `enforce`, allow list in
   `deelpe-core/src/allow.rs`): once a process has read from the folder,
   every destination is forbidden except the allowed ones. The verdict is
   called `denied`, applies from the very first byte and deliberately goes
   past the learning phase — "block all" must not turn into "mostly" after
   seven days. The allow list knows only IPs and networks with an optional
   port: the service has no outbound network access and cannot resolve a name.

   `enforce` switches the rule from reporting to acting — without stopping the
   sender. On a Windows workstation three levers do that: the browser
   connector (refuses the upload before the first byte and knows the target
   URL), the network cage (a WFP filter at the ALE layer: takes the network
   away from the touched process without ending it), and locking and deleting
   the copy. macOS and Linux have the cage as well since 2026-09-15
   (`crates/deelpe/src/cage.rs`): on Linux a cgroup per caged process and an
   nftables table matching `socket cgroupv2`, on the Mac a Network Extension
   content filter in the app that gets the cage table from the service via a
   small XPC relay. Both hold the process rather than the EXE. Opt-in per rule
   rather than the default.

   **Nobody terminates the sending process any more.** That was what the
   checkbox used to mean, and it is gone since 2026-09-09: on that day the
   intervention killed the user's `explorer.exe` twice, over 330 and 446 bytes
   of Microsoft telemetry. A kill lands after the bytes are already out, takes
   open tabs or the whole desktop with it, and so prevents nothing.

On top of that an **emergency stop** per folder in the dashboard: deny for
everyone, close the sessions, lift it with one click.

**The threshold for mass access:** a fixed upper limit as an emergency brake
from day one (generous, about 100 files a minute) plus a learned baseline per
user and rule (learning phase, review, the fourfold deviation from
`deelpe-core/src/learn.rs`), with the sum running per (user, rule) as in the
correlator's "trickle and flood", not per minute only. A new user with no
baseline: the emergency brake only, plus an alert "no profile". The Windows
agent sets up the SACL ("audit success: read" on the folder) and the "audit
file system" policy itself when the rule is created.

### Architecture of the central server

- **`deelpe-server`**, Rust, one binary: axum, sqlx on **Postgres**, the web
  interface embedded as static files. It uses `deelpe-core` for event types
  and threshold logic, so that a NAS (condensed centrally) and a Windows agent
  (condensed locally) behave the same. Shipped as Docker Compose (server +
  Postgres) and as a .deb with a systemd unit for Ubuntu/Debian.
- **Interface:** a JSON API plus a single-page app (Svelte), modern, with a
  login. Local users, Argon2, session cookies, the roles admin and read-only;
  lifting a block, the emergency stop and switching on the AD lock are for
  admins only. No default password: the initial password is generated on first
  start and written to the log. OIDC (AD/Entra) later.
- **Transport:** the agent connects outward over HTTPS, the central server
  never to the agent. Counts and alerts by POST, the configuration (rules,
  thresholds, lifted blocks) collected every 30 s. Enrollment with an
  enrollment token from the dashboard, the agent gets a client certificate,
  the token is burned. The agent buffers locally and sends
  afterwards (built as a backlog in its state file, not as a database —
  see "Z2 as built").
- **Agents are autonomous.** Thresholds and reactions run in the agent; the
  central server watches and configures. Agents send **no raw events**, but
  counts per (user, rule, minute) and alerts. NAS syslog is condensed on
  receipt and the raw line dropped.
- **Retention:** alerts and blocks for years, counts for weeks.
- **Versions (the user's requirement, 2026-09-06):** always the newest major
  version, nothing that runs out in a year or two. Postgres: the newest major
  at the start of the build (as of September 2026 at least 18, 19 if it has
  been released; Postgres maintains each major for five years). The same for
  Rust (stable, raise `rust-version` in the workspace once a year), Svelte,
  Node in the build (the current LTS) and the Docker base image (Debian
  stable). Check dependencies with `cargo outdated`/`npm outdated` before
  every milestone.
- The wire format agent↔central server is a contract, as daemon↔app is today:
  shared literals in Rust tests.
- The Mac daemon gets a "reporting" module with the same protocol; the local
  app stays unchanged. With that the root service speaks outward for the first
  time — only to the configured central server, only with a client
  certificate.

### Z1 as built (implemented 2026-09-06)

Built and played through against Postgres 18 (syslog → source → rule →
emergency brake → alert; enrollment with a CSR and a client certificate →
report → update). Instructions: `docs/SERVER.md`.

- `crates/deelpe-server`: axum 0.8, sqlx 0.9 (queries at run time, no
  `query!`, so that the build works without a database), migrations in
  `migrations/`. Three listeners in a tokio-rustls loop of its own
  (`tls.rs`): dashboard 8443, agents 8444 with `WebPkiClientVerifier` against
  its own CA (`allow_unauthenticated`, so that enrollment works without a
  certificate; the handlers check `PeerCert`), syslog UDP+TCP. Cleanup
  hourly.
- PKI (`pki.rs`): the CA 10 years, the server certificate 825 days for
  `DEELPE_SERVER_NAMES` (reissued when names are missing), agent certificates
  730 days, CN = the agent ID regardless of the CSR. Renewal comes with Z2.
- Enrollment against a man in the middle: the enrollment command from the
  dashboard carries the SHA-256 of the CA; the agent fetches `/agent/ca`
  unchecked, compares the fingerprint, and only then speaks with the CA as its
  only root (reqwest 0.13 without the roots feature has no others). Tokens
  only as SHA-256 in the database, burned atomically (`UPDATE … WHERE used_at
  IS NULL`).
- Sign-in: Argon2id, a sliding 12 h session, cookie HttpOnly/Strict/
  Secure, 10 failures per address block for a minute, the same running time
  for an unknown name. A password of at least 12 characters. Every change in
  the `audit_log`.
- The access counter in `deelpe-core/src/access.rs`: per (user, rule) a
  window of distinct files (the emergency brake; an episode from the first
  breach on = one alert, updated) and days (the baseline: from 3 days on,
  four times the largest day, at least 20 files). The state is serialisable;
  the server holds it per source in `sources.meter`.
- Syslog parsers (`syslog.rs`): Synology (`WinFileService Event: … Path: …
  User: … IP: …`), QNAP (`Users: … Accessed resources: … Action: …`),
  Samba `full_audit` (`user|ip|machine|share|op|ok|…`), header RFC 3164 or
  5424. Only reads count. Rule paths relative (`GL` matches every folder
  called "GL") or absolute. Unknown lines count as "not understood" per
  source. **Open:** the formats come from the documentation, not from a real
  device; check them against real lines at the first customer and follow up
  the parsers.
- The Mac service (`crates/deelpe/src/central.rs`, `daemon.rs::central_loop`):
  `/etc/deelpe/central.json` (0600) with the URL, CA, certificate and key;
  `/var/lib/deelpe/central-state.json` with the generation, the distributed
  folders and a signature per alert sent (only changes go out). Central rules
  with an absolute path become protected folders, ones no longer distributed
  drop out again, locally created ones stay. Errors do not stop the service
  (backoff up to 5 min). CLI: `deelpe central enroll|status|remove`. Without
  `central.json` the service stays offline as before.
- The menu bar app (2026-09-06, second round): a "Central server" section
  under the gear. The enrollment command from the dashboard can be pasted in
  (`EnrollCommand.parse`), or the address (IP or host name, port 8444 is
  appended, https only), the token and the CA fingerprint are entered one by
  one; "Connect…" runs as `deelpe central enroll` through the admin dialog,
  like every change to the service. The state comes over the new socket
  request `CentralStatus` → `Central(null | {url, agent_id, …})`, without the
  key and the certificate, readable by any local client. The token stands
  briefly in the command line of the admin dialog (visible in `ps`); a
  single-use token is burned by the enrollment, so that is acceptable. A
  rollout token (`max_uses` NULL, or > 1) stays valid, which is why the
  dashboard asks to revoke it once the rollout is done. An older
  service answers `CentralStatus` with `Err`; the app then shows "Reinstall
  service…".
- The interface `apps/web`: Svelte 5, Vite 8, TypeScript, no UI framework,
  built into `crates/deelpe-server/ui-dist` (rust-embed; read from disk in a
  debug build, `build.rs` puts a placeholder there). Pages: Overview, Alerts,
  Rules, Agents (with tokens), Sources, Users, Settings, Audit log. Lockdown
  and the AD lock can be set on a rule, but are marked "from Z3" and have no
  effect.
- Packaging: `packaging/docker/Dockerfile` (node:24 → rust:1-trixie →
  debian:trixie-slim), `docker-compose.yml` with `postgres:18`,
  `packaging/deelpe-server.service` (hardened, port 514 through
  `CAP_NET_BIND_SERVICE`), cargo-deb metadata in the crate.
- The wire format agent↔central server: `deelpe-core/src/central.rs`, the
  contract in `crates/deelpe-server/tests/central_wire.rs`. One report per
  interval, and the answer is the configuration; there is no channel from the
  central server to the agent.

### Z2 as built (implemented 2026-09-06)

`crates/deelpe-winagent`, played through against a real machine: Windows
Server 2025, domain controller `corp.example`, share `GL` on `C:\Freigaben\GL`,
access over SMB from a second account and from a Mac. The chain is proven:
enrollment → policy and SACL set by the agent itself → 5145 read → condensed
locally → counts and an alert in the central server, with the SID as the user
key and the client IP.

**Two assumptions from the planning were wrong; both only showed up on the
real machine:**

- **5145 sits in the subcategory "Detailed File Share"** (`{0CCE9244-…}`),
  not in "File Share" (`{0CCE9224-…}`). The latter gives 5140, once per share
  connection, and therefore no file.
- **Over SMB, 4663 never carries `FILE_READ_DATA`.** Only `0x80` (attributes),
  `0x8` (extended attributes) and `0x20000` (READ_CONTROL) were observed. An
  agent that filters 4663 on `0x1`, as planned, sees **nothing** on a file
  server. 4663 stays in, but covers only local access on the server (console,
  RDP).

So 5145 is the main source, and it is richer than expected: it names the user
with the SID, the **client IP**, `ShareLocalPath` (`\??\C:\Freigaben\GL`) and
`RelativeTargetName` in one event. The planned merge over the logon ID
(`SubjectLogonId`) is dropped with nothing to replace it.

- **Set up by the agent:** the system policy through
  `AuditQuerySystemPolicy`/`AuditSetSystemPolicy` with the GUIDs of the
  subcategories — not through `auditpol.exe`, whose output is translated
  ("File System" is called "Dateisystem" on German Windows). Existing bits are
  kept. The SACL as the SDDL `S:(AU;OICISA;FR;;;WD)` through
  `TreeSetNamedSecurityInfoW` with `UNPROTECTED_SACL_SECURITY_INFORMATION`,
  with `SeSecurityPrivilege` in its own token (reasoning below).
**A second lab run on 2026-09-06** (six shares — GL, Allgemein, Finance, HR,
Engineering, Projekte, Vorstand — nine test accounts, nested groups). Five
things nobody would have noticed without the real machine:

- **5145 needs no SACL.** A share with no audit entry at all delivered
  complete SMB accesses including the alert, as soon as the subcategory
  "Detailed File Share" is set to success. The SACL carries only 4663, that
  is, local access on the server. A SACL that fails is therefore not a total
  outage but a gap at the console and over RDP — and the report to the central
  server now says exactly that.
- **`SetNamedSecurityInfoW` audits only the folder itself.** Without
  `UNPROTECTED_SACL_SECURITY_INFORMATION` Windows writes the SACL as protected
  (`S:PAI`); without the tree version `TreeSetNamedSecurityInfoW` no existing
  subfolder and no existing file inherits it. Measured: the folder with an
  entry, 400 files in it without one, not a single 4663. With both: the entry
  passed down to the file, and a local read produces 4663.
- **`SeSecurityPrivilege` is not enough when the DACL shuts the service
  account out.** On a share whose NTFS permissions know only the department
  group, setting the SACL ends with error 5 — reading as well as writing. At a
  customer that means: give the service account read on the protected shares,
  or do without 4663 there.
- **A relative rule path (`Finance`) is not a folder.** The agent resolves it
  to the local path through the share table; before that the SACL silently
  stayed off, and the dashboard still showed a green agent. The SACL state
  therefore now goes to the central server per folder as a sensor, and it is
  rechecked every round instead of believed once.
- **A backlog instead of a loss.** Counts and alerts stay put until the
  central server accepts them, and they are part of the state. Before that,
  every minute without a connection cost exactly the accesses of that minute
  — and a restart during the outage cost the rest. Both sides are
  idempotent (a count over (source, path, user, minute), an alert over
  `external_id`), so sending again does no harm.

- **Counting carries on over `EventRecordID`**, not over time: no time zones,
  no clock drift, no duplicated accesses.
- **Rules before events.** The agent only reads once the central server has
  sent it the rules. The other way round, the first pass pushes the read
  cursor to the end of the log with no rule loaded — and the agent then throws
  away exactly what happened while it was away. Noticed in the lab, not in the
  design.
- **Shared code instead of a second version:** enrollment and the client live
  in `deelpe-core::net` (feature `net`), the rule matching in
  `deelpe-core::rules`. The central server and the agent use the same check of
  the CA fingerprint and the same path logic; the server lost its own version
  of `rule_matches`.
- **The build happens on the Mac** for `x86_64-pc-windows-gnu` (mingw-w64) and
  the `.exe` is copied over. Build tools in the VM would need 6–8 GB.
- **The Windows service** (`service install|uninstall|start|stop|status`):
  autostart as **LocalSystem**, because that account has `SeSecurityPrivilege`
  (for the SACL) and may read the security log. A process from a logon session
  ends with it — without a service the agent is gone after signing out. The
  log goes to `C:\ProgramData\deelpe\agent.log`, without ANSI colours.
  Stopping writes the state and the read cursor survives: checked in the lab
  by reading 35 files while the service was stopped — the alert came after the
  restart. At a customer, a service account of its own with exactly those two
  rights belongs here instead of LocalSystem, as soon as Z3 intervenes.
- **Alternate data streams** (`datei.dat:AFP_AfpInfo`, created by macOS
  clients over SMB) are mapped back to the file, and a stream on the folder
  itself to the folder. Without that every file counts twice, the emergency
  brake trips too early, and the alert carries names nobody recognises as a
  file. The colon of the drive letter is left untouched (`strip_stream`, with
  tests).
- **Open:** the client IP of an updated alert is the one from the last access
  seen, not from all of them. (The log file was on this list too; it has
  rotated since — one rollover at 4 MB, `deelpe-core::agentlog`.)


### Service account and shares (2026-09-06)

**Least privilege, measured on the machine.** The agent first ran as
LocalSystem. That is more rights than it needs; with an account of its own it
goes like this:

```
deelpe-winagent service install --account "CORP\deelpe-svc" --password-stdin
deelpe-winagent rights grant  --account "CORP\deelpe-svc"
deelpe-winagent rights show   --account "CORP\deelpe-svc"
```

**Exactly three** things are granted, each with a reason for what breaks
without it:

| Right | What for | Without it |
|---|---|---|
| `SeServiceLogonRight` | start as a service | the service does not start |
| `SeSecurityPrivilege` | set the policy and the SACL, read the security log | no events |
| Group `Ereignisprotokollleser` (Event Log Readers, S-1-5-32-573) | read the security log | an empty query |

**Not granted: Administrators.** Confirmed in the lab: the account was only
in `Domain Users` and could still set the policy, write the SACL, read the
security log and report mass access.

`SeSecurityPrivilege` is itself a strong right — whoever has it can read the
security log **and clear it**. Less is not possible if the agent sets up the
auditing itself; that belongs in what you tell the customer. The password
comes only over standard input (`--password-stdin`), never as an argument:
that would stand in the process list. Best of all is a **gMSA**
(`DOMAIN\name$`) — then there is no password at all.

**Three traps that only the service account made visible:**

1. **Pushing the `.exe` into place with `move` brings the access list of the
   source folder along** (out of `C:\Windows\Temp` or the downloads folder,
   say). The file then inherits nothing from `C:\Program Files`, the service
   account may not read it, and the start fails with "Zugriff verweigert"
   (access denied), without saying what it was denied. `service install`
   **and** `service start` therefore fix the permissions themselves — `start`
   too, because every update sets the same trap.
2. **The agent locked its own files against itself.** The private access list
   for `central.json` and `state.json` knew only Administrators and SYSTEM;
   under an account of its own the state could no longer be written. It now
   also contains the SID of the account the process runs under.
3. **A `.tmp` left lying around blocks for good.** If a write breaks off, the
   file carries the old access list; after a change of account it cannot be
   written and saving fails for ever. It is removed before every write.

**Shares in the dashboard.** The agent status carries `shares` (name, local
path, description, where the path came from); the list stands on the agent
page, and "Create rule" opens the rule form with the path and the agent filled
in. Two sources, because one is not enough:

- `NetShareEnum` level 2 (with the local path) requires admin rights
  according to the documentation. **On this machine it gave names and paths to
  the service account without admin rights as well** (Server 2025, a domain
  controller) — which means it should not be relied on at other customers, in
  either direction.
- On top of that the agent learns `ShareName` → `ShareLocalPath` from the
  5145 events. That costs not a single right and carries even where the
  enumeration stays silent. Such entries show `learned` in the dashboard;
  what is reported is the union of both sources.
- **A note to remember from the debugging:** an empty share list in the
  dashboard was not a permissions problem but an **old server in the
  container**, which threw the new field away while deserialising. Every time
  the wire format grows, the server has to be rebuilt along with it, or you
  search at the wrong end.

### The flood of alerts and what stops it (decision of 2026-09-06)

The first run at a customer walked into something the design could not show:
2319 open alerts in the central server, 1931 of them for **a single pair**
(`com.anthropic.claude-code` → `160.79.104.10:443`) within 3.7 hours. Not a
bug in the detection — the chain is right and is built that way:

- In the active phase an unknown pair gives `verdict: new`, and `learn.rs`
  deliberately does *not* remember it in doing so. It only goes silent once a
  human presses "Remember" (section "Learning", point 3).
- "Remember" existed only in the Mac app. Whoever works with the central
  server had no way to it — so every flow of the same pair stayed a new open
  alert.
- On top of that the central server carried `verdict: learning` as open too,
  although by "Learning" point 1 that means "in the table yes, reported no".

Three remedies, all implemented on 2026-09-06:

1. **Closing in bulk.** A checkbox per row (shift selects a range),
   `POST /api/alerts/ack` with a list of IDs, and "close everything
   matching the filter" with the *same* condition as the list (`alert_where`
   in `api.rs` stands on its own for that reason). With thousands of rows,
   ticking them off page by page is not an interface.
2. **`learning` arrives already settled.** The server sets `acknowledged_at`
   on intake; on an update such a row opens again if it gets a verdict that
   has to be reported. Anything closed by hand (`acknowledged_by` set) stays
   closed.
3. **A learning instruction from the central server to the agent.** New in the
   wire format: `ReportResponse.learn` (open instructions) and
   `Report.learn_done` (what the agent carried out), the table
   `learn_commands`. An instruction carries the alert ID *of the agent* —
   only there are the process identity and the destination network known — and
   stays open until the agent ticks it off; a lost report therefore costs only
   one repeat. Carried out also counts "the alert has rolled out of the log"
   and "an unsigned process, never learned", otherwise the same instruction
   would come back for ever. It is carried out in
   `deelpe_core::pipeline::apply_learn` — by both agents, since 2026-09-10.
   Until then the Windows workstation dropped `resp.learn` on the floor: the
   click never did anything there, and because nobody ticked anything off, the
   central server repeated the same instruction every 30 seconds. Because an
   instruction necessarily comes **after** the report, the endpoint keeps the
   alerts it last reported (`reported_endpoint_alerts`, 200 of them); the Mac
   service uses its alert log for that.

This is the first way in which the central server changes the behaviour of a
device (distributing rules only changes *what* is watched). It therefore hangs
on a switch in the settings and is **off by default**; the switch takes effect
at delivery, not only when an instruction is created. An agent can tick off
only its own instructions (`agent_id` is part of the query); whoever ticks off
their own without carrying them out merely stays noisy themselves.

A second switch from the same round: the **syslog receiver**. Off means the
port is not bound, not merely that lines are thrown away — syslog is
unauthenticated and UDP is easy to forge, and a receiver nobody uses belongs
shut. The default stays "on", so that an existing server keeps hearing from
its NAS devices after the update.

### Order of work

1. **Z1 the central server without intervention.** (implemented 2026-09-06,
   see above) The server, Postgres, the login, enrollment, syslog reception
   with the Synology parser, reporting in the Mac daemon. The dashboard shows
   Mac alerts and NAS accesses. Look at a customer's real data before anything
   blocks.
2. **Z2 the Windows server agent, watch only.** (implemented 2026-09-06,
   see "Z2 as built") Read audit events, set the policy and the SACL itself,
   send counts and alerts, the learning phase.
3. **Z3 intervention.** Lockdown, a block on mass access, the emergency stop,
   lifting it, the AD lock as opt-in. Only here does the tool change anything
   on the customer's system, and only after observation data from Z2 at that
   same customer.
4. **Z4 the Windows client agent, report only.** ETW (file and network, no
   driver), the counterpart to Mac v1.
4b. **The Windows workstation (implemented).** `deelpe-winagent enroll --endpoint`
   starts the same correlator as the Mac service, fed from the event tracing
   of Windows: `Microsoft-Windows-Kernel-File` for "who reads what" (on the
   share too: the path arrives as `\Device\Mup\srv\GL\…` and is translated in
   `deelpe-sensors::winpath`) and `Microsoft-Windows-Kernel-Network` for "who
   sends where". No driver, no minifilter.

   That covers the case the file server cannot see in principle: dragging a
   single file from the share into a browser or an AI service. At the server
   that is the same event as "opening it in Word"; only at the workstation can
   you see that the same process sends outward afterwards.

   Three decisions that matter here:
   - **Fields through TDH by name**, not through fixed byte offsets. The
     payloads of the two providers differ between Windows versions; a wrong
     offset gives a number that looks plausible and is wrong. Costs two calls
     per field.
   - **Rule paths have to be complete at the endpoint.** A relative rule
     (`GL`) is resolved by the server through its share table; a workstation
     cannot do that. Skipped rules go to the central server as a sensor with a
     reason, otherwise a green rule that protects nothing would stand there.
   - **Program identity from the Authenticode signature**: the publisher from
     the certificate as the "team", `OriginalFilename` from the version
     resource as the "signing ID". With that the same ignore rules apply as on
     the Mac (`Google LLC/chrome.exe`, `team:Microsoft Corporation`), and the
     original name survives a rename of the file. Without a valid signature a
     program counts as unknown: always report, never learn. The check is
     remembered per path and fetches no revocation lists — the service has no
     outbound network access, and this does not change that.
   - **Path comparison without regard to upper and lower case**
     (`Config::under`). Windows paths are not case-sensitive; without that the
     protection fails exactly when somebody spells the share differently.

   Since 2026-09-08 the intervention is the **network cage** (`wfp.rs`), and
   it acts before the first byte: a WFP filter at the ALE layer, bound to the
   EXE, set at the touch and open again after 60 s without a further touch.
   It needs no signed driver and lives in a dynamic session — if the
   service dies, it opens by itself. Since 2026-09-09 the agent no longer
   terminates the sending process.

   **First lab run on 2026-09-07** (Windows 11 Enterprise 10.0.26200,
   workgroup, an account with admin rights, over SSH). Both providers deliver:
   the keywords, event IDs and the field names through TDH are right, the
   kernel paths are translated correctly, the byte order of the port is right
   (80, not 20480), and the signature check recognises programs
   (`TiWorker.exe`, `powershell.exe`). The complete chain was measured:
   `powershell.exe` reads `C:\GLTest\zahlen.txt` and then sends to an external
   address.

   Three bugs that only the real machine showed up:

   - **The service ran the wrong loop.** The role from the enrollment was
     only read from the command line; `service run` called the file-server
     loop outright. A machine enrolled as a workstation therefore read a
     security log with nothing in it — and in the dashboard everything looked
     green, only the sensor was called `security-eventlog` instead of `etw`.
     The decision now lives in `run_role()`, in exactly one place that both
     routes use.

   - **The session was never stopped.** The callback set a stop flag, but
     `ProcessTrace` only returns when the session actually ends — and an ETW
     session outlives the process that started it. The agent carried on
     running after the end and could only be got rid of with `logman stop`.
     Now the callback stops the session as soon as nobody is listening any
     more, and `trace` does it itself at the end.
   - **Events were lost silently.** Unfiltered, over 20 000 file events
     arrived in five minutes, from Windows Update alone. The
     channel filled up, `try_send` dropped — and what got dropped was
     precisely the access that mattered. A tool that loses the interesting
     access under load is worthless. Filtering now happens **in the
     callback**, at the point where the mapping file object → path comes into
     being: only files under the protected folders get into the channel at
     all. Filtering any later does not help, because by then the queue is
     already full. Whatever is dropped all the same is counted, and the
     counter goes to the central server as the sensor's state — a silent loss
     is worse than a red line in the dashboard.

5. **Z5 blocking at the endpoint.** Mac with the developer account, Windows
   with a minifilter.

Deliberately rejected: blocking in the kernel of the file server (a
minifilter: months of work, and the server still does not see the problem),
the central server calling the agents (firewall rules per agent), Grafana on
its own (it cannot block), and multi-tenancy "retrofitted later".

## Milestones

1. **M3 (done, 2026-09-12):** Linux sensors and the systemd unit. fanotify
   for file access, `ss` for the bytes sent. What is deliberately missing is
   named in the sensors themselves; blocking on Linux is M4.
2. **M4 (v2):** blocking at the endpoint's network. (USB/AirDrop shipped with
   the macOS agent on 2026-09-05.) Corresponds to Z5 above.
3. **Z1–Z5:** the central server and the server agents, see the section above.
   Z1 begins after the user confirms.
