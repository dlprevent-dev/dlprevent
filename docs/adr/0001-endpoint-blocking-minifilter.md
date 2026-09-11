# ADR 0001: Blocking at the Windows endpoint needs a minifilter

- **Status:** superseded 2026-09-09 — the driver was removed from the
  product; everything above the *Update* at the end records what was decided
  and measured on 2026-09-07 and still holds
- **Date:** 2026-09-07
- **Affects:** `deelpe-winagent` (workstation role), strict folders
  ("block all"); `drivers/deelpe-flt` until it was removed

## Context

The workstation agent detects in user mode that a file is leaving a strict
folder, and then deletes the copy again. That is a **follow-up**: the copy
comes into existence, lives for a second or two, and is then removed.

On 2026-09-07 we walked 14 ways out of the folder on the test client
(`DESKTOP-EXAMPLE`, rule `\\fs-01\GL`, strict + enforce). Six were
detected and the copy deleted: `copy`, `xcopy`, `robocopy`, `Copy-Item`,
`File::Copy`, `Get-Content|Set-Content` — each under the same file name.
Eight got through:

| Way | Why it gets through |
|---|---|
| copy under a **different name** | detection compares file names |
| `type source > target` | the target is opened before the source is read |
| **ZIP** (`Compress-Archive`) | contents leave under a new name |
| **base64** | likewise, plus a changed format |
| `move` on the same volume | a pure rename, no data events |
| **alternate data stream** | the stream path is not covered |
| `\\127.0.0.1\c$\…` | the write goes through the SMB redirector (PID 4) |
| target folder with a leading dot | was a Unix rule; since fixed |

A ninth way, found on 2026-09-09 and not part of that walk: a **0-byte file**.
It leaves under its own name, and nothing sees it — ETW reports file *I/O*, and
a copy of nothing performs none. Neither the read in the folder nor the write
outside produces an event, so the correlator never learns the file exists.
Measured on `DESKTOP-EXAMPLE` with `deelpe-winagent trace`, copying the same
name at four sizes: 0 bytes gives 0 read and 0 write events, 1 byte already
gives 1 and 2. The extension plays no part.

It stays open on purpose. What escapes is a file name, not a payload, and the
alternate-data-stream row above is open at *every* size, so this adds no
attack surface to it. Closing it in user mode means treating an **open** as a
touch, and that is the change that killed Firefox twice and deleted the user's
`desktop.ini` — a bad trade for zero bytes.

On top of that, the race: whoever uploads faster than the agent deletes has
the data out. And the second line of defence — "the copy counts as derived, a
later upload is caught" — does not hold on Windows: a renamed copy is not
recorded as derived, and its upload from another process went unnoticed in
the test (20 KB sent, no alert).

The common denominator is not one bug but the shape of the thing. Event
tracing reports **after** the write, and it reports paths and PIDs, not
intent. Nailing down each gap individually leads to "delete everything a
touched process writes outside" — and that deletes the Defender cache, the
search index, the browser profile and the Word document somebody saves
elsewhere after opening a file in GL.

## Decision

Real blocking at the endpoint is its own stage, built on a **file-system
minifilter** (FltMgr), not on further tightening in user mode.

The driver acts before the operation, not after:

- `IRP_MJ_CREATE` (pre): opening with write intent **outside** a protected
  folder by a process that has read from a strict folder →
  `STATUS_ACCESS_DENIED`. The file never comes into existence.
- `IRP_MJ_WRITE` (pre): the same for targets that are already open. This is
  what catches `type source > target`, where the target was opened before the
  process was tainted.
- `IRP_MJ_SET_INFORMATION` (pre): `FileRenameInformation` and
  `FileLinkInformation` out of the folder — catches `move` and hard links.
- The taint is kept **in the kernel**, per process, from the data stream
  itself. That makes it independent of file name, format and ordering: ZIP,
  base64, alternate data streams and renaming all fall under it alike. It must
  arise at `IRP_MJ_CREATE` with read access, though, **not** at the first byte
  read — otherwise the driver inherits the 0-byte gap above. The create path
  carries `DesiredAccess`, which is exactly the field ETW does not expose, so
  in the kernel this costs nothing.
- The rules arrive from the agent over a communication port; the driver holds
  only the path list and the taint table.

**Behaviour on failure: fail-open.** No driver, no port, no rules → let it
through. A DLP driver that locks the file system on its own error cripples
the workstation; that is worse than the leak it is meant to prevent.

**Exception: the policy survives a disconnect.** The agent opens the port per
message (connect, send, close), so a disconnect arrives after *every* report.
Clearing the rules there wiped the policy that had just been set — measured
on 2026-09-07: `PolicySet` counted up while `PathCount` stayed 0 and nothing
was ever blocked. Beyond that, for a strict folder fail-**closed** is the
right call: if the guard dies, the door stays shut. Fail-open covers the
driver's own doubts (no name, no rule), not the question of whether the agent
is still alive.

## Result

Measured in the lab on 2026-09-07 with the driver loaded: **not a single byte
leaves the folder.** Seven of the eight ways above are refused outright; with
`type >` the empty target is created before the taint and the data write is
then denied — 0 of 20480 bytes. A plain copy fails with "Access denied" and
the file does not appear.

Two bugs in the first version were only found through counters built into the
driver — without a kernel debugger it was blind guessing:

1. `PortDisconnect` cleared the policy (see above).
2. The unload callback called `FltUnregisterFilter` itself. FltMgr does that
   after the callback returns; doing it inside tears the filter down halfway —
   `fltmc` no longer knew it, `sc` still showed the service RUNNING, the
   `.sys` stayed locked, and only a reboot cleared it. That cost three
   reboots before it was noticed.

Take-away for anything kernel-side: build the diagnostics in from the start.
A minifilter with no way to report on itself cannot be debugged in the field.

## What the driver does not solve

It blocks writing outward, not reading. Whoever has the data on screen can
retype it, photograph it, read it aloud. An upload straight from the reading
process (a browser uploading from `\\srv\GL`) is a **network** operation and
belongs to a Windows Filtering Platform filter at the ALE layer — a separate
piece of work next to this one.

## Cost and prerequisites

- **Building:** a Windows machine with the WDK and MSVC. Not possible on the
  Mac where the rest of the agent is built; the mingw toolchain cannot
  compile kernel code. That is a new line in the build instructions and a
  second environment to maintain.
- **Signing:** in the lab, Secure Boot off and `bcdedit /set testsigning on`.
  For customers there is exactly one path, and it is not cheap:
  - An **EV code-signing certificate** for the company (~300–600 CHF/year,
    hardware token or cloud HSM). Company validation takes days to weeks and
    is the bottleneck.
  - A **Partner Center** (Hardware Dev Center) account, whose registration is
    signed with that EV certificate. Free, one day.
  - **Attestation signing**: upload the `.cab`, get it back signed by
    Microsoft. Minutes to hours, **per build**.

  Two shortcuts that do **not** work, checked on 2026-09-07: **Azure Trusted
  Signing** does not sign Windows drivers and issues no EV certificates, and
  **cross-signed** kernel drivers lost their default trust with the April
  2026 update (Windows 11 24H2/25H2/26H1, Server 2025). Attestation via
  Partner Center is the only remaining route.

  Realistically **1–3 weeks to the first shippable driver**, almost entirely
  waiting on the certificate.
- **Risk:** a faulty minifilter produces a bugcheck or a machine that will
  not boot. It needs its own test environment (a VM with snapshots), Driver
  Verifier, and a documented way to get rid of it from safe mode.

## Alternatives

- **Stay with the follow-up.** Catches the careless user, not the determined
  one. Honestly documented, that is enough for many customers — and it is
  what ships today.
- **Buy it** (Microsoft Purview Endpoint DLP). Brings the same kernel filter
  ready-made and signed, costs licences and ties you to their ecosystem.
- **Do not let the data onto the endpoint at all** (a published application
  over RDS/Citrix without drive and clipboard redirection). Solves the
  problem architecturally instead of at the endpoint — often the better
  answer.
- **Protect the file itself** (RMS/AIP encryption). The copy succeeds but is
  useless outside.

Note on how the field handles this: most open-source security tools ship **no
driver at all** — Wazuh, osquery and Velociraptor observe through ETW and do
not block. Sysmon does have a minifilter, but it is signed by Microsoft
because it is a Microsoft product, and it too only reports. Projects that
really block have a company behind them that bought the EV certificate. There
is no community signing for open source; the signature is tied to a legal
entity.

## Consequences

Until the driver ships, this holds for strict folders: deleting the copy is a
**deterrent against carelessness, not a control against intent**. That is how
it goes into the customer documentation — not as "block all" without a
footnote.

The EV certificate is worth buying regardless of the driver: the agent EXE is
unsigned today, which means SmartScreen friction on every customer machine.

## Update 2026-09-09: the driver is removed

`drivers/deelpe-flt` is gone, along with its port client
(`deelpe-winagent/src/flt.rs`), the policy push in `client.rs`, and the
kernel-path translation that fed it (`winpath::to_kernel_path`,
`procinfo::reverse_volume_map`). Nothing above this line is retracted: the
measurements stand, and the Decision was right for what it set out to do.

What ended it was not the design but the cost of carrying it. It never
loaded outside a lab with Secure Boot off and testsigning on, and on the test
client it had not been loaded at all since 2026-09-07 — the agent pushed its
policy once a round into a port nobody answered, silently, because the client
falls back without complaint. A blocking layer that is dark and reports
nothing about being dark is worse than no blocking layer: the documentation
claimed protection the machine did not have. Shipping it for real still needs
the EV certificate and attestation route costed above, which nobody has
bought.

Two defects were found in review before the removal, both now moot, both
worth knowing if this is ever rebuilt:

- **The driver had no process exception list.** `PostCreate` tainted *every*
  user-mode PID that opened a protected file for reading — an Explorer
  thumbnail was enough — and from then on refused that process every write
  outside the folder until it exited. `explorer.exe` would be unable to write
  anywhere; so would `SearchIndexer.exe`, and so would `MsMpEng.exe`, whose
  signature and quarantine writes are how Defender works at all. The
  user-mode agent has such lists (`enforce::CRITICAL`, `wfp::NEVER_CAGE`);
  the kernel side had none. Ironically the Context above names "deletes the
  Defender cache" as the reason *against* the user-mode approach, and the
  driver reproduced it.
- **The altitude was a placeholder.** 268000, marked "Testwert" in the INF
  and never requested from Microsoft. The band is right (content screener,
  below the AV range at 320000–329999, so the scanner sees the I/O first),
  but an unregistered altitude collides with whatever else claims it.

## What is open again

The nine ways out of a strict folder that the Context measured are open once
more, and the user-mode agent catches six of them (`copy`, `xcopy`,
`robocopy`, `Copy-Item`, `File::Copy`, `Get-Content|Set-Content`, each under
the same file name) by deleting the copy afterwards. These get through:

| Way | Why |
|---|---|
| copy under a **different name** | detection compares file names |
| `type source > target` | the target is opened before the source is read |
| **ZIP** (`Compress-Archive`) | contents leave under a new name |
| **base64** | likewise, plus a changed format |
| `move` on the same volume | a pure rename, no data events |
| **alternate data stream** | the stream path is not covered |
| `\\127.0.0.1\c$\…` | the write goes through the SMB redirector (PID 4) |
| **0-byte file** | a copy of nothing performs no I/O, so ETW reports none |

Plus the race that outruns the delete, and the renamed copy that is not
recorded as derived.

So the sentence from *Consequences* is now the whole truth, with nothing
pending behind it: for strict folders, deleting the copy is a **deterrent
against carelessness, not a control against intent**. What does stop an
upload still stands and is unaffected by this removal — the browser connector
refuses before the first byte, the WFP cage takes the network from a tainted
process, and the copy is locked and deleted (ADR 0002).
