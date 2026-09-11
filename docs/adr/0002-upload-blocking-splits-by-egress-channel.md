# ADR 0002: Blocking an upload out of a strict folder splits by egress channel

- **Status:** accepted; both agent-side layers built, the cage measured on
  the client 2026-09-08 (see *Built* at the end)
- **Date:** 2026-09-08
- **Affects:** `deelpe-winagent` (workstation role), strict folders
  ("block all") and their allowed destinations, stage Z5
- **Relates to:** [ADR 0001](0001-endpoint-blocking-minifilter.md), which
  settles the *file* path — its driver was removed on 2026-09-09, so the
  network path below is what still blocks. This one settles that path.

## Context

The question that started this: a file lies on `G:` (a strict folder,
`\\fs-01\GL`), a user attaches it in an Edge window and uploads it to
an AI service. Nothing from that folder may leave except to the destinations
the operator listed in the dashboard.

The policy already exists and is already editable. A rule carries **Strict
folder (block all)** plus **Allowed destinations** (IP/CIDR with optional
port, `crate::allow`), and the semantics are exactly the ones wanted: once a
process has read from the folder, every destination is forbidden except those
listed. The endpoint has the list — the correlator runs in the agent.

What does not exist is the *blocking*. The `enforce` flag maps to
`TerminateProcess` on the sending process, driven by an ETW report. That is a
follow-up: the browser dies after the first bytes are gone. ADR 0001 already
recorded this shape for the file path and sent it to a minifilter. The
network path was left as "a WFP filter at the ALE layer — a separate piece of
work", which is this one.

### The measurement, 2026-09-08

Before deciding how to bind a network filter to the taint, we measured how
long the taint takes to become actionable. Test client `DESKTOP-EXAMPLE`,
30 reads of a local 4 KB file, 300 ms apart, agent in `trace` mode, elevated
SSH session, 30 of 30 matched, **0 dropped**:

| | ms |
|---|---|
| min | 647 |
| median | **1554** |
| p95 | 2486 |
| max | 2858 |

That is read → the touch being visible at the end of the agent's own
pipeline. It includes the PowerShell consumer used to timestamp the lines, so
it is an **upper bound**; the sensor-only share could not be separated,
because the instrumented build could not be moved onto the client (`scp` over
an `expect` pty corrupts the binary stream, and the alternative route over
the DC share was refused by the sandbox). The split does not change any
conclusion below.

One thing the number does settle: the taint's clock is **not** eaten by this
latency. `etw.rs` stamps `at: Utc::now()` in the callback, not
`EventHeader.TimeStamp`, so a touch TTL starts at delivery. The delay costs
coverage at the front, not at the back.

### Why the browser cannot be solved with a network filter

A user-mode WFP filter at `FWPM_LAYER_ALE_AUTH_CONNECT_V4` decides at
**connection setup**. When the user picks a file on `G:`, the browser's
connection to the destination has been open since the tab was loaded —
minutes earlier. The filter never fires for it.

This argument holds independently of the measurement. The measurement adds
the second half: even if the agent tears down the process's existing flows
when the taint is set, that teardown happens ~1.5 s after the read, and a
small file is through by then.

For a script the same mechanism works the other way round. `Invoke-WebRequest`
opens a **new** connection after the read, so anything that sends more than
~1.5 s after reading — every script with processing in between, every
human-paced action — runs into the filter. Only a tight `Get-Content;
Invoke-WebRequest` escapes.

## Decision

There is no single enforcement point for "nothing leaves this folder". The
egress channel decides which mechanism can act **before** the bytes move, and
the three do not substitute for each other.

**1. Browser egress → the browser's own DLP connector.**
Edge for Business DLP Connectors send the content of specific user actions to
an on-device agent and **wait for its verdict before the action proceeds**.
Covered actions: **Paste, Print, Upload**. Chrome has the equivalent through
the Content Analysis Connector, whose agent side is open
(`chromium/content_analysis_sdk`, protobuf over local IPC).

This is the only mechanism in this ADR with no latency race at all — the
browser blocks on us instead of us chasing it. It also closes the paste hole,
which nothing else here touches: marking cells, `Ctrl+C`, pasting into a chat
window produces no file event and is invisible to the sensor.

**2. Non-browser egress → a WFP filter at the ALE layer, in user mode.**
Pure permit/block filters are set through the management API
(`FwpmFilterAdd0`, `fwpuclnt.dll`) with admin rights, which the service has.
**This needs no signed driver** — the decisive difference from ADR 0001, and
the reason this stage can ship without the EV certificate.

On taint, the agent arms a filter set for the touching process's EXE: one
block-all plus one permit per allowed destination. Two requirements that are
part of the decision, not details:

- **Filters go in a dynamic WFP session.** If the agent dies, the cage opens
  by itself. Same fail-open stance ADR 0001 fixes for the driver: a DLP
  component that cuts the network on its own failure is worse than the leak.
- **Existing flows of the process are torn down when the taint is set.**
  Without it the filter only covers connections that happen to start later,
  and the gap is not an edge case.

The cage TTL is its own value, **60 s**, separate from the reporting touch
TTL of 600 s. It is a rolling window — `last_touch` is refreshed on every
touch — so it means "60 s after you stopped touching the folder", not 60 s
after the first access. Values of 1–3 s were considered and rejected: the TTL
is not the limiting factor, and shortening it only trades away the script
coverage that this layer exists for.

**3. Destination hygiene → proxy or browser URL policy, outside the product.**
`URLBlocklist` by GPO, or a category block at the proxy. This is destination
control, not origin control: it knows nothing about `G:`, and every
destination nobody thought of stays open. It is cheap, needs no agent, covers
every machine uniformly, and it is the layer that catches carelessness. It
belongs in the customer documentation, not in the agent.

## Consequences

- The per-EXE binding is coarse. While a taint holds, **every** instance of
  that EXE is caged, not just the tainted process — user-mode WFP filters
  condition on `ALE_APP_ID` (the image path); there is no PID condition at
  that layer. For short-lived processes (`powershell.exe`, `curl.exe`) the
  cost is small. Prosecuting it per PID needs a callout driver, and that is
  back to the EV certificate.
- The pain this causes is bounded by the **allow list**, not by the TTL. With
  the intranet and M365 ranges listed, a caged process still works normally
  inside the company and only unknown outside destinations die. That is the
  intended behaviour for a process that just read from a strict folder.
- `Strict::enforce` is a single bool that means "everything leaving this
  folder". It cannot express "enforce the network, only report a local copy"
  — which is what deleting a copy to the Desktop does today. Splitting it per
  target is an open follow-up, not decided here.
- Whoever renames a copy of `powershell.exe` gets a different `ALE_APP_ID` and
  falls out of the cage. And the taint must arise at all: a read through the
  SMB redirector appears under PID 4, the gap ADR 0001 already lists. This
  layer stops carelessness, not intent — the same sentence ADR 0001 ends on.

## Cost and prerequisites

- **WFP layer:** no certificate, no driver, no kernel test environment. A new
  module in the workstation agent, hooked where the taint is set. Buildable
  and testable today.
- **Browser connector:** Chrome's agent side is open and implementable now.
  Microsoft lists Symantec, Trellix and Cisco Secure Access for Edge, each
  with its own setup page — that reads as partner onboarding, not an open
  interface. Getting deelpe onto that list is a commercial question, not an
  engineering one, and it is the gating item for the Edge case specifically.

## Dead ends checked on 2026-09-08

- **`EdgeFileUploadBlockedForUrls`** does exactly what was wanted — block
  file upload per URL pattern — and is **not supported on Windows**. Android
  ≥ 115 and iOS ≥ 122 only. Recorded so nobody checks it twice.

## Alternatives

- **Stay with `TerminateProcess`.** Kills the browser after the bytes left.
  Honest as a deterrent, useless as a control.
- **MITM proxy.** Sees the URL and the upload body, so it can block the
  upload without touching the browser. Costs a CA on every client, breaks
  certificate pinning, and still knows nothing about `G:`.
- **Buy it** (Microsoft Purview Endpoint DLP), as in ADR 0001.
- **Do not let the data onto the endpoint** — published application over
  RDS/Citrix without drive and clipboard redirection. Solves upload, paste
  and copy in one move, and remains the better answer for a customer who
  really cares.

## Built

- **Browser connector** — `deelpe-winagent/src/browser.rs`, 2026-09-08.
  Firefox ≥ 137 and Chrome speak the same protocol; the policy that points
  the browser at the pipe is written by `service install`. Since 2026-09-08 a
  block also raises an **alert in the central** (`Verdict::Denied`, target
  `upload to <url>`) — before that it wrote one log line and the dashboard
  showed nothing of the one mechanism that acts before the bytes move.
- **WFP cage** — `deelpe-winagent/src/wfp.rs`, 2026-09-08. Armed where the
  taint is set (`Correlator::drain_tainted`), block-all plus one permit per
  allowed destination per `ALE_APP_ID`, at `ALE_AUTH_CONNECT_V4` and `_V6`,
  in a dynamic session; existing TCP flows of the touching process are torn
  down; rolling 60 s TTL swept by a 5 s tick. Processes on the agent's
  never-kill list and processes that submit their uploads at the connector
  are left out — the first because a caged `svchost.exe` is a machine
  without a network, the second because their "no" comes earlier and hits
  more precisely.
  - **Not covered:** an already open **IPv6** connection. `SetTcpEntry` has
    no user-mode IPv6 counterpart; tearing one down needs a callout driver
    and with it the EV certificate from ADR 0001. New connections are
    blocked on both families.
  - **The ALE layer does not separate TCP from UDP**, so a caged process
    loses **DNS** too unless the resolver is inside the allow list. That is
    the same sentence the Consequences already carry — with the intranet
    range listed, the resolver is in it; without it, the cage is tighter
    than the allow list reads. Worth one line in the operator docs.
  - **Hostnames in the allow list** are not filters here — they hold at the
    browser connector, where the destination URL is known. The agent logs
    which entries it skipped, once per cage.
  - **Measured on `DESKTOP-EXAMPLE`, 2026-09-08 22:46.** Agent 0.1.0 with
    the cage, rule `GL` (`\\FS-01\GL`, strict + enforce, empty allow
    list). One `powershell.exe`, one run:

    | | 1.1.1.1:443 | DC 192.0.2.201:445 |
    |---|---|---|
    | before the read | reachable | reachable |
    | 8 s after reading `\\FS-01\GL\Protokolle\Protokolle-001.dat` | **blocked** | **blocked** |
    | 62 s after the last touch | reachable | reachable |

    The agent logged `filtering engine open`, then `network cage armed …
    exe=…\powershell.exe filters=2 permits=0 torn=0`, and 62 s later
    `network cage opened again (no touch for 60s)`. Two filters, because an
    empty allow list means one block-all per address family and nothing
    else — the DC going dark with it is the allow list doing exactly what it
    says, not a defect.

    Nothing else on the machine lost its network: `sshd.exe` kept the
    session (it is on the never-cage list), and the agent's own reporting to
    the central continued through the same window.
  - **Internal networks are permitted by the cage, always** (RFC 1918/4193
    plus loopback, link-local and multicast), decided 2026-09-09 after the
    cage took the network away from the Start menu, the RDP clipboard and
    Firefox. The rule's `allow_destinations` is untouched by this: an upload
    to an internal server is still **reported**, it is just not **blocked**.
    Reporting and enforcement are different questions and now have different
    lists.
  - **The shell is never caged**, on its own list separate from the
    never-kill one: it reads from a protected folder the moment anyone looks
    at it, and nobody exfiltrates through the Start menu. Browsers are on
    that list too — they belong to the connector by this ADR's own decision,
    and keying the exception on a PID that had already talked to the pipe
    was not enough (Firefox lost seven open connections on 2026-09-09).
  - **Measured 2026-09-09 06:29–06:52**, same client and rule: with the
    internal ranges permitted, `filters=12 permits=10`, the DC stayed
    reachable and `1.1.1.1:443` went dark — so **permit filters do outweigh
    the block filter**, which settles the open question above. An already
    open TCP connection of the touching process was torn down (`torn=1`,
    the socket failed on the next send).
  - **Gap found the same day: a caged process's *children* are not caged.**
    `Get-Content <protected>; curl.exe https://…` from one PowerShell: the
    PowerShell is caged and blocked, the `curl.exe` it spawns reaches the
    destination (HTTP 301). The taint travels child → parent (the reporting
    layer needs that for `cat secret | curl`), and the cage arms on the
    reader. Reporting catches this case; the cage does not. Closing it means
    caging the descendants of a tainted process while the taint holds —
    a decision with its own blast radius, and not made here.
  - **Still to measure:** a `curl.exe` that reads the protected file itself
    (rather than being handed the bytes by a parent).

## Update 2026-09-09: process termination removed

Killing the sending process is gone from the product, on Windows and on the
Mac. On 2026-09-09 it killed a user's `explorer.exe` twice — for 330 and 446
bytes of Microsoft telemetry — and took the desktop with it while stopping
nothing that had not already left. That is the verdict the Alternatives above
had already written down ("honest as a deterrent, useless as a control"); the
lab incident only made it expensive.

What `enforce` means from now on: the browser connector (refuses the upload
before the first byte and knows the target URL), the WFP cage (takes the
network from a tainted process without ending it), and
`delete_copy`/`lock_copy` for a copy that already left the folder (Windows
only). The flag itself stays on the rule and still drives all of them — only
the kill disappears. The Mac keeps reporting; blocking before the first byte
needs the Network Extension there.

Nothing above this line is changed by that: the Decision, the measurements
and the *Built* notes record what was decided and observed on 2026-09-08.
