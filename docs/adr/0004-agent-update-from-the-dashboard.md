# ADR 0004: The agent replaces itself, the service manager restarts it

- **Status:** accepted, implemented 2026-09-10
- **Date:** 2026-09-10
- **Affects:** `deelpe-core` (`central::update_due`,
  `AgentConfig::update_to_sha256`, `net::Client::binary`),
  `deelpe-server` (`binaries`, `agent::report`, the setting
  `agent_update_enabled`, the column `agents.update_requested`),
  `deelpe-winagent` (`update`, `service`), the dashboard (the agent list with
  a button, Settings → Interfaces)
- **Relates to:** `docs/INSTALL.md` — the start-up script that swaps the EXE
  by comparing hashes still holds and remains the route for environments with
  GPO, Intune or Ansible.

## Context

Until now a new agent version reached the devices only over the route the
operations team runs anyway: a start-up script, a GPO file item, an Intune
package, Ansible. That works, but every version costs an intervention in a
second tool — and in an environment without a domain that route does not
exist at all.

Half the way was already there: the operator uploads the EXE in the dashboard
(`binaries.rs`, "an update is a file swap"), and a freshly set-up machine
collects it during enrollment over the agent port. What was missing was the
route to a device that is **long since enrolled**: its enrollment token has
been burned.

## Decision

**1. What is compared is the file, not a version number.** In every report the
agent reports `build` — the first twelve characters of the SHA-256 of the file
it is running. The central server holds the full checksum of the uploaded one.
If the one does not match the start of the other, an update is due
(`central::update_due`). That needs no version counting, no ordering and no
special handling for a rollback: the previous version is just as "different"
as a new one.

**2. The checksum travels with the instruction**, not merely a "yes"
(`AgentConfig::update_to_sha256`). The agent downloads over the same mTLS
connection as the report and writes only once the bytes add up to the
announced checksum. Without that, the central server would be a way to put an
arbitrary program with system rights onto every machine in the company, and
nobody could check the arithmetic.

**3. Two triggers, both explicit.** The master switch `agent_update_enabled`
is off as shipped; off means the agent list only marks who is out of date.
Next to it stands the button on a single agent
(`agents.update_requested`, migration 0013). The button is the more important
of the two: it is the route for the first device — update one, see whether it
comes back up, then the rest. A master switch on its own would mean that the
first attempt always hits the whole company.

The mark clears itself as soon as the agent is running the program that was
put ready. An instruction that got stuck could not be withdrawn — and on the
next upload this one device would collect that one too, unasked.

**4. The restart goes through the service manager's recovery action.** The
agent swaps the file (write `.new`, rename the running EXE to `.old`, move
`.new` into its place) and signs off with an error code; the service manager
then restarts it, into the new program. This is set up in `service::install`
and brought up to date on **every** `service start`, so that installations
from before this version get it too.

## Consequences

- The file comes into existence **in the target folder** and inherits its
  access list. One pushed in from outside would bring its own along, and then
  the service account may no longer read its own program — the fault that
  `service::repair_access` clears up after every start.
- The restart goes through the service manager, because a service that stops
  and starts itself needs rights on itself for that, which a dedicated service
  account (a gMSA) precisely does **not** have. An `sc start` from a detached
  child process failed there silently.
- That takes two calls, not one: as shipped, the actions only apply to a
  crash. A service that signs off properly with an error code only falls under
  them with `set_failure_actions_on_non_crash_failures(true)`.
- **Every swap appears in the event log as a service failure.** That is the
  price of this route and is deliberately not papered over: the service was no
  longer running and was restarted, and that is exactly what it says.
- **No swap without a way back.** Before downloading, the agent checks whether
  it may write in the program folder and whether a recovery action will start
  it again afterwards. If either is missing, it stays as it is. That was
  learned expensively in the lab on 2026-09-10: a workstation replaced its
  program, signed off, and nobody was waiting for it — an out-of-date running
  agent turned into no agent at all. Better out of date and running than up to
  date and dead.
- **The recovery action is brought up to date at service start**, not only in
  `service start`. Whoever brings the service up through the services console,
  `Start-Service` or a restart of the machine would otherwise walk past it —
  a safeguard that only applies to one particular command is no safeguard.
  Under a service account with no right on its own service it still does not
  work; the reason then stands in the dashboard.
- **The swap stands in the central log.** Log lines travel with the next
  report — and there is no next report from the process doing the swapping.
  Without one last report before exiting, exactly the lines that make up the
  operation would be lost, and the dashboard would show only a version that
  changed without explanation.
- **No automatic rollback.** If the new program does not come up, the service
  manager gives up after three attempts; the agent stands as offline in the
  dashboard, and the previous version lies next to it as
  `deelpe-winagent.exe.old`. Visible and fixable by hand, rather than an
  automatism that oscillates between two versions when in doubt.
  The old version is only cleared away after an **accepted report**, not at
  start-up: a program that starts and then fails on configuration or on the
  connection is the more common case, and for that the net still has to hang
  there.
- Making "after three attempts" really mean the end costs a fourth entry: the
  service manager repeats the **last** entry in the list when a service fails
  more often than the list has entries. Without a closing `None` a broken
  program would start up again every two minutes, on every machine. And the
  reset period is short (ten minutes), because a *successful* swap counts as a
  failure just the same — with a day, `None` would be up after the fourth
  update within a day, and the agent would stay down after the swap.
- **macOS is excluded in the code, not only in this note**
  (`binaries::self_replacing_platform`). The service there reports the
  fingerprint of its program file, but what is put ready is the zip around the
  bundle: the one checksum can never be the start of the other, and
  `update_due` would always be true there. Whoever adds macOS needs a
  fingerprint over the same artefact first.
- **Not staggered.** Whoever throws the switch while ten thousand agents are
  running sets off ten thousand downloads within one report interval. The
  bytes lie buffered for that (`binaries::cached`, read once for everyone),
  but nobody shares the line. For large installations this stays an open
  point — staggering by agent ID would be the way.
- The same checksum is attempted at most three times, then there is quiet
  until the agent restarts. The central server does of course go on ordering
  the update — it does of course go on seeing the old fingerprint.
- The macOS service stays out of it: there it is a bundle swap with launchd,
  not a file swap. The response already carries the field for it, the route
  there is open.
