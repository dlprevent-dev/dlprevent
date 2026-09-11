# ADR 0005: New agent versions come from a signed release

- **Status:** accepted, implemented 2026-09-10
- **Date:** 2026-09-10
- **Affects:** `deelpe-server` (`release`, `binaries::install`,
  `api::release`, the settings `release_repo`, `release_check_enabled`,
  `release_pubkey`), `deelpe-sign` (a new program), the dashboard (the agent
  page, Settings → Interfaces)
- **Relates to:** [ADR 0004](0004-agent-update-from-the-dashboard.md) — the
  distribution to the devices. This decision only fills the pigeonhole.

## Context

ADR 0004 brings a program from the central server's pigeonhole onto the
devices. Into the pigeonhole it came only through a human's file picker:
whoever releases a new version had to get every operator, one at a time, to
download it and upload it. For one installation that works, for twenty
customers it does not.

That raises the question nobody had to ask before: **how does a central server
tell that a program from the network really comes from the publisher?** It
then pushes it onto every workstation in a company, with system rights. That
is exactly the route by which supply chains are attacked.

## Decision

**1. One signature, and its key does not come from the release.**
Every program carries a detached signature (`<name>.sig`, ed25519 over the
whole file, base64). It is checked against a key that was either fixed at
compile time (`DEELPE_UPDATE_PUBKEY`) or stands in the settings. A plain
checksum next to the file would have been worthless: whoever can change the
release changes it too.

`ring` is in the tree anyway through rustls — no library is added.

**2. The private key never touches the central server.** Signing is done with
`deelpe-sign`, a small program of its own. Deliberately not a subcommand of
the server: a runtime image should not carry the tool along, and the server
should not be able to touch the private key.

**3. Looking is automatic, fetching and rolling out are one click each.**
Every six hours the central server asks what there is and writes the result
into its store and into the log. Nothing is downloaded. `fetch` downloads,
checks and files it away — no more than that; onto the devices it goes by the
route from ADR 0004.

Three steps, three decisions: *there is something new* → *I fetch it
here* → *my company gets it*. A central server that passes things through
automatically from the network all the way to the workstation would be a route
nobody can stop any more — and one faulty release would take out every
customer at the same time.

**With one exception, and it deserves naming:** if the master switch
`agent_update_enabled` from ADR 0004 is on, then the second step *is* the
third at the same time. Whatever lands in the pigeonhole, the agents collect
on their next report. That is not a bug — whoever threw the switch decided
exactly that — but the box in front of the fetch has to say so, or it promises
"nothing will be distributed" while within half a minute it is on every
workstation. It does say so (`rolls_out_at_once`).

**4. Nothing is built on the central server.** It takes finished programs: out
of a signed release, out of the file picker, or straight into the pigeonhole
by whoever runs it (`scripts/publish-agent.sh` for installations that clone
the repo and build it themselves). A "build now" button would mean that an
installation holding the records of a whole company compiles and runs foreign
code on a shout from the browser; a hijacked dashboard account would then be a
hijacked build server. The price is that somewhere a human at a machine with a
compiler types a command — once at the publisher, or once per installation
after the `git pull`.

## Consequences

- **The check happens before the write.** A file that makes it into the
  pigeonhole and is only noticed there is one that could already have been
  shipped.
- The compiled-in key wins over the one from the settings. Only it protects
  against an attacker with database access; the one from the settings protects
  against a hijacked account at the git server, and that is the boundary that
  counts here. **An administrator can upload an arbitrary program by hand
  anyway** — that is the same trust boundary, and this decision does not widen
  it.
- **Without a key, nothing is fetched.** No silent fall back to "unchecked,
  then"; the dashboard says that none is stored.
- A program without a `.sig` next to it counts as absent, not as half present.
  A release with the signature missing is meant to stand out.
- The short form `besitzer/name` means GitHub, a full address stays as it is
  — a Gitea of your own has the same API shape and therefore stays reachable.
- **Key rotation is unsolved.** Whoever loses their private key can reach a
  central server with a compiled-in key only through a new server version. For
  an installation with a few customers that is bearable; whoever grows needs
  two permitted keys at once, so that one can be retired while the other still
  holds.
- **A failure on one platform does not take the other with it.** Before, the
  whole call broke off while the Windows program was already in the
  pigeonhole; the response reported an error and nobody knew what now
  applied. Now it collects: what can be fetched is fetched, and what was
  refused stands in the message and in the audit log.
- **The signature says who sent the file, not what is in it.** The header
  check (`MZ`/`PK`) therefore sits in `binaries::install` and applies to both
  sources: a CI that accidentally attaches the Linux file as
  `deelpe-winagent.exe` is cleanly signed and would otherwise supply every
  Windows machine with a program that does not start.
- **No rollback over this route.** The release knows only "latest"; an older
  version you fetch by hand through the file picker, which stays.
