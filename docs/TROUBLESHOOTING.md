# Troubleshooting

Short entries: symptom, cause, fix. Central-server problems (certificates,
enrollment, expired agents) are in
[INSTALL.md → When it goes wrong anyway](INSTALL.md#when-it-goes-wrong-anyway).

## Mac

**Red bar "Full Disk Access missing", log shows
`ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED`.** The service has no Full Disk
Access, so it sees no file access. Grant it to the *responsible program*:
as a LaunchDaemon that is `/usr/local/bin/deelpe` (System Settings →
Privacy → Full Disk Access, `+`, ⌘⇧G); started from a terminal it is the
terminal (iTerm, Terminal.app). Then **Restart service…** in the app. On
MDM-managed Macs see
[INSTALL.md → macOS via MDM](INSTALL.md#macos-via-mdm-jamf-intune-kandji).

**Service does not start or is killed with Bitdefender installed.** The
antivirus blocks the binary. Add an exception for `/usr/local/bin/deelpe`.

**Orange icon in the menu bar.** A protected folder lives inside a sync
folder (iCloud Drive, Nextcloud, Dropbox, OneDrive). The sync client is on
the exception list, so data leaves through it without a warning. Move the
folder out of the sync tree or accept the gap.

**Red bar "Sensor eslogger failed: …" (or nettop).** The sensor process
exited. The service restarts it with a growing pause; the bar clears by
itself. If it stays, check `/var/log/deelpe.log` — usually Full Disk Access
or the antivirus (both above).

**Red bar "config.json changed outside the service" (or `learned.json`).**
The file was edited behind the service's back; the checksums no longer
match, and `/var/lib/deelpe/changes.log` gets a line. Intended: **Restart
service…** in the app. Not intended: read `changes.log`, then check who has
root.

**A process reports constantly.** A backup tool, indexer or similar reads
everything and has network access. Click **Ignore this process** in the
warning; the list is in the gear menu (or `deelpe ignore add`). Unsigned
processes are always reported.

**Nothing happens when testing.** Upload a file *from the protected folder*
with `curl -F`; a read from elsewhere is not a hit. The upload must exceed
4 KB; strict folders warn from the first byte.

## Windows

**The service "started and then stopped".** The agent is installed but not
enrolled. Without `C:\ProgramData\deelpe\central.json` it ends in its first
line, and the service control manager only shows its generic dialog. The
reason is in the log:

```powershell
& "C:\Program Files\deelpe\deelpe-winagent.exe" status
Get-Content C:\ProgramData\deelpe\agent.log -Tail 5
```

`not enrolled — run 'deelpe-winagent enroll' first` means the enrolment step
of the one-liner did not go through, usually because the agent URL does not
resolve on this machine or the token has expired. Enrol again and start the
service. `service install` answering *The specified service already exists*
(error 1073) is expected on a second run and harmless — the service is
already registered, only `service start` matters.

The service display name reads "DLPrevent file server agent" for **both**
roles. That is no evidence that `--endpoint` was lost; check the role in
`agent.log` as described in
[INSTALL.md → Agent on Windows](INSTALL.md#3-agent-on-windows).

**Agent installed, no warnings.** Event tracing delivers different keywords
per Windows release. Run
`deelpe-winagent trace --seconds 30`, open a file on the share and upload
it: both `file` **and** `net` lines must appear. See
[SERVER.md → Check once before first use](SERVER.md#check-once-before-first-use).

**Red sensor "network cage".** Arming the cage failed for the program named
in the message — the filtering platform refused the filters (no LocalSystem,
`FwpmEngineOpen0`/`FwpmGetAppIdFromFileName0` in the log with the error code,
"Base Filtering Engine" service stopped). The cage fails **open** by design
(see [ADR 0002](adr/0002-upload-blocking-splits-by-egress-channel.md)), so
that program keeps its network: reads from a strict folder are still reported
and the copy is still deleted, but an upload out of a strict folder is no
longer stopped. The message stays until the next cage
arms successfully, so it does not clear by itself on an idle machine —
trigger a read from a strict folder to see whether it is still true.
Programs that are never caged (shell, browsers, critical processes) do not
turn this red; that is the browser connector's job, not the cage's.

## Central server

**Admin password lost.** No reset command; see
[INSTALL.md → Admin password lost](INSTALL.md#admin-password-lost).

**Agent cannot reach the server, certificate errors, expired agents.**
[INSTALL.md → When it goes wrong anyway](INSTALL.md#when-it-goes-wrong-anyway).

**No email arrives.** Settings → Notifications → *Save and send a test email*
saves first and then sends, and shows the mail server's own answer. The three
usual ones:

- *Connection refused* — wrong host or port, or the server sits behind a
  firewall the central server cannot cross. In Docker, `localhost` is the
  container, not the host: a bridge running on the host is
  `host.docker.internal` (Docker Desktop) or the host's address on the bridge
  network.
- *Authentication failed* — a hosted mailbox usually wants an app-specific or
  SMTP-only password, not the one you sign in with.
- Nothing at all, no error — the mail went out and is stuck at the provider.
  Check the sender address: most servers refuse to relay for a `From:` that is
  not one of their own addresses, and some accept it and drop it silently.

The email goes out at most once per *collect for* window, so a freshly raised
alert can wait that long. `Since restart` on the same page counts what really
left the building.

## "recovery action not set (Access is denied)" on `service start`

The service starts anyway — but without a recovery action the agent will
replace its program on an update from the dashboard and **then stay down**.

The permission is usually not the problem. Recovery actions containing
`SC_ACTION_RESTART` need a service handle with `SERVICE_CHANGE_CONFIG` **and**
`SERVICE_START`. Without the second one Windows answers "access denied" even
to an elevated administrator. The counter-test: `sc.exe failureflag <service> 1`
goes through (no restart in it), setting the actions does not.

Agents before this version asked only for `CHANGE_CONFIG` when catching up, so
they run into it. On a **fresh install** it never shows, because the handle
from `create_service` carries both rights. Set it by hand — one line, elevated
(the spaces after `reset=` and `actions=` are part of the syntax):

```
sc.exe failure deelpe-winagent reset= 600 actions= restart/5000/restart/30000/restart/120000//0
sc.exe failureflag deelpe-winagent 1
sc.exe qfailure deelpe-winagent
```

`qfailure` has to show `RESET_PERIOD (in seconds) : 600` and three `RESTART`
lines. The trailing `//0` is a fourth action, "none": without it Windows
repeats the last one forever, and a program that does not come up would
relaunch every two minutes.

## The agent is "outdated" and does not fetch the new program

The **`self-update`** sensor on the agent says why; it is in the agent list
when you expand the row. Three cases:

| Message | Cause | Fix |
|---|---|---|
| *cannot replace the program: … is not writable* | the service account may not create files in the program folder | `rights allow-self-update --account …` |
| *no recovery action: nothing would start this service again* | no recovery action with a restart | `sc.exe failure …` (above) |
| *the recovery action only covers a crash* | action is there, `failureflag` is missing | `sc.exe failureflag deelpe-winagent 1` |

No `self-update` sensor **and** no line about the program in the device's log
means it runs a version from **before** self-update. That one cannot see the
order at all — that version has to go onto the device by hand, see
[INSTALL.md](INSTALL.md).

In the last two cases the agent refuses to swap **on purpose**: it would
otherwise replace itself and stop, because nobody would start it again. An
outdated running agent beats an up-to-date dead one.

## `checksum mismatch` on the enrollment command

The command carries the checksum of the program that was in place **when the
token was created**. If a new version was uploaded afterwards, it no longer
matches. Create a new token and the command is correct again.
