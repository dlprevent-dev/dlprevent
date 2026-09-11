# ADR 0003: `enforce` splits by target — the network and the copy

- **Status:** proposed, **decision open** — the recommendation below can be
  built, but nobody has asked for it
- **Date:** 2026-09-10
- **Affects:** `deelpe-core` (`config::Strict`, `enforce::action_for`,
  `central::Rule`), `deelpe-winagent` (the cage), `deelpe-server`
  (the rule fields, a migration), the dashboard (the rule form)
- **Relates to:** [ADR 0002](0002-upload-blocking-splits-by-egress-channel.md),
  which leaves this question explicitly open: *"`Strict::enforce` is a single
  bool … It cannot express 'enforce the network, only report a local copy'.
  Splitting it per target is an open follow-up, not decided here."*

## Context

`Strict::enforce` is a `bool` and drives two things that have nothing to do
with each other:

1. **The network.** `client.rs::fresh_touches` filters
   `strict_for(&origin).filter(|x| x.enforce)` and puts up a WFP cage for the
   touching process: everything blocked except the allow list (ADR 0002).
2. **The copy.** For `Target::Volume` and `Target::Copy`,
   `enforce::action_for` returns `Action::DeleteCopy` — the file that came
   into existence outside the strict folder is deleted.

An operator who wants to block the upload out of `G:` but only wants to see a
copy to the desktop cannot say so. The choice is between "both" and
"neither".

The two interventions are also of a very different weight. The cage is
reversible and runs out by itself after 60 seconds without a touch; at worst
it costs a program its reach to an unknown address. Deleting a copy is
**not** reversible and has already hit the wrong thing twice in the lab
(Firefox, `desktop.ini` — see the exception lists in `correlate.rs`). An
operator who wants to shut the network has to buy the deleting along with it
today.

## Recommendation (not decided)

`enforce: bool` becomes two fields, both with `#[serde(default)]`:

```rust
pub struct Strict {
    pub path: PathBuf,
    pub allow: Vec<String>,
    /// Block the network while the taint holds (WFP cage, ADR 0002).
    pub enforce_network: bool,
    /// Remove the copy outside the folder.
    pub enforce_copy: bool,
}
```

**Migration:** an existing `enforce: true` becomes `enforce_network:
true, enforce_copy: true` — behaviour unchanged. On its first start the
central server writes both columns out of the old one; the rule generation
grows by one in doing so, and the agents collect it anyway.

**The default for new rules:** `enforce_network: true, enforce_copy: false`.
That is the direction ADR 0002 points in — the cage is the intervention that
acts before the bytes and opens itself again; deleting is a follow-up that
can grab the wrong thing.

**In the dashboard** two checkboxes instead of one, with the difference in the
text: one blocks, the other deletes.

## Open questions for the decision

1. Is the default for **new** rules right this way, or should both be on, so
   that "strict" stays strict?
2. Should `enforce_copy` stay at all? ADR 0001 handed the file path to a
   minifilter and the driver was removed afterwards; deleting in user mode is
   the follow-up that ADR 0001 describes as insufficient. Dropping it with
   nothing in its place would be the smaller solution — and looking into that
   costs nothing as long as nobody is running it.
3. Does the browser connector need a third field, or does it stay on
   `enforce_network`? It too acts before the bytes, but by an entirely
   different route.

## Why this is written here and not in the code

The split changes the wire format, the database and the rule form. Which
default is right is a product decision, not a technical one: it determines
what an operator gets who ticks "strict" and reads no further. The rebuild
itself is small — the decision about it is not.
