---
name: trap-a-retirement-keyed-on-a-node-id-alone-eats-a-live-tenure-once-the-page-is-servable-before-the-purge
description: TRAP (sess40/D-0962): the takeover's per-page purge matched ex_node only; the page is published MINE at activation, BEFORE that purge, so a mount car…
metadata:
  type: feedback
tags: [dlm, tauth, ledger, identity, D-0962]
---

# A retirement keyed on a node id alone is not keyed on an identity

`dlm_takeover_page` activates a ledger page, calls `dlm_page_now_mine()` — which
publishes the page as `DLM_PS_MINE` and marks it for re-import — and only THEN
retires the departed owner's records on it. Those two steps are not one
transaction. Between them the ordinary grant path (`dlm_page_ensure_mine` →
`dlm_ledger_import_page` → commit) can serve a request on that page and write a
record.

The purge matched `e->ex_node == node` and never looked at `e->ex_inc`. So any
record carrying the departed NODE ID under a LIVE incarnation was retired, and
the import that follows rebuilt the page without it: a lock lost with no error
on any node, both sides then believing they hold it.

## Why "node ids are random, so ids are not reused" is the wrong answer

They are reused, deliberately, in three places:

- `boot_resume_pending` adopts `boot_resume_node` — a resumed term keeps its
  predecessor's node id on purpose, "so every record and ledger entry this mount
  writes carries the provisional identity the term's descriptors name".
- `node_id_override` pins an id; harnesses use it to make page-ownership races
  deterministic.
- The `takeover_only` departure flag exists ONLY because "the departed
  incarnation carries this mount's own node id, so the id-keyed purges must be
  skipped" — and that flag skipped the two BULK purges while the pass it then
  ran called the same id-keyed retirement page by page. The hole the flag was
  written to close was open one call deeper the whole time.

## The rule

Identity is `{node, incarnation}`. A retirement that names a node id and not an
incarnation may only run where no other incarnation can be carrying that id —
inside a barrier, with the departed node fenced. Anywhere a live mount can be
writing, match the incarnation exactly, and SPARE (do not retire) a record whose
incarnation is unknown: unknown provenance is not evidence that removal is safe.
`inc == 0` from a CALLER means "no incarnation to match on"; it must never mean
"an entry whose `ex_inc` is 0 matches anything".

## How it was proven, cheaply

`tests/tauth/ledger_test.c` case 17 — a usermode fixture, no rig: one page
carrying EX for `{5,100}` and EX for `{5,101}`, purge naming inc 100. The
incarnation-exact form clears 1 and leaves `{5,101}` ACTIVE; the same call with
`inc = 0` clears it too, which is the non-vacuity assertion — it shows the
fixture exercises exactly the record the old shape ate. Ledger-layer identity
questions are answerable in `tests/tauth` in seconds; they do not need a lap.
