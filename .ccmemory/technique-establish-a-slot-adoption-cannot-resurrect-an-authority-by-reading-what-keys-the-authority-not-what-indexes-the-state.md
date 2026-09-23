---
name: technique-establish-a-slot-adoption-cannot-resurrect-an-authority-by-reading-what-keys-the-authority-not-what-indexes-the-state
description: TECHNIQUE (s111): "an adopted slot could alias the dead node's ledger ownership" was settled by asking what KEYS authority (node+epoch), not what is…
metadata:
  type: feedback
tags: [tauth, ledger, bootstrap, audit]
---

# The question that looked unanswerable, and the read that answered it

The whole-cluster bootstrap adopts a certified victim's heartbeat slot K as its
own journal. On TCP there is a durable authority ledger underneath, and part of
its state IS slot-indexed. The open question was whether adopting K could let
the new mount inherit the dead victim's authority.

The trap in that question is that it invites a survey of every place a slot
appears. That survey is long and it never terminates in a verdict, because
finding another slot-indexed field does not tell you whether authority moved.

**Ask instead what keys the authority.** In `dlm/tauth_ledger.c` a page's
authority is `hdr.auth_node` + `hdr.authority_epoch`, and every transition must
name that exact pair to proceed:

- `lpage_mine_locked` (:546) — the mastership test.
- `mxfs_tauth_ledger_prepare` (:748-760) — an ACTIVE or PREPARED page refuses
  with `-EPERM` unless `auth_node`/`authority_epoch` equal the named
  (`victim_node`,`victim_inc`) or this node's own.
- `tauth_purge_scan_page` (:1451) — the same triple.

No transition reads a heartbeat slot. So the adopted slot cannot carry
authority, whatever else it indexes — and the question is closed by three
lines, not by a survey.

**Then, separately, name what IS slot-indexed and what its failure mode is.**
Record-level `holders` and `open_holders` are `1ULL << slot` bitmasks
(`apply_op` :1007, :1158). A stale bit for the adopted slot makes another
node's `GRANT_EX` return `-EBUSY` (:1082) — it refuses, it never double-grants
— and the adopter's own `GRANT_EX` clears it (`e->holders &= ~bit`, :1134).
Fails closed, self-healing on the adopter. The code already says so in its own
words at :1506-1517: "a slot-keyed bit cannot be told from the successor's own,
and keeping it is the integrity-safe side".

**And check the epoch the adopter actually opens with.** `v5_mount.c:4383-4384`
records `esc->claim_epoch = ctx->disklock->epoch` and `esc->victim_epoch =
me->epoch` as two separate fields, and the ledger is opened with
`ctx->disklock->epoch`. The adopter's epoch is its own. That is the one fact
that would have overturned the reading above if it had gone the other way, so
it is worth the extra minute even once the keying is established.

# The shape to reuse

When asked "can X inherit Y's authority", the terminating question is *what is
authority keyed by*, not *where does X appear*. One answers in a few lines and
closes; the other enumerates forever and concludes nothing.
