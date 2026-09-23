---
name: trap-a-lone-mount-takes-no-grants-so-it-writes-no-ledger-pages-for-a-takeover-harness
description: TRAP (sess592, D-0960/0961): a harness built its "authority" (32000 creates) AFTER the peer left; a lone mount takes no grants, so the ledger held 4…
metadata:
  type: feedback
tags: [trap, harness, tauth, ledger, single-node, D-0960, D-0961]
---

# A lone mount takes no grants, so it writes no ledger pages

**What happened (sess591d, sess592a; tests/join_during_takeover.sh):** the lap
needs the bootstrap's takeover-only pass over its own predecessor's pages to be
long (~15k pages, minutes) so a join can be issued inside it. The harness had B
unmount FIRST and then had A create the 32000-entry directory alone. On a fresh
filesystem the pass then found `cand=4`, finished in 2.3 s, and every lap aborted
"the takeover pass was not seen in flight". Earlier laps (s590) had only worked
because a ~15k-page ghost from an older campaign was already in the ledger.

**Why:** the TCP authority ledger records GRANTS. A mount with no peer modifies
everything at NL with no grant (that is the whole single→multi transition
problem), so nothing it creates or reads leaves a record. Records — and hence
pages under an incarnation's authority — come only from cluster acquires taken
while at least two nodes are members. Measured after the fix: a `ls -l` of the
32000 entries with both nodes mounted logged `P-TAUTH-PREPARED`/`P-TAUTH-ACTIVATE`
per inode at ~10 ms each, and B's clean departure handed its pages to A.

**The lesson:** any harness whose precondition is "many ledger pages under node
X's authority" must take the grants under two members, then have the peer leave
cleanly (handoff) and X leave last. Creating or reading files alone proves
nothing about the ledger. And check the pass summary's `cand=` on the first lap
of a fresh filesystem before trusting an in-flight window measured on an aged one.
