---
name: trap-a-ledger-pages-authority-is-its-master-so-a-quiesce-on-another-node-moves-nothing-and-a-departure-re-aligns-every-page
description: TRAP (0.90.12, 3/tcp stall lap): freeze/thaw on a non-master moved no authority; a clean departure re-mapped page mastership onto the dead member (pu…
metadata:
  type: feedback
tags: [dlm, ledger, mastership, harness, tcp]
---

# A ledger page's authority is its master; a departure re-aligns every page

**Measured 2026-09-28, tests/nonfallible_transition_stall.sh 3-node arm
(tests/evidence/20260928T185439Z_nftstall_s4d_3node, console lapq_s4d_2.console):**

- The harness assumed a node's freeze/thaw (`P-SB-SUMMARY-LOCK ... at=quiesce`) makes that node the
  SB summary page's AUTHORITY.  It does not: the page's authority is the node that MASTERS it (the
  master owns the page it decides on; a remote requester's lock moves nothing).  So the victim's
  quiesce left the page owned by the live master, the third node's put_super lock was answered
  rc=0 in a second, and nothing met a takeover.  s146f had found the same at 2 nodes; the 3-node arm
  repeated the premise.
- Mastership is `active_nodes[page % N]` over the sorted active view (`dlm_page_master_locked`).  A
  dead member stays in the view until its recovery completes, and a member's CLEAN departure shrinks
  N, so every page's master can move — including onto the dead member: after test3 left, test1's own
  put_super saw the summary page mastered elsewhere (`master_self=0`) and its acquire failed fast on
  the transport (`rc=-107`).  Conversely a page the dead incarnation authored can land on a live
  master, whose on-demand takeover the retention judgement refuses while the guard stands.

**Consequences for harness design:**
- to make a page "belong" to a node, that node must MASTER it; read `master_self=` and choose roles
  from it, never from who last locked.
- any lap that unmounts a member mid-measurement changes every page's master; read the roles again
  after the departure or expect fast transport failures (-107/-112) instead of waits.
- the shape that reaches a refused takeover on a live node is exactly a departure during a standing
  guard; that is what tests/tcp_death_replay.sh `TDR_BLOCK_REALIGN=1` drives.
