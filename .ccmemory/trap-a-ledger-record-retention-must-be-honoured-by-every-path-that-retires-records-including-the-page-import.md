---
name: trap-a-ledger-record-retention-must-be-honoured-by-every-path-that-retires-records-including-the-page-import
description: TRAP (0.90.63→64): K's records were held from the sweep and the takeover, but the page import's own-slot residue rule purged them; every resume refus…
metadata:
  type: feedback
tags: [dlm, ledger, bootstrap, trap]
---

A whole-cluster bootstrap owner adopts victim K's slot as its own log. K's ledger records must survive until the term completes, because a same-boot resume or a takeover re-verifies K's replay against its sealed manifest. `v5_recovery_judging_cb`'s K arm protected them from the orphan sweep and `dlm_takeover_page`. But `dlm_ledger_import_page` (dlm/dlm.c) has two "residue of our own slot" rules: an EX record on our slot under another node id is purged by node id, and an unaccounted shared bit of our slot is released through the unlock. Neither asked the judging callback. K's records sit on the owner's own slot, so the import purged them. Measured on 2/net/mesh/drbd: `P-TAUTH-IMPORT-RESIDUE-EX ... slot=0 node=<K>` while the other victim's pages were taken over, then `P-RMAN-POSTSEAL-MUTATION site=prereplay ... live{rc=-2}` on every resume.

**Why it was missed:** the retention was added where the earlier failure was seen (the sweep), as a predicate on a {node, inc}. The import's rule is keyed by SLOT, not by an incarnation, so a node-keyed guard can't reach it.

**How to apply:** when adding or debugging a hold on ledger records, enumerate every path that retires one and check each honours it:
- orphan sweep and `dlm_takeover_page` (`recovery_judging_cb`)
- import own-slot EX and shared residue (`slot_retained_cb`, 0.90.64)
- `dlm_import_settle` / settled retire (oracle)
- `mxfs_dlm_ledger_purge_owner` (it also marks the owner purged for later imports)
- the completion ladder

To find which path removed a record, grep the kernel stream for the victim's node id: every retire path logs it.
