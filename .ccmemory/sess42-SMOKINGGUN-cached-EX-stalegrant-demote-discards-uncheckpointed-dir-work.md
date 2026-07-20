---
name: sess42-SMOKINGGUN-cached-EX-stalegrant-demote-discards-uncheckpointed-dir-work
description: sess42(ccloop) PINPOINT: dir_reuse 799 loss site = cached-EX stale-grant demote at xfs_mxfs_dlm.c:13485-13516 — demotes NL+stale WITHOUT flushing un-…
metadata:
  type: project
---

## sess42 (ccloop) — THE precise code site of the dir_reuse readdir=799 loss (the cached-EX stale-grant demote). Pairs with [[sess42-PROVEN-799-is-stalebase-clobber-not-insert-loss-gpt-tenure-fence-plan]].

### Location: `xfs/xfs_mxfs_dlm.c` ~13485-13516 (the sess-tcp "un-throttled dir-EX held verify", TCP only).
When a node has `i_dlm_mode==EX && i_dlm_state==CACHED` (cached EX) and the cheap mirror check `mxfs_v5_dlm_inode_held(dlm, ino)` returns 0 (the node does NOT actually hold the on-disk/TCP grant anymore — a peer took it), the code does:
```
ip->i_dlm_mode = MXFS_LOCK_NL;
ip->i_dlm_epoch++;
ip->i_dlm_state = MXFS_DLM_ISTATE_NONE;
ip->i_dlm_stale = true;        // forces slow-path re-acquire + reload-adopt
```
**NO release-drain / no flush of the dir's dirty+undestaged DATA blocks before this demote.** The just-added dirents the node committed while holding the (now-lost) cached EX are in-core/log only, NOT durable on the LUN. The forced slow-path re-acquire then RELOADS from disk (P63-HANDOFF disk-superset-adopt / P62-RELOAD-FORK-SHRINK) and DISCARDS those un-checkpointed dirents → readdir=799. The trace shows `P-TCPEX-REACQ ino=131 ... (cached EX, mirror !held -> re-acquire)` exactly at the victim's loss moment.

The comment at the site already ADMITS the scenario: "a node modifies its self-created shared dir under a CACHED EX whose real DLM grant is gone (PROVEN: P106-STALE-EX; both nodes durably agree on the lost contiguous range = concurrent divergent RMW)."

### Why it still fires (the window): the check requires `pin_count==0 && ex_holders==0 && pr_holders==0 && state==CACHED`. So while the node is MID-BATCH (holders>0, MHT create-batch window — see P35-ACQBAST-BATCH), the grant-loss is NOT detected, and addname/commits proceed under the STALE cached EX. By the time the batch ends and this check fires, the divergent modifications already happened on both nodes → the entry is durably lost/clobbered (matches the dland-proven stale-base RMW: node2 wrote block to count 112, test6 to 132 without the entry).

### THE FIX (preventive, GPT-aligned — cached EX must be backed by a valid grant token):
The bug is NOT the demote itself; it's that the node MODIFIED the dir under a cached EX whose grant was already lost. Two correct directions:
1. **Verify the grant is held BEFORE each dir modification under cached EX, not after** — i.e., run the `mxfs_v5_dlm_inode_held` mirror check (cheap in-mem walk for TCP) at the START of each addname/dir-modify trans while cached-EX, even mid-batch (holders>0). If lost → drain+reload+re-acquire a REAL grant BEFORE modifying. Removes the window.
2. **At this demote site, if un-checkpointed dir work exists, fail-closed** (GPT): the cluster is already divergent (peer modified concurrently). Flushing our blocks here would clobber the peer's adds (divergent RMW) → do NOT silently demote+reload. But fail-closed shuts down the FS, too aggressive for the test — so direction 1 (prevent the window) is preferred.

Also note GPT's broader fix: make EX release/downconvert a real per-tenure checkpoint (flush all tenure-dirty dir metadata home before any handoff), and never grant a peer EX while the prior holder's grant could be silently revoked mid-modification. The grant-revocation path that lets a peer take EX while THIS node thinks it still holds cached EX is the deeper DLM bug — find where `mxfs_v5_dlm_inode_held` flips to 0 without this node being notified/drained (lease expiry? peer steal? the TCP grant state machine). That async grant-loss-without-callback is the root.

### NEXT (RULE 4): instrument the addname/dir-modify entry under cached-EX to log when the grant mirror is !held AT MODIFY TIME (not just at acquire) → confirms modifications happen under stale grants mid-batch. Then implement direction 1 (per-modify grant verify). Re-verify 1/2/4 tcp (the written_seq fix `dir_wseq_at_completion=1` is in build 9B06D682, unverified on 1/2/4).</body>
