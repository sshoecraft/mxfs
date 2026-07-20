---
name: AAA-ccloopcc87-sess6-END-fix-reverted-fable-refused-next-GPT
description: sess6 END: recycle-relink fix REVERTED (made P135 worse: visited=17 not 2-3, new dir_reuse_coherency failures). Fable refused twice. Next: escalate t…
metadata:
  type: project
tags: [ccloop-cc87fed3, pr_sweep, RULE4, RULE5]
---

## CRITICAL: deployed build 0.10.91 on test1/test2 is the BAD (harmful) fix — do not trust it
The module currently loaded on test1+test2 (srcversion D1C2FDFC88DDE4D0B0FA3E3, VERSION file says 0.10.91) has
the auto-heal `inode_sb_list_add(inode)` call in `xfs_iget_recycle` STILL ACTIVE. This build made the bug
WORSE (see below) — do NOT use it for anything, do NOT trust any test run against it. The SOURCE TREE
(xfs/xfs_icache.c) has ALREADY been edited to revert this (diagnostic-only now, no auto-heal) but this revert
has NOT been rebuilt or redeployed yet. **First action next session: `make modules`, bump VERSION to 0.10.92,
redeploy to test1+test2 via `cluster_reset_n.sh 2`, confirm srcversion changed, before doing anything else.**

## Full session arc (sess6, ccloop cc87fed3) — read sibling memories in this order for full detail:
1. `AAA-ccloopcc87-sess6-ringbuf-built-0.10.87-validating` — found+rebuilt the ring-buffer pr_sweep fix
   session 5 wrote but never rebuilt/deployed.
2. `AAA-ccloopcc87-sess6-ringbuf-INSUFFICIENT-worse-hang-need-tripwire` — ring buffer works for its own
   function but the SAME corruption independently hangs stock kernel `drop_pagecache_sb` (zero protection,
   proven via live capture) — fixing pr_sweep alone can never be sufficient.
3. `AAA-ccloopcc87-sess6-tripwire-REFUTED-adding-heartbeat` — GPT's (sess5's consult) sweep-pin tripwire
   fired ZERO times (refutes "pr_sweep's own pinned inode gets evicted from under it"); heartbeat instrumentation
   proved pr_sweep itself is NOT the long-running lock holder during the hang.
4. `AAA-ccloopcc87-sess6-fable-consult-recycle-race-hypothesis` — Fable consult (bar met: proven diagnosis +
   2 distinct refuted approaches + architectural question). Fable's answer: self-loop signature requires
   `inode_sb_list_add()` called TWICE without an intervening delete (not a bad evict). Hypothesized mechanism
   via `xfs_iget_cache_hit`'s "sess40" block's non-exclusive IRECLAIM handling.
5. `AAA-ccloopcc87-sess6-ROOT-FIX-recycle-relink-0.10.91` — **P139 diagnostic CONFIRMED the general shape**:
   `xfs_iget_recycle` fired on an already-VFS-unlinked (`list_empty(&inode->i_sb_list)`) struct inode 14 times
   in one repro, always same reused ino, always via `xfs_create -> xfs_icreate -> xfs_iget -> cache-hit ->
   xfs_iget_recycle`. Applied a fix: call `inode_sb_list_add(inode)` to re-link it when found empty.
6. **THIS memory**: that fix was WRONG / made things worse. Re-validated same repro on 0.10.91 (the fix
   build): P139 fired 34 times (up from 14), pr_sweep's cycle detector's FIRST hit showed `visited=17` (a real
   ~17-node cycle) instead of the clean 1-hop self-loops (`visited=2` or `3`) seen in EVERY prior run including
   pre-fix, AND `dir_reuse_coherency` itself (first of the 3 chained tests, previously always PASS) started
   timing out and failing outright. The original drop_pagecache_sb softlockup hang STILL happened too. **Reverted
   the auto-heal in source** (xfs/xfs_icache.c, `xfs_iget_recycle`) back to diagnostic-only (P139 warn, capped at
   200 occurrences, no dump_stack anymore since we already have proof, no `inode_sb_list_add` call). NOT yet
   rebuilt/redeployed (see CRITICAL note above).

## My working theory for WHY the fix made it worse (not yet proven, needs the next diagnostic round)
A `visited=17` cycle appearing immediately upon blind re-linking suggests the orphaned struct is a genuine
**zombie with a second, legitimate owner already active for the same ino** — not simply "forgot to link it."
Most likely: a CONCURRENT `xfs_iget_cache_miss` (different code path, allocates a genuinely NEW `struct
xfs_inode`/`struct inode` object) has ALREADY claimed this same ino number and is live/linked, while THIS old
struct (found via a stale-but-not-yet-cleaned-up per-AG radix tree entry) is a leftover corpse that should be
discarded, not resurrected. Forcibly re-linking it gives pr_sweep's/drop_caches' walker a SECOND path that
eventually entangles with the legitimate object's own list neighborhood, producing a longer/messier cycle
instead of a clean self-loop.

**Candidate correct fix (NOT YET IMPLEMENTED OR VALIDATED)**: when `xfs_iget_recycle` (or its caller
`xfs_iget_cache_hit`, xfs/xfs_icache.c ~line 1200-1214) finds `list_empty(&inode->i_sb_list)`, it should NOT
proceed with recycling this object at all — bail (return an error, e.g. -EAGAIN or similar, mirroring the
existing `xfs_iget_recycle` failure path at ~line 610-624 which already handles "re-initializing the inode
failed... re-add it to the reclaim list") and force the caller through a fresh lookup / `xfs_iget_cache_miss`
path instead. Open question: does the stale per-AG radix tree entry pointing at this zombie need EXPLICIT
removal at that bail point (to stop repeatedly re-finding the same zombie as a false cache-hit), or does it
get cleaned up naturally by something else already in flight? This needs code-reading (xfs_perag radix tree
removal call sites) AND live-capture proof before implementing, per RULE 4 — do not skip straight to coding it.

## Fable consult status: REFUSED (both attempts)
Tried twice (original technical framing, then a genericized rephrase removing MXFS-specific framing/proper
nouns) — both times `mcp__ask_fable__query` returned `success:false, error:"Anthropic returned no text
content (stop_reason=refusal)"`. Unclear why (content is a straightforward kernel-debugging technical
question, nothing sensitive). **Per RULE 5's escalation chain, since Fable failed to provide guidance
(refusal counts as failure), the next consult attempt (if truly needed — try own analysis first, see
candidate fix above) should go to `mcp__ask_gpt__query` instead of retrying Fable again.**

## Reusable repro (unchanged all session)
```
SP=<scratchpad>/<label>
mkdir -p "$SP"
for n in 1 2; do
  nohup /src/mxfs/tools/mxfs_sshpass.sh test$n /tmp/.mxfs_pass "dmesg -T -w" > "$SP/live_test${n}.log" 2>&1 &
done
disown -a
sleep 2
cd /src/mxfs
nohup env MXFS_DEV=/dev/mapper/mpatha ./run.sh 2 caw dir_reuse_coherency fence_during_write fault_netpartition > "$SP/harness.log" 2>&1 &
disown -a
# poll: while kill -0 <run.sh PID>; do sleep 15; done  (in ~8min foreground chunks)
# ALWAYS: rm -f /tmp/mxfs_run.lock before starting; kill stale run.sh/dmesg -T -w/bare-ssh processes first
#   (grep "ssh .*root@test|sshpass.*root@test" by lstart, not just wrapper script name — see sess6 notes)
```
Watch for: P139-RECYCLE-UNLINKED, P140-RECLAIM-COMMIT, P135-PRSWEEP-CYCLE (note the `visited=` value — this
session established `visited=2-3` is the healthy/expected signature when it fires at all pre-any-bad-fix;
larger values are a regression signal), soft lockup, VFS_BUG_ON_INODE, kernel BUG, invalid opcode.

## None of the 1/2/4/8/16/32 sweep tasks have progressed further
Still stuck validating 2/caw's 3-test repro subset (dir_reuse_coherency + fence_during_write +
fault_netpartition) — have NOT yet gotten a clean pass of even this subset, let alone the full 2/caw suite,
let alone resumed 1/4/8/16/32. Criteria are NOT met. Task list (TaskList tool) has the full breakdown, task
#10 (tripwire — actually now superseded by the recycle-race work) should be marked understanding it evolved
into the current investigation; tasks #3-#9 (the sweep itself) are all still pending, correctly blocked on
getting 2/caw's repro clean first.
