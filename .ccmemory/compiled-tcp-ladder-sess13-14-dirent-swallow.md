---
name: compiled-tcp-ladder-sess13-14-dirent-swallow
description: Compiled sess13-14 TCP ladder: dirent-swallow tenure-boundary race, fence sf-dangler leak, SF-tenure-floor, first 8/tcp 17/17.
metadata:
  type: project
tags: [compiled, tcp-dlm, dirent-swallow, sf-tenure-floor, cache-coherency, sess13, sess14]
---

# TCP ladder sess13-14: the dirent-swallow tenure-boundary race, fence sf-dangler leak, SF-tenure-floor, and the first 8/tcp 17/17

Central thread across sess13-14 (ccloop "run" sessions): climbing the TCP-transport
correctness/perf ladder toward the ship gate of **1/2/4/8-node tcp all at 100%**
(criteria marker NEVER written this run — not met). Two structural wins landed
(FIX-C entry-lock ordering; SF-TENURE-FLOOR perf) and the last-standing blocker was
isolated to the millisecond: a **stale-base RMW "dirent swallow" that is a
tenure-boundary mutual-exclusion race**, not an iget/reload miss. Same root wears
several faces: 8-node drc readdir loss, dlm_scaling got=0, dlm_fairness EUCLEAN, the
fence sf-dangler leak, and the 2/tcp shutdown.

## Build ledger (chronological, single lineage)

sess13:
- **705FDC6E** — FIX-C: entry-locks-before-AG-grants in xfs_remove + xfs_rename. [[sess13run-FIXC-entry-locks-before-AG-grants-705FDC6E]] [[sess13run-three-residual-faces-triage-705FDC6E]]
- **61EFACE7** — +P13-PLACE placement ledger, P64 present2 (node2_f1 tracer).
- **B008722F** — +FIX-D v1: iget visibility nudge (raw-DLM PR) — insufficient alone. [[sess13run-FIXD-iget-visibility-nudge-B008722F]]
- **9F1CC83B** — +FIX-D v2: mxfs_dlm_iget_shell_reload (radix-find dead shell, igrab, reload via grant+mirror); ordered shell_reload → miss_reload → nudge in xfs_lookup retry ×8.
- **E0C0D2C5** — +P13-SFRM (sf-removal ledger, watch-gated) + P56-RELOAD-MERGE prints ours_cnt/ours=[names]. [[sess13run-STATE-fence-leak-sfdangler-and-build-ledger]]
- **3BB25A6E** — FIX-E: slot-level FUA patch past the P91 logged-buffer guard. [[sess13run-FIXE-slotpatch-census-3BB25A6E]]
- **3D4A350E** / **496C1710** (=3D4A350E minus dirwr-gate on P13-PLACE) — full FIX-C/D/E stack; sess13 END build. [[sess13run-END-8tcp-status-and-next]]

sess14:
- **5A31CD27** — floor only (SF-TENURE-FLOOR). tds standalone 41.7s PASS 8/8. [[sess14run-FIXES-sf-tenure-floor-and-missreload-ligate]]
- **360111F2** — +FIX-F (iget_miss_reload li_list gate), never regression-tested alone.
- **11FAB23A** — +P14 tripwires (sf desync sentinels); iter r6. [[sess14run-STATE-r6-drc-wholeblob-and-tds-insuite-drag]]
- **8E654A57** — RC: floor + FIX-F + P14 tripwires + **dir_sf_mht_ms=40 default**. First default-config 17/17. [[sess14run-MILESTONE-8tcp-17of17-sfmht40-build-8E654A57]]
- **4D677327** — lineage head at sess14 handoff (+FIX-G destage-then-reload for 2/tcp). [[sess14run-DECISIVE-one-dirent-swallow-is-tenure-boundary-mutex-race]]

## FIX-C — no task holds AG grants while parked on entry locks (705FDC6E)

Proven defect (P12-HOLDERTASK + P36-STACK): sess58's p58 pre-lock child-AG hold in
xfs_remove parked a task holding AG-0 EX while waiting for the hot dir's inode DLM
inside xfs_trans_alloc_dir → xfs_lock_two_inodes. Peer rm in defer_finish starved 60s
on AG-0 → rc=-110 → dirty-cancel shutdown = fence/netpartition/tcp_dlm_scaling
triple-FAIL. The pre-acquire INVERTED the hold-and-wait edge instead of removing it;
xfs_rename's mxfs_trans_preacquire_inode_ags had the same shape.
Fix invariant: **entry (inode/dir) locks FIRST, AG grants AFTER while trans still
CLEAN** → acquire timeout becomes a clean cancel (bounded retry P13-CLEANRETRY, 3
tries in remove), never a dirty-cancel shutdown. Release deferred to commit/cancel
via t_mxfs_ag_unlocks. Result: **fence family 0 failures in 10-14 full-suite 4/tcp
iters** (pre-FIX-C ~1-in-4). Benign side effect: P71-UNDERFLOW prints (~125/run,
node-local, xfs_lock_two_inodes in-AIL nowait path). Residual unfixed-but-audited:
xfs_inactive_ifree AG-across-ilock (bounded), cross-AG dir-block ABBA (never
observed), xfs_link dir→AG edge (converges same as defer_finish). [[sess13run-FIXC-entry-locks-before-AG-grants-705FDC6E]]

## The dirent-swallow family — one root, many faces

After FIX-C the residuals collapsed to **shared-dir concurrent-modify staleness**
(sess83-88 stale-base RMW family). Faces triaged: [[sess13run-three-residual-faces-triage-705FDC6E]]
- **dlm_scaling got=0**: a node's OWN subdir dirent vanishes from shared parent
  `.dlm_scaling` right after a 4-way racing `mkdir -p`. ZERO P12-IGETMISS in the
  latest hit → NOT an iget miss; the dirent is gone from the parent view = stale-base
  RMW swallow.
- **dlm_fairness EUCLEAN (-117)**: fresh inode CHUNK allocated over freed dir blocks;
  chunk-INIT write never destaged (fresh bufs queue on pag_mxfs_alloc_buflist for
  Phase-2 drain) but the `.dlm_fairness` dirent already published in root → peer
  cold-iget reads stale platter (an XDB3 dir-data block of a dead dir) → EUCLEAN. Also
  exposed a mkdir-p double-create (two inos one name = root-dir swallow).
- **drc readdir-miss**: all nodes agree readdir=394/397 of 400, lookup_fail=0; missing
  = first REMOTE adds (f1/f2 of nodes 2,3,4). sess12-r7 walk-vs-lookup divergence.

### FIX-D — fresh-inode cross-node visibility (B008722F → 9F1CC83B)

PROVEN root (run_dlm_scaling_20260704T075050Z): mkdir-race loser (node3,
P127-EEXIST-LOSER winner_ino=8394204 dp_stale=1) did iget where in-core shell = DEAD
prior incarnation (mode=0 dlm_stale=1, a P4ST dangler taking neither reuse branch),
platter = one gen further behind (live REG-FILE dinode; the free never destaged),
winner's dir existed only in its log. **di_gen IDENTICAL across all three incarnations
(3281719562)** → all gen-based incarnation guards are BLIND (sess87 same-gen family).
Reload adopted the stale platter (P34D-RELOAD-FRESHSRC src=fua) → ENOENT → mkdir rc=1
→ got=0. Later losers recovered via P74-GRANT have_mirror=1 (grant arrived after
winner published, ~7ms publish chain P51-REL drain_ms=7); node3 was just EARLY.
FIX-D: mxfs_dlm_iget_visibility_nudge PR-acquires the ino by number to BAST the
creator into publish/iflush + mirror-provision, in a xfs_lookup retry 3→8 (msleep
i*10, ≤360ms). Covers dlm_fairness EUCLEAN and drc -117 variants too. Sidesteps three
KNOWN DEEPER unfixed roots: (1) di_gen not advancing on realloc, (2) P4ST dangler
shell path, (3) inode free (mode→0) not destaged before chunk realloc. [[sess13run-FIXD-iget-visibility-nudge-B008722F]]

### FIX-E — slot-level FUA patch past the P91 logged-buffer guard (3BB25A6E)

PROVEN loop: P12-IGETMISS-RELOAD invalidate → retry read captured by sess91
P91-FUA-SKIP-LOGGED (li_empty=0: ANOTHER slot's inode AIL item on the cluster buffer)
→ in-place serve of stale image → ENOENT ×64. Guard authority is **per-logged-slot,
not per-buffer**. FIX: in iget_miss_reload stage 2, when invalidate can't act and the
TARGET ino has no attached inode log item, FUA-read the cluster to a temp page and
memcpy ONLY the target slot into b_addr (P13-SLOTPATCH, ret=2). Census on 3BB25A6E:
8 iters, 7 clean, 1 zero_silent_loss singleton (peers read node1's 256K files as
size=0 — silent stale dinode; iget SUCCEEDS so FIX-D/E never engages; FIRST in ~30
iters). 6 consecutive clean at checkpoint. [[sess13run-FIXE-slotpatch-census-3BB25A6E]]

### FIX-F — iget_miss_reload li_list gate (360111F2)

r3 ds 7/8 node6 got=0 ROOT: mkdir-race loser's cluster buf (daddr=33491808) carries
OTHER slots' inode log items (li_empty=0 has_bli=0) → FIX-D invalidate ret=1 (checks
only bli/pin) → FUA re-read P91-captured → same stale image, no FUA_FRESH → ∞ loop
(P12-IGETMISS-RELOAD alternating with P13-VISNUDGE, lock_rc=0 nudges useless). Fix:
whole-buffer invalidate now requires list_empty(&bp->b_li_list); li-present routes to
FIX-E slot patch (ret=2) or ladder escalation. [[sess14run-FIXES-sf-tenure-floor-and-missreload-ligate]]

## Fence sf-dangler leak (n4_14) — the shortform variant

Autopsy (run_...091132Z + live query): leftover dirent n4_14 durable on all 4 nodes;
hot dir ino=160 SHORTFORM (fmt=1). test4 creator hit P26-IGET-FAIL name=n4_14
inum=6295916 err=-2 + P127-EEXIST-LOSER → the dirent DANGLES (name on disk sf fork,
ino freed on disk) → rm can't remove (lookup→iget ENOENT) → permanent leak.
Mechanism: rm committed sf-removal + ifree; ifree destaged, but the DIR-160 dinode
(sf minus n4_14) never destaged; later reloads clean-adopt disk (P56 merged=0 clean=1
disk=[n4_14]) everywhere → the removal is undone. Suspect: the sf CLEAN-SKIP release
fast path (P51-REL sf=1 clean_skip=1 via mxfs_dir_pr_release_fast) skips the sf-dinode
publish for a committed-but-checkpoint-pending removal. Root-fix candidate: sf
clean-skip release must verify the sf dinode is DESTAGED (not just xfs_inode_clean)
before skipping the publish (p_clean_release near P51-REL, xfs_mxfs_dlm.c ~11619).
Same family as the drc block-variant loss. Probes added: P13-SFRM (sf-removal ledger,
via raw mxfs_watch_ino compare — mxfs_ino_watched is a static inline invisible in
libxfs sf.c). [[sess13run-STATE-fence-leak-sfdangler-and-build-ledger]]

## SF-TENURE-FLOOR — the tds/perf win (sess14, 5A31CD27)

tds 8/tcp root: 2.4 dir-EX handoffs/round × ~20ms (12.9ms holder release P138:
sa=1.6 b2=3.5 flush=1.6 sc=1.7 sd=4.3; ~7ms requester). Eager idle-release arms
(mxfs_dlm_ilock_end + mxfs_inode_unpin CACHED&&bpend, sess9-v3/sess11) hand off at
EVERY syscall boundary; MHT never covered the 2-5ms shell-exec gaps. sess11's "19.6s
PASS" was 4-NODE — the 8-node bill is 2×rounds, so it never passed on this lineage.
Fix: mxfs_dlm_sf_tenure_keep_delay/arm — keep EX at idle while tenure < dir_sf_mht_ms
(SF dirs, EX only), leave bpend SET, arm dwork for the remainder (dwork serves the
peer at expiry; igrab-fail = eviction releases). dir_sf_mht_ms 2→15. Result: tds
41.3-41.9s all 8 (window 60), 150/150, 0 P73-WAITSTALL, 201 P36-MHT-REARM (batching
live). [[sess14run-FIXES-sf-tenure-floor-and-missreload-ligate]]

**In-suite op-inflation** then defeated the standalone win: 15ms passes standalone
(41.7s) but per-op inflates ~2× in-suite (aged log/tail-push, 17 tests on one
module+FS instance) → round-batching collapses → 80-86s. **sf_mht=40 re-covers it**
and became the 8E654A57 default. tds in-suite is BIMODAL: 17-31s when drc passes,
66-116s when drc fails/forensics-floods first — fixing the face fixes tds's bad mode.
[[sess14run-STATE-r6-drc-wholeblob-and-tds-insuite-drag]]

## drc suite-killer — the drop_caches eviction hang (not only coherency)

drc's per-round drop_caches interlocks with peer rm-storm evictions → node silently
hangs (INTERRUPTIBLE, no hung-task/P73). This produced the whole-blob 700/800 "miss"
(victim never created) and then 120s×2/round barrier timeouts (62s/round death
spiral). The forensic death-spiral compounded it: 15 fail-round events ×
(6000-line dmesg + 32 dd blkdumps + classify) inflated rounds and blew the 800s
budget. Instrumented in dir_reuse_coherency.sh: bounded drop_caches + DCSTACK capture
+ proceed-warm; gate heavy forensics behind DRC_FORENSICS. drc passed r7/r8 after
this. The eviction hang may have SEEDED stale bases — watch whether the 5-file face
recurs now that the hang is fixed. [[sess14run-MILESTONE-8tcp-17of17-sfmht40-build-8E654A57]] [[sess14run-STATE-r6-drc-wholeblob-and-tds-insuite-drag]]

## MILESTONE — first ever 8/tcp full-suite 17/17

- **iter r8** = 17/17 (11FAB23A + modargs sf=40): tds 17.3-30.9s, cc 8/8 clean —
  first-ever full-suite PASS at 8 nodes.
- **iter r9** = 17/17 on 8E654A57 DEFAULT (no modargs) — confirms the RC config.
- 4/tcp = 17/17 ×1 (8E654A57); 1/tcp = 16/16 ×1. 4/tcp had earlier logged 8
  CONSECUTIVE clean 17/17 on 496C1710 (longest streak, ~35 session iters). [[sess14run-MILESTONE-8tcp-17of17-sfmht40-build-8E654A57]] [[sess13run-END-8tcp-status-and-next]]

## DECISIVE — the one-dirent durable swallow is a tenure-boundary mutex race

Captured to the ms (artifact run_...20260704T201007Z iter r10, 8/tcp, build
4D677327; round 4, dir ino=540021 block-fmt daddr=534408, victim node4_f9 durably
gone, 799/800 all nodes, LOOKUP_ENOENT). P-DIRWR count+crc timeline (wr_timeline.txt):
- +3.6546 N6 EX-granted FUA-fresh base read: cnt=73 (fresh=1 fua_fresh=1)
- +3.6579 N4 writes count=74 crc=cac556ea (includes ITS f9 add; P11-DATALOG f9@off=1800 comm=dd)
- +3.6647 N6 writes count=74 crc=45fb2864 (73-base + N6's OWN add, NO f9)
- chain continues from N6's lineage → final 168 vs 169 → f9 durably gone.

Duplicate count=74 with different CRCs 7ms apart = the stale-base fork. **N4's
add/publish (its trans commit / DATALOG, not merely a late writeback) executed
~3-9ms INTO N6's EX tenure** — a mutual-exclusion break at the unhold/release
boundary. Favored hypothesis (a): N4's op ran under a stale cached EX after its
release completed — an admitted-but-not-yet-pinned window slips between the dwork's
quiescence sample and trans-pin, especially interacting with the NEW sf-tenure-floor
keep-path (bpend kept + dwork release at expiry). Alt (b): N4's earlier release
completed without waiting for a CIL-pinned dir-data buffer (Invariant-#1 drain hole)
and the write landed late — timing disfavors it. This face fails **~1-in-2-3 8-node
iters** and is the reason the criteria marker is unwritten.
Next-session plan (RULE 4): (1) instrument the boundary — on P-DIRWR of a watched dir
under mode!=EX / grant-held=false, print holders/pin/state to catch the phantom-EX
writer; log pin_count in P11-DATALOG. (2) inspect mxfs_dlm_ilock_begin fast-path admit
vs dwork quiescence sample vs trans-pin ORDER for xfs_create/dir-add — is there an
admitted-but-unpinned window where i_dlm_bast_dwork demotes+releases? (3) fix
candidate: make dwork/unhold release recheck ATOMIC vs admits (grant-era token: ops
stamp tenure gen at admit; release aborts if any admitted-op token outstanding —
extend P15 holders-recheck). [[sess14run-DECISIVE-one-dirent-swallow-is-tenure-boundary-mutex-race]]

## 2/tcp shutdown ROOT — P34F dirty-ili authority inversion (same family, sf/extents variant)

2/tcp iter s14a = 13/17, ALL ONE EVENT: test2's FS shut down at drc round ~10
(19:30:02), everything after failed on the dead mount (EIO). Proven chain on test2
(dir ino=540033 fmt=2/EXTENTS, 3 dir blocks):
1. Dir inode's ili became UNDESTAGEABLE (ili=0x5 in_ail=1 for minutes; pin=0, fmt=2 so
   NOT the P22/P14 sf-skip paths — WHY it never flushed is OPEN).
2. Releases still completed → test1 advanced the dir **13 GENERATIONS** (disk gen 68
   vs test2 loaded gen 55). So unlock-with-dirty-ili DOES happen on some path — vs
   the gap-run 184s AIL-STALL case that correctly REFUSED to unlock = **inconsistent
   drain contracts**, a direct Invariant-#1 concern.
3. Every test2 re-acquire hit P34F-RELOAD-SELFAHEAD-SKIP (xfs_mxfs_dlm.c ~13300): the
   premise "dirty ili ⇒ platter behind us ⇒ in-core authoritative" is INVERTED when
   the dirtiness is a stuck-flush leftover → served the 13-gen-stale image in a skip
   LOOP (P34F ×dozens, same dgen=68 lgen=55).
4. Concurrent local create RMW'd the stale base → xfs_dir2_data_use_free internal
   error (libxfs/xfs_dir2_data.c:2421) → trans_cancel → SHUTDOWN.
Fix directions: (A) find the iflush wedge (log iflush rc for watch dirs / "ili stuck
>Ns" sentinel). (B) P34F must distinguish "dirty mid-op" from "dirty because flush is
STUCK across handoffs" — if disk gen is AHEAD of loaded gen, in-core is NOT
whole-dir-authoritative; force-destage our ili first (log_force+ail push+retry), then
reload/merge fresh base, THEN apply; NEVER RMW a base generations behind the platter.
(C) find + close the unlock-with-dirty-ili release path. FIX-G (destage-then-reload,
gap≥3 gate) is the first cut: s14d = 17/17 at gap≥3 on 4D677327, but s14c showed
FIX-G v1 too hot (destage storm) — the gap≥3 threshold may sit inside 8-node jitter;
consider gap≥N+2 and check P14-DESTAGE counts if tds slows. [[sess14run-ROOT-2tcp-shutdown-P34F-dirty-ili-authority-inversion]]

## Column status at sess14 handoff (build 4D677327 + lineage)
- 8/tcp: r8 17/17 (11FAB23A+sf40), r9 17/17 (8E654A57 default), r10 15/17 (the
  tenure-boundary face + tds aftermath-slow 107-116s).
- 2/tcp: s14a 13/17 (test2 shutdown), s14b 17/17 (pre-FIX-G), s14c 16/17 (FIX-G v1
  too hot), s14d 17/17 (gap≥3 gate).
- 4/tcp: 17/17 ×1 (8E654A57). 1/tcp: 16/16 ×1 (8E654A57).
- **Criteria marker NOT written** — the tenure-boundary race must be fixed, then
  repeats accumulated on all four columns.

## Recurring failure modes / lessons
- **Same-gen blindness**: di_gen does NOT advance on realloc → every gen-based
  incarnation guard is blind (sess87 family). Load-bearing across FIX-D and the 2/tcp
  P34F inversion.
- **Guard authority is per-slot, not per-buffer**: the P91 logged-buffer guard blocks
  invalidation when ANY slot on the cluster buf has an AIL item (FIX-E/FIX-F).
- **Publish-before-durable**: dirent published in parent before the child chunk/dir
  block is destaged → peer cold-iget reads stale platter (dlm_fairness EUCLEAN, drc
  loss, fence sf-dangler). Real fix direction = release-side publish ordering.
- **Inconsistent drain contracts**: some release paths unlock with a dirty/undestaged
  ili while the AIL-STALL path correctly refuses — Invariant #1 (no on-disk unlock
  without drain) is not uniformly enforced.
- **In-suite op-inflation** (~2×) breaks round-batching that passes standalone —
  always re-measure perf in-suite, not just standalone.
- **Forensic death-spiral**: heavy per-fail-round forensics inflate rounds and blow
  time budgets; gate behind an env flag, but that never substitutes for fixing the
  face.
- Timing is a first-class failure (RULE 0): tds 66-116s vs 60s window is a FAIL even
  at 150/150 correct.

## Harness / infra facts
- suite_iter.sh: timeout raised 1100→2600 (1100 silently truncated 8-node iters
  mid-drc, dropping the last 4 tests → phantom "0/8 drc"); recycles VMs itself. Manual
  ./run.sh (gap runs) does NOT — virsh destroy+start test1-8 before rerunning after any
  mid-flight kill or nodes wedge (umount/rmmod busy, prep hangs forever).
- Foreground Bash caps 600s → use nohup+log+until-grep for >10min; iter logs buffer
  through `| tail -25` (nothing visible until run.sh exits) — watch /tmp/run_*
  artifacts or node dmesg for live progress.
- run.sh per-test case-arm OVERRIDES the TEST_TIMEOUT env; drc got a 100*N=800s
  case-arm (healthy standalone ~530s 8/8) recorded in TIMEOUT_BUDGETS.md.
- tar-over-ssh artifact pull resets mtimes → trust in-file kernel timestamps
  (realns−uptime), not filenames; drc script now rm's stale /root/drc_* at start
  (persisted across reboots, poisoned r4's postmortem).
- journald RuntimeMaxUse=400M + RateLimit off per prep (fixes the ~85s
  journal-rotation window under the P71-UNDERFLOW firehose).
- ds/tds artifacts only pulled on FAIL; PASS elapsed lives in node dmesg
  (mxfs-TDS rank= lines). small 6G disks on test5-8 (65-75% used) killed
  journald/snapshots after round ~9 in some 8-node runs.
- Node access helper: mxfs_sshpass.sh &lt;host&gt; /tmp/.mxfs_pass "&lt;cmd&gt;".
