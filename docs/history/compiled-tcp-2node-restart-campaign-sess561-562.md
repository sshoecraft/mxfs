<!-- TCP 2-node restart campaign sess561-562 (0.75.80-0.75.86): D-0934/D-0935/D-0937 closed F&V, D-0936 open, dino-noowner authority thread found. -->
Contents were written to /tmp path above; reproduced below.

# TCP 2-node whole-cluster-restart campaign, sess561-562 (0.75.80-0.75.86)

Continuation of the TCP-2NODE-only restart/authority chain (prior chapter:
`docs/history/docs/history/compiled-tcp-2node-departure-restart-campaign-sess545-560.md`). Harness throughout:
`tests/sess570_chain_ghost.sh <label>` (env `LAPS`) — every lap re-preps and
re-runs the workload, since the ghost probe only leaves ACTIVE heartbeat
records when the mounts it destroys had SUCCEEDED (harness lesson recorded in
`docs/history/docs/history/docs/history/compiled-tcp-2node-restart-campaign-sess561-562.md`:
a lap after a failed prior lap is vacuous).

## D-0934 — empty admission cut treated as clean

Root, from `tests/evidence/20260909T011714Z_ghost_s567`
(`docs/history/docs/history/docs/history/compiled-tcp-2node-restart-campaign-sess561-562.md`):
`mxfs_dlm_mount_recovery_barrier` broke on `!todo && !error`. A crash-leftover
heartbeat record is a plain ACTIVE record with no WITHDRAWN stamp, `pend`=0,
the membership gate discounts it, and the monitor can't declare it dead for
31×2s — barrier reports `cohort=0x0 late=0x0 replayed=0` and admits early, then
root inode 128's AG-0 ledger names a dead incarnation as authority and both
mounts fail on `Failed to read root inode`.

Fix (0.75.80, sv 514C2B9502FF1CFA5664EC0): call
`mxfs_v5_dlm_deaths_undeclared()` once per barrier pass BEFORE the clean-cut
test; break only on `!todo && !error && undecl <= 0`; a bound reached with an
empty cut plus undeclared deaths aborts -EBUSY with its own alert.

Underneath the fix, a NEW deadlock surfaced immediately: both mounts died with
test1 holding AG0 EX and blocked on inode 128 EX behind a GRANTED PR entry
whose owner is `0xFFFFFFFF` (a sentinel, not a node) — this became D-0935.

## D-0935 — shared ledger bit on a recovered, now-empty slot

Rooted+fixed in
`docs/history/docs/history/docs/history/compiled-tcp-2node-restart-campaign-sess561-562.md`
(0.75.81, sv 6B5DB71D8FD3902758FC7A8): a shared holder bit names a SLOT, but
recovery purge (`dlm_owner_purged`) is keyed on NODE ID by design (D-0344), so
a published recovery zeroes the slot and `slot_node_cb` returns 0 — the bit
imports as an unreleasable UNKNOWN owner (`owner=4294967295`) because both
`demand_collect_holders` and `fire_bast_records` skip unknown owners. Fix:
`dlm/dlm.c` `dlm_slot_purged_owner()` + retire-instead-of-import when a slot has
no occupant and names a purged owner; `dlm_owner_mark_purged` upgrades a stored
slot of -1. Verified firing: `P-TAUTH-IMPORT-RETIRE-VACANT-SLOT` logged, prior
shutdown/timeout signatures gone.

Confirmed together in
`docs/history/docs/history/docs/history/compiled-tcp-2node-restart-campaign-sess561-562.md`:
D-0934 and D-0935 both have proven causes and clean laps once D-0937 stops
masking them.

## D-0936 — filed, NOT fixed this campaign: sole-survivor gate can evict a live joiner

Filed alongside D-0935's fix
(`docs/history/docs/history/docs/history/compiled-tcp-2node-restart-campaign-sess561-562.md`):
kind-20 EXCLUSIVE_WRITE_GATE issues PREEMPT AND ABORT on the authority of a
READ KEYS snapshot taken once and never re-validated at PROUT time. Observed:
test2 proved sole survivorship at PR gen 1817, test1 registered at gen 1818 and
started log recovery, test2 issued the gate at gen 1819 — test1's log-recovery
write got EBADE, mount dead at 1450ms.

The fix ships in 0.75.85 (`other_n` refusal, per
`docs/history/docs/history/docs/history/compiled-tcp-2node-restart-campaign-sess561-562.md`) but is
**never exercised** by the normal restart shape: reading `dlm/v5_mount.c`
~7580-7632
(`docs/history/docs/history/docs/history/compiled-tcp-2node-restart-campaign-sess561-562.md`)
shows the sole-survivor gate is only attempted when boot-succession has
*declined* to prove exclusion — and in the 2-node restart shape,
boot-succession proves it first, so the gate path is structurally unreached
(zero `P-PR-GATE` lines in six clean laps; the fence instead fires
`BOOT_SUCCESSION_ABSENT(21)`). **A clean chain run must not be used to
disposition D-0936.**

The only way to actually exercise it: the existing TEST-ONLY module arg
`fence_bootsucc_inject_refuse` (`dlm/v5_mount.c:204`, added 0.75.72 for
D-0929/D-0930) forces the verdict to stay KEY_ABSENT_UNPROVEN so the gate is
reached against the concurrently-restarting peer as a real other registrant:

    MXFS_MODARGS="target_cache_protected=1 force_transport=1 fence_bootsucc_inject_refuse=1" \
      tests/ghost_slot_restart_probe.sh <label>

Expect the probe's mount assertions to FAIL by design (injection removes the
only proving route). What actually matters: `P238-FENCE-GATE-TRY` >= 1 first
(else the lap measured nothing), `P-PR-GATE-NOTSOLE` >= 1, `P-PR-GATE-ISSUE`
== 0. Negative control: `tests/tcp_death_replay.sh` already asserts the gate
CERTIFIES (kind EXCLUSIVE_WRITE_GATE) with no other registrant. No third real
initiator is available (clyde has no iSCSI path to the QNAP LUN; a PR REGISTER
from an existing I_T nexus replaces that nexus's key rather than adding one).

**Rig hazard**: this verification arm was launched at 17:52:57Z and died
in-flight with the session
(`docs/history/docs/history/docs/history/compiled-tcp-2node-restart-campaign-sess561-562.md`) —
its restore step never ran, so the rig can be left loaded with
`fence_bootsucc_inject_refuse=1`, which makes mounts hang and *looks* broken
but isn't. First action before diagnosing anything on this rig:
`MXFS_NODE_LIST=test1,test2 MXFS_FORCE_PREP=1 ./run.sh 2 tcp prep_cluster`.
Tree at that boundary was 0.75.86 (sv 1E4A6EEA3CF7D7C86285502); the verified
6-lap chain ran on 0.75.85 (sv 1AB3DD9847889D392108B72).

## D-0937 — directory images captured while authority is unpublished

Root proven in
`docs/history/docs/history/docs/history/compiled-tcp-2node-restart-campaign-sess561-562.md`
via a fast producer-only reproducer,
`REPEAT=25 tests/dir_retype_authcap_probe.sh` (~10s/iteration vs ~250s for a
full restart lap — this reproducer is the campaign's key methodology win,
reused for every subsequent authority question). Signature:
`P239-OWNAUTH-NONDUR blft=10|11 outcome=6 mode=5 unpub=0` — the node holds EX
on the directory inode (mutation is authorized) but the grant's epoch was never
durably published at first protected dirty, so `mxfs_ownauth_measure` returns
UNPUB and the image ships class NONE, unattributable forever. Consumer side:
`P227-FR-TORN-UNPUBLISHED` refuses the whole slice, both mounts die on the root
inode. Instrumentation note: `st=11` (AUTH_NOT_HELD) only became visible once
0.75.82 stopped flattening it to MISLABELLED.

First hypothesis (sess561 END,
`docs/history/docs/history/docs/history/compiled-tcp-2node-restart-campaign-sess561-562.md`):
the per-inode arm of `mxfs_dlm_inode_lock_routed` installs authority without
de-listing `i_dlm_unpublished` first (unlike the ICLUS-routed arm, which
explicitly de-lists before install because the install refuses any inode still
flagged unpublished) — expected signature `try=7` (`MXFS_AUTH_TRY_UNPUB`).
Fallback alternative recorded but not chosen: classify such images under the
already-held AG grant (precedent: `mxfs_buf_iunlink_ag_authorized`, sess468
fix shape B), justified by `mxfs_dir_epoch_superseded` case (1) — deferred as
the harder, wire-semantics-changing option.

**Hypothesis DISPROVEN in sess562**
(`docs/history/docs/history/docs/history/compiled-tcp-2node-restart-campaign-sess561-562.md`):
measured `try=0` (`MXFS_AUTH_TRY_NONE`) — never attempted, not refused. Actual
root: three publish sites take a real on-disk EX slot for an unpublished inode
and pass `NULL`/`MXFS_AUTH_GEN_NONE` for the grant result, so
`mxfs_dlm_authority_install` is never reached or is a no-op:
`mxfs_dlm_publish_drain_loop` (non-routed directory arm), `mxfs_dlm_publish_dirs_work`,
`mxfs_dlm_publish_inode`. Because the inode is then cached EX, every later op
uses the ilock_begin fast path and never re-enters the lock layer — the tenure
never becomes provable for the inode's whole life. Instrumented in 0.75.84
(`P242-PUBCLAIM site=... rc=...`), which pinned the failure to a single inode
(ino=131) touched only by `site=drain` and `site=dirswork`, confirming both
`try=0` and `try=7` (a second signature, reachable via
`mxfs_dlm_rearm_unpublished` re-listing between delist and acquire) are the
same one defect
(`docs/history/docs/history/docs/history/compiled-tcp-2node-restart-campaign-sess561-562.md`).

Fix, 0.75.85 (sv 1AB3DD9847889D392108B72): all three sites now iget INCORE,
snapshot `i_mxfs_auth_gen` under `i_dlm_lock` before the claim, pass a real
`struct mxfs_grant_result`, and install under `i_dlm_lock` after the delist.
Lock order verified mechanically (no `m_mxfs_unpub_lock` section takes
`i_dlm_lock` inside it; nesting stays `i_dlm_lock -> m_mxfs_unpub_lock`).

## Closure discipline and outcome (sess562)

`docs/history/docs/history/docs/history/compiled-tcp-2node-restart-campaign-sess561-562.md` closed
D-0934, D-0935 and D-0937 as FIXED AND VERIFIED, applying the rule that a clean
run alone never proves a fix — the fix's own code path must have logged, not
just the symptom been absent (this is the same test that keeps D-0936 open).
Verification run: `tests/sess570_chain_ghost.sh LAPS=6`, chain s579a, 0.75.85 —
`RESULT: PASS label=s579a laps=6`
(`docs/history/docs/history/docs/history/compiled-tcp-2node-restart-campaign-sess561-562.md`),
zero shutdowns/kernel faults/lock-request failures, 12 foreign replays, cross-
grant workload saw all 300 peer files each lap. Ledger after: 93 open (66
critical), up from 95 open at sess561 start net of these three closures plus
new filings.

## Next authority thread found, not yet fixed: DINO no-owner population

After the D-0937 fix, one non-durable population survives on both nodes,
unchanged by that fix
(`docs/history/docs/history/docs/history/compiled-tcp-2node-restart-campaign-sess561-562.md`):
`P239-OWNAUTH-NONDUR blft=8 outcome=0` (`XFS_BLFT_DINO_BUF` / `MXFS_OWNAUTH_NOOWNER`),
~18-20 per node per 25-iteration run, stable across builds — a background
population, not fix residue. `mxfs_buf_derive_owner` has no owner arm for
inode-cluster buffers by design (a dinode buffer holds up to 32 inodes with no
single owner), so NOOWNER is correct from that arm; the real question is why
the inode arm is reached at all — it's the `!auth && ge` branch of
`mxfs_auth_classify`, meaning the node dirtied an inode-cluster buffer in an AG
whose grant it does not positively hold. This is the territory of the existing
open critical D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY /
D-FOREIGN-REPLAY-UNGATED-IMAGES — explicitly **not** D-0937 residue. Same fast
reproducer applies (`PREP=1 REPEAT=25 tests/dir_retype_authcap_probe.sh`); the
probe's own assertions only check blft 10-14, so it PASSES while this
population is nonzero — add a second assertion or count `blft=8` by hand
before treating a PASS as coverage. Next step: instrument the `!auth && ge`
branch to name the AG and dirtying path per blft=8, the same technique
(`P242-PUBCLAIM`) that rooted D-0937 in two runs.

## Scope note

Miner classification of the 92-95 open records, run twice this campaign
(`docs/history/docs/history/docs/history/compiled-tcp-2node-restart-campaign-sess561-562.md`,
`docs/history/docs/history/docs/history/compiled-tcp-2node-restart-campaign-sess561-562.md`):
SCALE_ONLY 61, TCP_2NODE 18, CAW_ONLY 6, AGNOSTIC 7. In-scope for the
directive (two-node TCP only) = TCP_2NODE + AGNOSTIC.

## Harness fix noted in passing

`run.sh` TEARDOWN now reads `/proc/mounts` instead of `mountpoint -q`
(`docs/history/docs/history/docs/history/compiled-tcp-2node-restart-campaign-sess561-562.md`) —
an ESTALE-answering mount used to be skipped by the old check and bricked the
next two preps.
