<!-- TCP 2-node departure/authority campaign sess518-520 (0.75.28-0.75.34): D-0912/0287/0913/0910/0914/0538/0915/0536 chain, D-482 instrumentation, two-no… -->
# TCP 2-node departure/authority campaign, sess518-520 (0.75.28-0.75.34)

Direct continuation of the sess513-517 campaign, under a hard user directive
issued mid-sess518 and repeated twice more across sess519 ([[feedback-scope-is-two-node-tcp-only]]):
rig is test1+test2 on the QNAP LUN, TCP transport ONLY. No CAW leg, no 32- or
4-node leg, no extra VMs, even when a ledger record's own closure condition
names one — note it out of scope and move on. Trigger: a session had inherited
test3/test4 from a prior 4-node lap, delegated a CAW re-prep for one record's
CAW leg, and was planning a 32-node campaign because a dozen open records name
32/tcp or CAW as their closure condition.

## D-0912 — requester fail-stops behind a live holder (`docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess518-520.md`)
Filed from sess517's harvested death arm: a paused holder's rejoin outlives the
requester's 3x60s retry budget, so the requester hits the timeout classifier's
arm (3) ("DLM inode lock unrecoverable", rc=-110) and self-fences via the
EXCLUSIVE gate instead of waiting out a holder it can see is still live. Fix
0.75.28: `mxfs_dlm_resource_wait_is_live` / `node_live_cb` (dlm.c/dlm.h),
`mxfs_dlm_caw_resource_holders_live` (dlm_caw.c), `v5_node_live_cb` (v5_mount.c:
self | valid lease && !dead-noted && !recovery-blocked/refused). In
`xfs_mxfs_dlm.c`, arm (2b) runs before arm (3): on `-ETIMEDOUT` with a live
holder, park (P-LKWAIT-LIVE, backoff min(500*laps,5000)) and restart instead of
failing. Harness `tests/live_holder_wait.sh`. Verified TCP leg (9/9, 12/12)
in `docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess518-520.md`;
CAW leg deliberately left OPEN as out-of-scope under the directive
(`docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess518-520.md`).

## D-0287 — membership purge / reconstruction — CLOSED F&V 0.75.28
Verified by `tests/live_holder_wait.sh` (s518a, 9/9) and
`tests/d0287_2node_death_rejoin.sh` (s518b, 12/12): recovery 88s, rejoin +125s,
clean sweep (0 PURGE-FAIL/PARTIAL/PENDING, 0 rc=-116, 0 TAKEOVER-NOINC).
Harness fixes landed alongside: md5 error text no longer laundered by `tr -dc`
(was masking real errors as garbage), pause-end check ordered on the holder's
own `/proc/uptime` instead of racing the END dmesg stamp
(`docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess518-520.md`, `docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess518-520.md`).

Rig trap surfaced here: a withdrawn/self-fenced zombie mount makes `run.sh
prep` fail "unusable after power cycle" (external nodes are never
auto-power-cycled) — fix is `virsh destroy/start <node>`, wait for ssh,
remount `/src`, re-run `tests/sess507_chain_0750.sh <label> 1`.

## D-0913 — DLM wait spins unkillably with a signal pending — CLOSED F&V 0.75.29
Found via the AG-mask lap: a SIGALRM landing inside a 1s DLM wait makes
`mxfs_pal_cond_timedwait` (TASK_INTERRUPTIBLE) return 0 immediately with the
signal still pending, so the retry loop spins forever (task stays R, stime
climbs, wchan 0). Fix: `pal/linux/kern.c` cond_wait/cond_timedwait switch to
TASK_UNINTERRUPTIBLE when `signal_pending(current)`. Harness
`tests/dlm_wait_signal.sh` (7/7 verified)
(`docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess518-520.md`, `docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess518-520.md`).

AG-mask harness lesson from this same investigation: MXFS has no directory
rotor across AGs — every node's mkdirs land in its own AG. The harness's own
pre-create (in the writer's AG) was polluting the mask; drop it and let the
victim create its dir in its own AG.

## D-0910 — refused victim keeps mastership, blocking survivor root creates — CLOSED F&V 0.75.30
Measured on 2/tcp: after an AG-scoped terminal refusal, survivor root mkdirs
all TIMEOUT (~14.7s) via P-RBLK-DENY-DEAD-MASTER — pages mastered by the dead
victim are never remastered or purged on TCP (`purge_out_of_closure` is a
no-op for `!dlm_caw`)
(`docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess518-520.md`).
Fix design decided from measurement, landed as 0.75.30
(`docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess518-520.md`):
`mxfs_v5_dlm_recovery_refused` gains `victim_inc`/`fswide`/`ag_mask`; first
refusal triggers `v5_note_dead_node` + `mxfs_lease_unregister_node` +
`v5_refresh_active_nodes` (remaster) + a **selective** ledger purge
(`mxfs_dlm_ledger_purge_owner_selective` filtered by a `closure_classify_fn`
so only provably-out-of-mask imported blockers of the dead node are dropped)
+ selective takeover (`dlm_takeover_page` variant that preserves in-mask
grants instead of retiring everything). FSWIDE skips the purge but still
remasters. Verified 39/39 (AG-mask), 45/45 (plain), 35/35 (fswide) in
`docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess518-520.md`.
Closure text carried forward pending board harvest through
`docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess518-520.md`,
`docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess518-520.md`,
`docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess518-520.md` —
re-verified again on 0.75.33 and finally CLOSED together with D-0915 in
`docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess518-520.md`
and confirmed in
`docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess518-520.md`.

## D-0914 — inode allocator rotor picks the quarantined AG — CLOSED F&V 0.75.31
Filed from the AG-mask lap: the single-node inode rotor
(`xfs_dialloc_pick_ag`/`xfs_dialloc`) breaks its AG-search loop on `-EIO`
(only `-EAGAIN` skips), so a quarantined AG picked by the rotor EIOs the whole
create instead of moving on. Fix: `xfs_ialloc.c` skips the quarantined AG;
fswide case returns `-EIO` up front. Closed via s519f (IN_MASK n=0, OUT_MASK
8/8, 0 gate refusals)
(`docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess518-520.md`, `docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess518-520.md`).

## D-0538 — block allocator doesn't exclude the quarantined AG — CLOSED F&V 0.75.32
Measured on 2/tcp with a new harness arm (`TDR_AGFILL`): fallocate of
`agblocks*4096+256MiB` in the root hits `P240-QUAR-AG-EIO agno=1`. Fix:
`xfs_alloc_vextent_iterate_ags` skips AGs covered by
`mxfs_quarantine_covers_agno` before `prepare_ag`. First verify (s519g) was a
false negative — a bare fallocate started allocation at AG 9 and never
touched AG 1; the harness had to be fixed to seed the file's first extent in
AG 0 (placed by the per-mount rotor) before fallocating, to actually exercise
the skip. Closed via s519i (`P538-AG-SKIP agno=1`, 48/48)
(`docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess518-520.md`, `docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess518-520.md`).

## Harness false positive: precond_readiness D-state check
Board FAIL "no D-state mxfs/writeback task" was a single-dmesg-snapshot false
positive catching a transient D-state sighting (e.g.
`mxfs-worker[bdev_pipelined_read]`). Fixed by sampling twice 2s apart and
convicting only a pid+wchan seen at both samples; transient sightings now
logged as `mxfs-precond-DSTATE-TRANSIENT`. Not an MXFS defect — no ledger
record needed (checked: all 5 existing records mentioning precond/D-state were
already closed)
(`docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess518-520.md`).

## D-0915 — TCP dir committed WITHOUT EX after a dead holder's deny — CLOSED F&V 0.75.33
Critical. First evidence (0.75.29): a mkdir raced a terminally-refused
victim's still-granted root EX and committed lock-less (P58-DIRPIN-NONEX,
P234-LOG-NOEX) while the harness saw `rc=0` and PASSed
(`docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess518-520.md`).
**First fix attempt (0.75.33 draft, sess520-MID)** diagnosed the gate as blind
because `mxfs_v5_dlm_any_recovery_blocked` only counted the "blocked" bucket,
not "refused"; patched that plus a new per-inode latch
`MXFS_IF_ACQ_REFUSED` (bit 28) read by `mxfs_quar_gate_locked` at six
post-ilock backstops
(`docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess518-520.md`).
**Re-measurement disproved that as the root mechanism**: on 0.75.30+ the
refused victim leaves the membership view entirely at P-RBLK-TERMINAL, so the
survivor becomes single-node and `mxfs_dlm_ilock_begin` takes the
**single-node bypass** path (no acquire, no install) — and the P58/P234
sensors are themselves gated on `!mxfs_v5_dlm_is_single_node`, so they are
blind by construction, independent of the refused/blocked bucket. Getting a
deterministic repro took four harness iterations (s520a-d): root-only misses
because mastership is a per-boot coin flip; targeting dirs the victim held EX
on but path-walking to them stalls 83s on the root lookup itself; the working
shape opens dir fds *before* the writer creates them (an fd holds no grant) so
creates are relative, not path-walked, landing genuine races in the
verdict-to-purge window
(`docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess518-520.md`).
Final fix, still 0.75.33: (a) `mxfs_v5_dlm_any_recovery_blocked` also counts
`recovery_refused_n` (closes the window, not the bypass); (b) the
`MXFS_IF_ACQ_REFUSED` latch, set in the `-EHOSTDOWN` arm and cleared at the
three grant-install sites, read only by `mxfs_quar_gate_locked` at post-ilock
backstops (`xfs_create`, `xfs_rename`, `xfs_trans_alloc_inode`/`_ichange`/`_dir`),
and only honored when multi-node && NL && no holders — so it can never latch
EIO permanently, since the bypass installs nothing. Verified s520e: 16 EIO in
the verdict-purge window (4 survivor-mastered dead-held dirs), 0 P58/P234
(`docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess518-520.md`).
Build trap: `xfs_inode.h` can't see `dlm/v5_mount.h`, and a file-scope forward
decl of `mxfs_v5_dlm_is_single_node` collides with other files' block-scope
declarations of the same name — resolved with a wrapper
`mxfs_dlm_mount_is_single_node()` in `xfs_mxfs_dlm.c`. Closed F&V together
with D-0910, board s520i 25 PASS
(`docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess518-520.md`, `docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess518-520.md`).

## D-0536 — SB runtime cover writes private counters outside the summary lock — fix 0.75.34, VERIFIED, closure owed
Racing a paused node's SB hold against another node's periodic SB cover
write, the cover wrote counters unlocked. Fix: `mxfs_sb_runtime_cover()`
(xfs_log.c) takes the summary mutex, reads counters coherently under
`m_sb_lock`, logs the SB via a dedicated `NO_WRITECOUNT` transaction +
`xfs_bwrite` + buftarg/blkdev flush, called from `xfs_log_worker` in place of
upstream `xfs_sync_sb` when clustered+lazysbcount;
`xfs_log_sb`'s in-item fold path skips the unlocked fold when
`m_mxfs_sb_cover_durable` is set, otherwise logs the durable coherent read
with a `P-SB-LOG-UNLOCKED` probe. Needed a new `mxfs.syncd_centisecs` module
param (bound to `xfs_params.syncd_timer.val`) because the fork's sysctl table
registers under a nonexistent `fs/mxfs` directory and `sysctl` isn't on the
nodes' non-login ssh PATH
(`docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess518-520.md`).
Verified via `tests/sb_runtime_cover_2node.sh`: pre-fix (s520j, 0.75.33)
reproduced `Y_unlocked_in_hold=1`; s520k (0.75.34, default period) caught only
the missing knob; s520l with `syncd_centisecs=100` PASS 15/15 — 4 covers, all
locked, 0 unlocked, 0 post-mismatch
(`docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess518-520.md`).
Closure text (F&V) owed pending the plain death lap (s520m) + board (s520n),
delegated nohup so it survives the session relay
(`docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess518-520.md`).

Build trap this leg: Claude Code's own low-memory background killer can kill
a kernel module build when other users' VMs hold ~20GB RSS on clyde — build in
the foreground with an explicit long timeout when that happens.

## D-482 — phantom-grant bail skips epoch bump (dentry ABA) — verification instrumentation only, UNBUILT
Fix landed 0.66.1 but was never verified. Instrumentation added to tree at
sess520-END: one-shot injection knobs (`dbg_p106_inject_ino/_shots`,
`dbg_p106_bail_pause_ms`), a `P106-INJECT-CONSUMED`/`P106-BAIL-PAUSE` probe
pair at the P106 stale-EX-bail site, and `P-DREVAL-EPOCH-FAST` probes at both
dentry-revalidate epoch fast-path sites. Harness design specified
(`tests/d482_phantom_epoch_2node.sh`: arm the injection on a cached dir-EX
holder, let a second node's request BAST it during the induced pause, confirm
the fast path is NOT taken for the raced names afterward) but not yet written
(`docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess518-520.md`).

## Rig/tooling traps collected this campaign
- `tools/mxfs_sshpass.sh` takes a bare hostname — it prepends `root@` itself;
  passing `root@test1` doubles to `root@root@test1` and gets rejected
  (`docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess518-520.md`).
- A withdrawn/self-fenced node fails `run.sh prep` with "unusable after power
  cycle" — `virsh destroy/start`, wait for ssh, remount, re-run the chain prep
  step (`docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess518-520.md`).
- AG-mask harness laps need `TDR_LAP_BOUND=400`; the chain's default 240s
  bound kills the probe mid-run
  (`docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess518-520.md`).

## Queued next (2/tcp-reachable, as of sess520-END)
D-398 (release drain re-logs a dead incarnation; fix landed 0.23.8/0.23.9,
32/caw-verified, needs 2/tcp verification — its harness derivation needs
`AGSHIFT=23` since the QNAP LUN has no local disk image to read geometry
from), D-0496 (leaf hash index loses entries after death+replay),
D-DUP-RELEASE-HANDOFF-INVARIANTS-UNVERIFIED, D-AFFINE-FASTPATH-STALE-DENTRY-VECTOR-UNTESTED
(`docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess518-520.md`).
