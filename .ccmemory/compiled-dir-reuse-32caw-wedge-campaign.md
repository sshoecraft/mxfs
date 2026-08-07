---
name: compiled-dir-reuse-32caw-wedge-campaign
description: Compiled: dir_reuse_coherency@32/caw — the 9-session multi-wedge campaign (ccloop a864, 0.10.34-0.10.61); six distinct wedges, roots and refutations.
metadata:
  type: project
tags: [c, o, m, p, i, l, e, d, ,,  , d, i, r, -, r, e, u, s, e, ,,  , 3, 2, c, a, w, ,,  , d, l, m, ,,  , c, a, w, ,,  , w, e, d, g, e, ,,  , o, r, p, h, a, n, -, b, i, t, ,,  , x, f, s, _, b, u, f, ,,  , l, o, s, t, -, w, a, k, e, u, p, ,,  , s, t, a, r, v, a, t, i, o, n]
---

# dir_reuse_coherency@32/caw — the multi-wedge campaign (ccloop a864, sess1-9)

For nine sessions this was **the single remaining criteria cell**: 101 of 102 applicable
caw cells PASS at 1/2/4/8/16/32; only this one never had. It was not one bug. It was
**six distinct wedges stacked**, each of which only became visible once the one above it
was fixed. The campaign resolved in later runs (first full PASS on 0.10.66; 32/caw
17/17 on 0.10.74).

## The workload and why 32 tips over

rank1 (test1) owns the lifecycle of ONE shared directory `ino=131`: it `rm -rf`s and
recreates it every round, while 31 peers create 50 files each (EXP=2×32×50=3200 entries).
24 rounds, budget 140×N = 4480s. dir_reuse PASSES at 2/4/8/16 and tips over at 32 — every
wedge below is single-hot-directory contention amplified 32 ways.

## Prologue — the binval fence wedge (fixed first, v0.10.34)

Before any of the wedges below, the run died at r3 to a **release-fence wedge on a freed
buffer's undestaged debt**. Chain: the r2 rm-tail btree collapse frees rank1's bmbt leaf
(`daddr=18839216`) with `lseq=102 > wseq=100` — the last two logs were collapse+free and were
correctly never written — but **mxfs's seq accounting survives the free**. In r3 the daddr is
reallocated as a dir DATA block and written by another node. test1's release-fence map-walk
then hits its own cached corpse (`done=0 stale=0 li_empty=1 undest`) → `data_durable=0`
forever, `P3F-UNLANDED-LOST` refusing the garbage ×15,006 laps → **240s EX hold on ino=131**
→ `P97-RELFENCE-WEDGE` shutdown → 14 peers die rc=-110.

Fix: equalize `b_mxfs_written_seq = b_mxfs_logged_seq` in `xfs_trans_binval` (+`P3B-BINVAL-RETIRE`
probe). Verified: P3B fired 56× on the rm, the r3 kill-zone passed clean, zero P3F/P97/rc=-110
through r6. **16-node never hit this** — a 1600-entry dir stays EXTENTS format and grows no
bmbt ([[AAA-ccloopa864-sess1-STATE-binval-zombie-fixed-rm-pace-hunt]]).

That memory also holds the rm-pace decomposition worth keeping: rm = 3200 sequential unlinks
× ~45ms EX-handoff, each BASTing ~31 PR holders (every node md5-reads every file in verify,
so all 31 hold PR), whose unlocks are read-modify-CAW on the **same slot** = thundering herd.
The old backoff `(retry + node*5) % 7` gives only **7 phases**, so ~5 nodes per phase
re-collide forever — replaced with true-random jitter.

## Wedge 0 — fairness. THE WRONG TREE (four runs burned)

sess1-2 spent B2-B5 tuning the CAW yield/streak fairness machinery: `ex_grant_streak`
PR-anti-starvation, `yield_set_ms` don't-re-arm, streak-reset-on-yield, upgrader-defers-to-
pure-PR. Two-sided starvation was real and reproducible — B2 starved EX, B3 starved PR,
moving the victim class with knobs *proved* the mechanism — but it was a symptom.
All four runs still died at r2/r3
([[AAA-ccloopa864-sess1-END-streak-fairness-built-next-run-B2]],
[[AAA-ccloopa864-sess1-PACE-war-and-use_free-corruption]],
[[AAA-ccloopa864-sess2-two-sided-dir-starvation-and-B4-fix]],
[[AAA-ccloopa864-sess2-FIXES-and-B8-status]]).

The reframe that broke it: merged-log forensics showed **ALL dir-EX modify events stop at
248s** yet a peer's PR acquire spins 360s on a slot with `ex=0 pr=0` — **holderless**. Not
contention. A stuck acquire ([[AAA-ccloopa864-sess2-REFRAME-reuse-boundary-acquire-wedge]]).

## Wedge 1 — the orphaned on-disk EX bit

`P-ACQ-STUCK` (dump the full slot when an acquire exceeds 15s) showed `hex=0x80000000`,
**gen frozen**: one node holds dir EX on disk while its in-core view says `state=NONE
mode=NL ex=0 pr=0`. The reused ino maps to the same CAW slot because `resource_id` carries
**no inode generation**, so a reclaimed inode's reset in-core state orphans a live disk bit
([[AAA-ccloopa864-sess2-ROOT-orphan-EX-bit-stale-DEMOTING]]).

Why nothing cleared it: `bast_process`'s release condition is
`ex_holders>0 || pr_holders>0 || pin>0 || gen_moved || orphan_live`, and on CAW **every
term is false** — `orphan_live` requires `p_rel_gen != 0`, which is *always* 0 on CAW. The
whole orphan-detection + 280-strike escalation is **TCP-only**
([[AAA-ccloopa864-sess2-DEEPROOT-bast_process-CAW-orphan-release-gap]]).

A second, independent reason found by code audit: `mxfs_dlm_caw_unlock_gen` locates the slot
by **hinted** `find_slot`; if our bit isn't in *that* slot it early-returns rc=0 "nothing to
unlock" with no CAS. `caw_held`/`inode_held_rawmode` use the same hinted lookup — which is
why `inode_held` returned 0 while the acquirer saw the bit set: **they were reading
different slots** ([[AAA-ccloopa864-sess3-ROOT-hinted-unlock-misses-orphan-slot]]).

### Two refuted fixes, and a costly misdiagnosis

- **Force-clear on the P72 shape REGRESSED.** `P72-SWALLOW-DEAD` (`state=DEMOTING mode=NL
  work_busy=0`) fires 7k-57k times, but it is **mostly the NORMAL deferred-release window**:
  `mxfs_dlm_ilock_end` sets DEMOTING then defers `bast_process` to `xfs_trans_free`;
  `work_busy==0` until the transaction commits. Force-clearing on that shape aborted
  legitimate releases → **57,593 swallows (7× baseline), wedged at r4, worse than the r18
  baseline**. Param defaulted to 0. *`mode==NL && DEMOTING` is NOT an orphan predicate*
  ([[AAA-ccloopa864-sess3-CORRECTED-model-frozen-holder-not-transient-swallow]],
  [[AAA-ccloopa864-sess3-FIX-orphan-forcerel-build-83F6743A]]).
- **`caw_unlock_backoff=1` (release-CAS-starvation theory) REFUTED** — made it worse;
  `bast_process` aborts *before* the unlock, so backoff never engages
  ([[AAA-ccloopa864-sess3-END-perf-drain-root-and-refuted-hypotheses]]).
- Fable's design review caught a **TOCTOU double-EX hole** in the naive predicate and
  ruled: use a claim protocol (CAS NONE→DEMOTING, re-validate inside the claim); the fix
  must **INVALIDATE, never flush** (flushing prior-incarnation cache into a reused inode is
  worse than the hang); and the real prevention is **reclaim-time release** — every
  `i_dlm_mode→NL` reset site must go through RELEASE, not reset
  ([[AAA-ccloopa864-sess2-END-fable-design-and-evict-formation-site]]).

**The fix that worked (0.10.50):** a CAW-only **wall-clock strand escape** —
`i_dlm_orphan_since_ns` + `caw_orphan_force_ms=3000`, resetting only on genuine consumption
(ACQUIRING / mode!=NL), never on gen churn, plus `!p15h_reap` bypassing the `gen_moved`
abort. `P15H-STRAND-TIMEOUT` fired 15+/node; r4-wedge → r9
([[AAA-ccloopa864-sess4-orphan-fix-WORKS-then-AIL-flush-deadlock]]).

## Wedge 2/2a — the durable-signal sync bwrite that never wakes

With the orphan cleared, rank1's `rm` wedged D-state 200-300s:

```
xfs_buf_iowait ← xfs_bwrite ← mxfs_dir_data_owner_scan (or mxfs_dir_bmbt_scan)
← mxfs_dir_flush_data_blocks ← mxfs_dlm_dir_durable_signal ← xfs_remove
```

**`inflight=0` on every device** — no bio in flight, yet waiting forever. A/B with
`dir_owner_scan=0` just moved the hang to `bmbt_scan`: not scan-specific, it's the
per-op durable flush's synchronous `xfs_bwrite`
([[AAA-ccloopa864-sess4-wedge2-is-durable-signal-sync-bwrite-hang]],
[[AAA-ccloopa864-sess5-WEDGE2-FRESH-bmbt-inflight0-lostwakeup]]).

sess4's first theory was an **AIL jam** (P91-BAST-PROTECT keeps the inode-cluster buffer
authoritative, nothing destages it, `_XBF_DELWRI_Q` collision per CLAUDE.md tension #1).
sess5 refuted it for the fresh repro: **a LONE stuck task**, xfsaild running, no bast
kworkers blocked ([[AAA-ccloopa864-sess5-HEAD-diagnostic-run-and-pathB-plan]]).

**ROOT (sess6):** `P-IOWAIT-STUCK` decoded `flags=0x30 (ASYNC|DONE) done=0 lseq==wseq` —
a real counted write **completed**, but routed through the **XBF_ASYNC branch**
(`if (ASYNC) queue_work/relse else complete(&b_iowait)`). `xfs_bwrite` clears XBF_ASYNC at
submit, but XBF_ASYNC is a **non-atomic b_flags bit set by four other paths** (readahead,
xfsaild delwri, buf-item unpin-remove, inode-cluster-flush-fail). Set it after the clear and
the sync waiter is never woken ([[AAA-ccloopa864-sess6-ROOT-wedge2a-async-completion-routing]]).

Fix took **three iterations** — a lesson in latching:
1. `b_mxfs_sync_wait = !(XBF_ASYNC)` snapshotted **at `xfs_buf_submit`** — override fired
   **0×**, still wedged, because the async flip landed *before* the snapshot
   ([[AAA-ccloopa864-sess6-PROGRESS-syncwait-fix-insufficient-diag-added]]).
2. Diagnostic build adding `sync_wait / ioend_seen / relse_seen` to the probe — the
   decode table that named the answer ([[AAA-ccloopa864-sess6-END-wedge2a-FIXED-now-peer-shutdown-r7]],
   [[AAA-ccloopa864-sess6-HANDOFF-diagrun-live-r5-clean-watch-outcome]]).
3. **`b_mxfs_force_sync` set by sync submitters under `b_sema` BEFORE submit**, OR'd into
   `sync_wait` — immune to the race. First run to complete all 24 rounds with
   `iowait_stuck=0` ([[AAA-ccloopa864-sess8-END-CRCfix-WORKS-wedge2-fix-built]]).

The durable signal is **load-bearing** — `durable_caw=0` durably LOST a dirent at r17/8-node
and fired `P-COUNTREGRESS` (stale-base RMW lost-update). Never ship it off
([[AAA-ccloopa864-sess5-durable0-fairhandoff-FAILED-hardhang]]).

## Wedge 3 — release-abort livelock (acquire starvation)

Default config then reached r8 with `fails=0` and stalled. `P15-REL-ABORT` on ino=131 fires
every ~40s: the abort at `xfs_mxfs_dlm.c:12056`
(`gen_moved || pin_only || orphan_live`) is a P58-double-grant safety, but under 32-way hot-dir
load **the local re-acquire always beats the pending remote BAST** → never hands off →
peers starve past the 120s barrier ([[AAA-ccloopa864-sess5-WEDGE3-release-abort-livelock-ino131]]).

`caw_fair_handoff=1` is **PARTIAL** — r8→r10/r11 with `fails=0`, but `P15-REL-ABORT` stays
at 300-566/round because it isn't only fresh acquirers, it's in-flight re-acquires and the
orphan case. The designed fix is **starvation-aware abort**: when a peer BAST has waited
past a threshold, PROCEED with the handoff instead of aborting — BAST-priority over local
re-acquire ([[AAA-ccloopa864-sess5-END-fairhandoff-partial-r10-nextsteps]],
[[AAA-ccloopa864-sess4-END-three-wedges-and-combined-config-plan]],
[[AAA-ccloopa864-sess5-COMPREHENSIVE-STATE-multihead-wedges]]).

## Wedge 4 — reproducible hard-hang spinlock deadlock

Two nodes hard-hung identically: most vCPUs HALTED, **one vCPU busy-spinning in an ~18-byte
window**, RCU stall, networking dead while `virsh domstate=running`. The idle→spin offset was
**IDENTICAL across nodes (0x116553F, KASLR-invariant)** = a fixed vmlinux code site = a
corrupted/leaked spinlock, almost certainly an mxfs-owned lock freed and reused under
dir-reuse churn. Config-independent (hit with default modargs too). Capture recipe:
`unknown_nmi_panic=1` on all 32 + `virsh inject-nmi` → stacks to the serial log.
**Do not power-cycle a hung node before capturing** — that lost test27's state
([[AAA-ccloopa864-sess5-HARDHANG-reproducible-spinlock-deadlock]]).

## Wedge 5 — the corruption family (bmbt leaf torn / double-alloc)

Once progress reached r5-r7, peers began **shutting down** (EFSCORRUPTED) and rank1 then read
the shared dir as `readdir=0` every round. Two mechanisms, both real:

**(a) RMW-restamp laundering — ROOT PROVEN.** A node that RE-ACQUIRES dir EX after peers grew
the dir RMWs its own **stale prior-tenure bmbt-leaf buffer** (never re-read from the coherent
medium); `mxfs_dir_bmbt_track` unconditionally re-stamps `b_tenure_id = i_mxfs_ex_grant_seq`,
which **defeats the sess66 xfsaild gate by design** (the P67 detector sees the laundering
moment and is log-only); xfsaild then writes that stale image onto the shared leaf
concurrently with the real holder → the on-disk leaf **tears** (valid structure, bad CRC) →
next reader EFSBADCRC → shutdown. Decisive evidence: three ranks writing the same block in a
200ms window, each locally believing `buf_tenure==cur_seq mode=5 ex=1`; raw LUN block
`numrecs=39` matching **no single writer**
([[AAA-ccloopa864-sess8-ROOT-PROVEN-bmbt-leaf-RMW-restamp-laundering]]).
Fix direction: at cross-node EX re-acquire, **DISCARD (invalidate)** the stale cached leaf —
never drain/bwrite it, which would clobber the peer's newer medium image.

**(b) Transient torn coherent read — FIXED (0.10.57).** A distinct, *timing* case: the prior
holder rewrote the leaf ~15× in 250ms then handed off 1.6ms later; the new holder cold-read
~30ms after and got an unsettled image. A later raw dump was valid — the state **settled**.
Fix = bounded coherent re-read retry in `_xfs_buf_read` for multi-node dir metadata failing
verify (`dir_read_crc_retries=8`, `dir_read_crc_retry_us=4000`), process-context only.
**PROVEN**: the round that shut the FS down on 0.10.56 logged `P-DIRCRC-RETRY-OK`, 0 shutdowns.
Cannot mask real corruption — a durably-bad block still fails after retries
([[AAA-ccloopa864-sess8-FIX-coherent-reread-retry-0.10.57]]).

**A critical measurement trap here:** the first sess8 reading claimed *concurrent* writes.
It was a **CLOCK ERROR** — per-node dmesg timestamps are unsynchronized; `realns` wall-clock
is the truth ([[AAA-ccloopa864-sess8-FIX-coherent-reread-retry-0.10.57]]).

**(c) AG free-space double-alloc ("Bug B")** — a block on the coherent medium durably
double-used as bmbt-leaf for ino131 AND dir-data (XDD3 where BMA3 expected). `P133` silent
(the adopted dinode IS coherent) + `P60-RELAUDIT INCONSISTENT-AT-RELEASE` frequent on healthy
peers (`di_nextents=26` vs `leafsum=63`). This is the multi-session-unclosed cross-domain gap:
the dir EX release flushes inode+data+leaf, but AGF/bnobt/cntbt are coordinated by a
**separate AG-DLM** ([[AAA-ccloopa864-sess7-ROOT-bmbt-XDD3-crc-shutdown-diagnosed]],
[[AAA-ccloopa864-sess7-FIX-target-AG-freespace-doublealloc]],
[[AAA-ccloopa864-sess8-repro-P78flood-singleleaf-two-mechanisms]],
[[AAA-ccloopa864-sess7-diagrun-live-r7-clean-watch-outcome]]).
Also here: `P15I-MEDIUM` never fired because the CRC-fail completion path runs in
**softirq** — `!in_interrupt()` was false. Medium verdicts must be deferred to process context.

## Wedge 6 — the wr_inflight leak and the convoy collapse

sess9 unified the r10+ collapse: a counted dir-metadata write's completion misses its
decrement → `m_mxfs_dir_wr_inflight` leaks **permanently** → every subsequent dir release pays
the full wr-barrier at *both* wait sites (`5000×msleep(2)` each) → **`P51-REL drain_ms=20013`,
the exact-20s signature** → 31 EX waiters × 20s/handoff → waiters blow the 120s budget →
rc=-110 → cascade. The old counter code RESET the flag and re-incremented on a double-submit
= a permanent +1 leak; 0.10.61 keeps the single count and logs `P-WRCNT-RESUBMIT` with the
buffer's event ring ([[AAA-ccloopa864-sess9-ROOT-wrcount-leak-20s-drains-run61-live]]).

Compounding it: **shutdown nodes kept contending.** A node that shut down at 1993s still
ACQUIRED ino131 EX at 2359s — a zombie tenure — and dead nodes' waiter bits persisted because
shutdown nodes **keep heartbeating**. Fix (0.10.60) = **shutdown withdrawal**: first
`xfs_do_force_shutdown` queues a worker that stops the disklock heartbeat so peers' expiry
purges our slots. Verified: rank3 fenced 12ms after shutdown, all 31 peers purged it
([[AAA-ccloopa864-sess9-STATE-r13-collapse-withdraw-fix-run60-live]]).

Slot facts settled here: the CAW slot table was **NOT filling** (159/65536 at r10) —
table-fill REFUTED by live count. Healthy handoff rate ~13/s. A slot with no holder and no
waiters gets recreated (gen reset) — benign, waiter registration is transient by design.

## Durable lessons

- **A symptom you can move with a knob is still a symptom.** Moving the starving class
  between EX and PR proved the fairness mechanism was real and irrelevant.
- **Reused inodes need generation in the resource id.** `make_inode_resource` carries none, so
  a reclaimed inode's in-core reset orphans a live on-disk bit on the *same* slot.
- **Hinted lookups create blind spots.** Two code paths using `find_slot` on different slots
  is why "holder says it holds nothing while the acquirer sees a bit."
- **`state==DEMOTING && mode==NL` is the normal deferred-release window, not an orphan.**
  Acting on it livelocked the cluster worse than the bug.
- **Latch sync intent under the lock, at the source.** Snapshotting a racy non-atomic flag one
  layer too late failed twice before `b_mxfs_force_sync` fixed it.
- **Per-node dmesg clocks are unsynchronized.** Use `realns`. One clock error produced an
  entire wrong root cause.
- **Never power-cycle a hard-hung node before capturing.**
- Rig discipline: killed runs leave ssh-wrapper and grep-pipeline processes holding
  `/tmp/mxfs_run.lock` → next run aborts. Never rebuild `mxfs.ko` while a run is live — a
  mid-run node reboot re-insmods and contaminates the experiment.
