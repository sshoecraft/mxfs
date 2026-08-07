---
name: compiled-c7ee71c6-sess30-39-authority-and-pace-era
description: Compiled: c7ee71c6 sess30-39 (0.11.265-330) — obligation-ledger/release-barrier campaign, coldread blind-close, ref-leak family, pace campaign, five…
metadata:
  type: project
tags: [c, o, m, p, i, l, e, d, ,,  , r, e, l, e, a, s, e, -, b, a, r, r, i, e, r, ,,  , P, 2, 1, 9, ,,  , P, 2, 2, 0, ,,  , c, o, l, d, r, e, a, d, ,,  , a, u, t, h, o, r, i, t, y, ,,  , p, a, c, e, ,,  , d, i, r, -, r, e, u, s, e, ,,  , u, n, m, o, u, n, t, -, l, e, a, k, ,,  , s, e, l, f, -, f, e, n, c, e, ,,  , s, t, a, t, f, s]
---

# c7ee71c6 sess30-39 — the authority-ledger and pace era (0.11.265 → 330)

Ten sessions that took the board from "20/21 with an unmeasurable authority family" to
**five consecutive all-green functional boards (322, 325, 326, 327, 330)** and the open
ledger from 12 down to 7. Organised by campaign, not by session.

## 1. The obligation ledger — how D-RELEASE-BARRIER-OPEN was finally closed

**The false negative first.** P220's original verdict "the release tails are clean" was an
artifact of the wrong predicate: it tested IFLUSHING, which is structurally blind. The
architectural fact that unlocks everything — `xfs_inode_item_precommit` attaches the inode
log item to the cluster buffer **at transaction PRECOMMIT, not at flush**, and
`xfs_buf_inode_iodone` detaches only items that were not re-logged. So a re-dirtied inode's
item stays attached across iodone while IFLUSHING clears
([[ccloop-c7ee71c6-sess31-P219-semantics-precommit-attach-and-the-real-hole]]).

**The numerator that broke it open:** the LEDGER predicate
`i_mxfs_pub_pending_seq != i_mxfs_pub_durable_seq` (pending++ at every
`xfs_trans_log_inode`; durable promoted only at real home iodone). Per lap at 32/caw:
unlocks=8234 obligation=10; epoch_ends=8918 **epoch_obligation=19..41 while
epoch_flushing=0**. Dominant class: freshly self-created empty child dirs
(`isdir=1 nlink=2 ili_f=0x3`, mode already NL, comm=kworker bast-drain) — the Phase-2 drain
completed and released while a commit was still open
([[ccloop-c7ee71c6-sess32-RELBAR-ledger-numerator-and-GPT-fix-design]]).

Shipped as `mxfs.relbar_enforce=1` (0.11.280): before the wire unlock, run up to 2 in-place
durable passes; if the ledger still won't close, DEFER the unlock via the existing
`-ESTALE` path. A/B: 10-12 leaks per lap at enforce=0 vs **0**
([[ccloop-c7ee71c6-sess32-relbar-enforce-shipped-default-on]]). Extended to both unlock arms
in 281; the residual shape was 119/70950 defers, **all on the one hot dir** — exactly GPT's
predicted cost of a missing admission interlock
([[ccloop-c7ee71c6-sess32-relbar-281-both-arms-hot-dir-defer-shape]],
[[ccloop-c7ee71c6-sess32-admission-interlock-design-ilock-barrier]]).

**Why FIX-A self-disarmed** (a category error worth remembering): its gate exempted
`ip->i_dlm_stale` — and the release pipeline **itself sets `i_dlm_stale` (src=5)** mid-pipeline.
Census: 459/459 leak events were dss=5. `i_dlm_stale` means next-tenure READ-cache staleness;
it says nothing about whether our committed writes landed. Removing the exemption (306) made
P244 defers fire and drove P241 blind-discharges to zero
([[ccloop-c7ee71c6-sess36-dstale-exemption-removed-terminal-leak-closed]]).

**Closed sess39** on its own ledgered test: full all-green board then a cluster-wide P220
census — ~130K unlocks, `obligation=0 / flushing=0 / in_ail=0 / pinned=0` on **all 32 nodes**,
defer backstop fired twice and correctly withheld
([[ccloop-c7ee71c6-sess39-END-326-board-green-9-open]]).

Supporting audits: GPT's condition 3 (per-I/O tuple capture) was **already satisfied** —
`flush_seq` is stamped only under the IFLUSHING interlock, single-flight per inode, so the
iodone promotion reads exactly the submitted image's watermark
([[ccloop-c7ee71c6-sess31-audit-gpt-cond3-satisfied-by-iflushing-interlock]]). The fix design
and GPT's ruling conditions (skip BOTH cases, three-state model not rollback-only, never
fence-free case-2 writes) are in
[[ccloop-c7ee71c6-sess31-relbar-fix-design-skip-if-durable-else-restage]] and
[[ccloop-c7ee71c6-sess31-GPT-ruling-stale-stage-mask-conditions]]. The buffer-side analog
(dir-DATA committed but never submitted) is scoped in
[[ccloop-c7ee71c6-sess32-dir-data-certificate-scoping]].

## 2. The stale-stage masks (P219 family)

Classes, from sharpened P219 data: **class X** = ORPHAN images (`nlink=0` with mode retained,
`bflags` shows a real home write, no XBF_STALE) published **at NL** after the staging tenure
died — the real hole. **Class Y** = xfs_iflush genuinely running at NL. **Class Z** = the
shared parent dir submitted under EX with a stage_epoch 2-4 behind
([[ccloop-c7ee71c6-sess31-P219-sharpened-classX-orphans-at-NL-classZ-stale-parent-midEX]]).

NL mask A/B (0.11.271): skip=0 wrote 2 dead-tenure images; skip=1 masked them, **0 to the
wire**, full guard sweep green at healthy walls
([[ccloop-c7ee71c6-sess31-P222-first-AB-mask-works]]). EX-side epoch gate shipped default-ON
in 289 with `sskip_ex_unl=0` always — skip-at-EX is always safe because staged bytes are
either equal to current (restage is a no-op) or peer-reverting
([[ccloop-c7ee71c6-sess33-EX-gate-shipped-P234-sensor-lesson]]).

**The inodegc authority class needed no new machinery** — MXFS does not defer inactivation:
with `m_mxfs_dlm && !single_node && journal_info==NULL` it runs synchronously at final iput,
so `xfs_inactive → xfs_ilock(EXCL)` *is* the "reacquire authority before dirty" design,
structurally. P234 source counters measured dirty-at-NL/PR = 0 strict
([[ccloop-c7ee71c6-sess33-inodegc-authority-verified-P234-zero]]).

A latent admission hole found by audit and closed: `mxfs_dlm_ilock_try` returned true on
`preempt_count() > 0` — an atomic-context trylock bypassing the DLM entirely (no DEMOTING
gate, no holder count). Measured **zero firings** on this workload, so 285 refuses EX in that
arm as pure latent-hole closure ([[ccloop-c7ee71c6-sess32-ilock-try-preempt-bypass-admission-hole]],
[[ccloop-c7ee71c6-sess32-P229-zero-EX-refusal-shipped-host-load-blocks-verdict]]).

## 3. D-CRASH-COLDREAD-STALE-SPLIT — the blind close

First hypothesis: overlapping same-daddr cluster writes completing out of order
([[ccloop-c7ee71c6-sess33-END-overlap-reorder-hypothesis]]). **REFUTED** — the cc=6 image was
never submitted at all. The real chain: an O_SYNC append committed **sub-EX** during a release
abort/re-entry; the durable pass staged cc=6; **`mxfs_iflush_cluster_merge_dirs` replaced the
staged slot with platter cc=4 without rolling flush back**; completion then honestly stamped
`durable=flush` over poisoned input = **BLIND CLOSE**; the anchored unlock ran (which is why
P228 was 0); reload adopted the stale platter and destroyed the only cc=6 copy. Loss =
acknowledged O_SYNC data, cluster-wide, silent
([[ccloop-c7ee71c6-sess34-coldread-blindclose-root-and-fixes]]).

Live capture of the whole chain in one 74ms window (P242 epoch churn → P239 overlay condemn →
P241 blind discharge), plus the classifier verdict that killed a proposed fatal tripwire —
**zero true-staleness in 17 events**, the class was false-positive churn
([[ccloop-c7ee71c6-sess35-coldread-live-capture-B3C-shipped]],
[[ccloop-c7ee71c6-sess34-END-295-296-instrumentation-and-enforce]]).
Patched at three links (B3 merge staging protection, honest-ledger rollback C, terminal
release gate) and closed sess36.

## 4. The reference-leak family (5-session hunt, closed)

**D-UNMOUNT-BUSY-INODES root:** `mxfs_dlm_bast_notify` starts with `xfs_iget`; its four
dispatch sites transferred the ref on `queue_work()` success but on **queue_work()==false**
returned without `xfs_irele` — the already-pending instance owns only the first donor's ref,
so each collision leaked exactly one. Every prior instrument failed because *the arms are
balanced*; the winning instrument was **tracefs kprobes on igrab/ihold/__iget/iput** with
per-inode running-count reconstruction. Fixed 307, proven by a 126-collision injector
([[ccloop-c7ee71c6-sess36-unmount-leak-ROOT-bast-notify-qfalse]]).

Teardown sibling: `xfs_io -x shutdown` **never worked on mxfs** — the whole xfs ioctl surface
is stubbed ENOTTY, so every prior scripted "shutdown -f" was a silent no-op. Fixed by handling
`XFS_IOC_GOINGDOWN` in the stub; class fix = arm-gate at all 25 sites + a put_super s_inodes
sweep ([[ccloop-c7ee71c6-sess37-armgate-sweep-313-engaging]],
[[ccloop-c7ee71c6-sess36-HANDOFF-310-built-teardown-fix-unverified]]).

Runtime siblings closed sess39: **D-EVICT-RETENTION-WIRE-EX-LEAK** (sess37 retention trusted
in-memory mode while the wire held EX — 190 orphans → 0 once retention required a
wire-confirmed PR) and **D-INODE-WIRE-EX-ORPHAN-ON-EVICT**, the true slot-leak mechanism:
the "unpublished ⇒ no on-disk slot" premise is false — every created file's type-1 slot exists
at gen=1 EX while still on the unpublished list, orphaning one slot per created-then-evicted
file (the 13.4K population) ([[ccloop-c7ee71c6-sess39-END4-330-fifth-green-board-7-open]]).

## 5. The pace campaign — and its disproof

**Create-cycle root, captured live:** each create is `lookup-PR (CAS storm) → full dir reload
→ EX upgrade → EDEADLK rc=-35 → PR drop through the FULL drain → fresh EX acquire → insert →
EX stripped`. ≥3 wire transitions + a drain + a reload **per create**, explaining 214 dir
transitions per round ([[ccloop-c7ee71c6-sess37-create-cycle-EDEADLK-root]]).

CREATEINT (take dir EX for the create-intent lookup, mirroring the existing PRIREAD precedent)
was designed, implemented, and **measured a NET LOSS** — 6 rounds knob-on vs 7 knob-off, because
it moves refresh+evict+FUA-reread inside the serialized dir-EX critical section. Defaulted off;
mechanism kept ([[ccloop-c7ee71c6-sess37-createint-implementation-sketch]],
[[ccloop-c7ee71c6-sess37-END-318-createint-built-untested]],
[[ccloop-c7ee71c6-sess38-createint-verdict-and-fairness-tail-root]]).

What *did* work: **direct EX handoff** (transfer ownership in the same release CAS),
**PR batch grant** (8.6× on the grant-wait anatomy: 11.1s/75 grants vs 95.8s/171),
**evict-retain-PR**, and a local eofblocks peek — which killed the dc convoy outright
(6.3-8.8s → 0.10-0.15s) ([[ccloop-c7ee71c6-sess37-handoff-retention-dc-convoy-dead]]).
PR batch-claim (322) removed the admission storms
([[ccloop-c7ee71c6-sess38-batchclaim-322-and-turn-anatomy]]). The 32-node create convoy's herd
was rooted as **waiter POLL cadence** (>1100 serialized FUA slot reads/s at one target), fixed
by a 250ms hopeless-defer + targeted nudge ([[ccloop-c7ee71c6-sess35-caw-herd-nudgev2-hopeless-defer]]).
First dir_reuse PASS in 11 runs came on 317, at exactly the 8-round floor with zero margin
([[ccloop-c7ee71c6-sess37-FINAL-drc-first-pass-8-rounds-bounce-proven]],
[[ccloop-c7ee71c6-sess37-HANDOFF-8-open-create-rotation-next]]).

**Then sess39 DISPROVED the whole defect.** The "bimodality" was not stochastic — it was
deterministic **run-over-run decay with idle recovery**: fresh after ≥25min idle = 8-9 rounds
PASS, consecutive runs plateau at 7. Every in-guest mechanism was refuted by measurement
(device queues, CAW table state byte-identical, tombstone chains, AGI chains, guest CPU, log
pressure with `xs_sleep_logspace=0` lifetime). The cause was **host storage**: a 93%-full
consumer SSD with an ambient 37MB/s writer exhausting the dynamic SLC cache
([[ccloop-c7ee71c6-sess39-drc-degradation-reframe-two-new-defects]],
[[ccloop-c7ee71c6-sess39-hostside-slc-exhaustion-hypothesis]]).
**RIG RULE: pace measurements are only valid from a ≥25min-idle storage state.**

Also corrected here: sess38's "drain-dominated" turn economy was **WRONG**. The P138 stage
split proves drain stages are ~1.6ms p50 while the **wire-unlock CAS** is p50 9.7 / p90 44ms —
that is the dominant slice ([[ccloop-c7ee71c6-sess39-END2-327-fourth-green-board-grace10]]).

## 6. Self-fence — a whole RULE-4 arc inside one session

test21 self-fenced during rsync. Initially read as a `P15-REL-ABORT` orphan loop; reframed by
code+deployment check — the heartbeat had failed to land for the **full 62s lease** and the
abort loop was a late co-symptom. The fence was correct behaviour
([[ccloop-c7ee71c6-sess38-CLOSE-323-board-10-open]],
[[ccloop-c7ee71c6-sess38-selffence-62s-lease-hb-qos-root-target]]).

The new P-HB-SLOW probe caught the mechanism live within an hour: `lockwait_ms=26726` with
`write_ms=0`. Root: **three disklock read loops held `ctx->lock` across full slot scans**
(~25s continuous holds against a 62s lease). Fix = per-slot lock/unlock.
**NEW INVARIANT: never hold disklock `ctx->lock` across a multi-slot I/O loop.** Bonus — the
323/324 `crash_consistency NO_TERMINAL_RECORD×32` events and a `fence_during_write` failure
were the *same* starvation surfacing elsewhere; all green post-fix
([[ccloop-c7ee71c6-sess38-END3-325-selffence-CLOSED-9-open]],
[[ccloop-c7ee71c6-sess38-END2-324-deployed-three-tripwires]]).

## 7. Other closures and finds

- **D-CAW-YIELD-STARVATION-SHUTDOWN**: a mode-compatible fresh acquire that defers on a
  `yield_to` ticket **never CAS-registers into `slot->waiters`** — registration existed only on
  the incompatible path — so releases rebuild the ticket as `yield_to = waiters` and the
  deferrer is invisible to the rotation it defers to. 10 nodes shut down in 1.8s
  ([[ccloop-c7ee71c6-sess31-ROOT-FIXED-caw-yield-starvation-shutdown]]). A second idle-holder
  arm was proven by *intervention* — a manual `ls` on one holder granted a 23.7-minute-starved
  waiter in seconds — and fixed with a strikeout downshift
  ([[ccloop-c7ee71c6-sess33-starvation-fix-and-coldread-split]]).
- **D-MOUNT-DEGRADES-WITH-USE: closed as a detector artifact.** `sustained_load`'s rmrf phase
  deletes the *previous run's* tree, so every "fresh fast" rmrf was a first run deleting nothing.
  A matched-tree control (fresh mkfs, three runs: 7ms / 1354ms / 1414ms) severed mount age
  entirely ([[ccloop-c7ee71c6-sess36-FINAL-mount-degrades-closed-9-open]]).
- **D-STATFS-IFREE-NEGATIVE**: percpu `m_icount/m_ifree/m_fdblocks` receive only LOCAL
  transaction deltas — foreign deltas never land, and rank1's cluster-wide cleanup guarantees
  asymmetry, so it is monotonic drift, not a race. Per-AG summaries *are* cluster-coherent;
  statfs now sums those ([[ccloop-c7ee71c6-sess39-END3-statfs-rootcause-gpt-design]]).
  Residual open thread: near-ENOSPC cross-node delalloc overcommit.
- **NEW D-AGI-UNLINKED-CROSSNODE-RECOVERY-SHUTDOWN**, exposed by a grace=10 A/B: runtime
  `xfs_iunlink_reload_next` recovers a PEER's in-flight unlinked inode mid-churn →
  `xfs_droplink rc=-117` → dirty trans cancel → shutdown. **grace default stayed 40 because
  lowering it masks the race, and the race is the defect** — later moved to 10 only after a
  protective board ([[ccloop-c7ee71c6-sess38-END-322-allgreen-board-new-AGI-defect]],
  [[ccloop-c7ee71c6-sess38-FINAL-323-canary-armed-relay]]).
- **ICLUSTER Phase A** green at knob=1 across an 11-criterion board
  ([[ccloop-c7ee71c6-sess33-icluster-phaseA-board-green-one-wedge]]); writer-quiescence
  admission barrier shipped with the census-counting subtlety that raw forensic callers bypass
  `note_unlock` and would leak the census permanently
  ([[ccloop-c7ee71c6-sess33-wrq-barrier-shipped]]).
- Board/matrix state and the running closure scoreboard:
  [[ccloop-c7ee71c6-sess36-three-closures-board-green-10-open]],
  [[ccloop-c7ee71c6-sess36-END-matrix-caw-column-green-309]],
  [[ccloop-c7ee71c6-sess38-END4-325-full-green-board-9-open]].
- Earlier incarnation-coherence campaign (v0.11.83-86) that seeded several of these families —
  corpse-dir root, phantom AIL retire, CLMERGE dead-incarnation overlay, reload TOCTOU:
  [[ccloop-c7ee71c6-sess3-incarnation-campaign-fixes-83-86]].

## 8. Measurement traps — the most reusable output of this era

- **A probe that panics its own nodes.** P219's print passed a `u64` where the format had
  `comm=%s`; vsnprintf walked a nanosecond timestamp as a char pointer → GP fault → panic in
  xfsaild → reboot → counters wiped. Session 12's "nodes died with no visible error" was partly
  this, and **every prior `noauth=0` harvest carries survivorship bias**. Serial logs are
  root-only; unprivileged reads look empty
  ([[ccloop-c7ee71c6-sess31-P219-format-bug-panics-and-first-real-authority-hits]]).
- **Host contention masquerading as regression.** Four consecutive failures on identical code,
  no panic/EFSCORRUPTED/withdraw — just clyde under unrelated load. Check loadavg and
  `ps --sort=-pcpu` before believing any budget FAIL
  ([[ccloop-c7ee71c6-sess30-rig-contention-masquerades-as-regression]]).
- **Never queue a write on a reader-held hot-dir rwsem.** An unconditional
  `down_write/up_write` barrier convoyed readdir 65s → 240s: readdir holds ILOCK_SHARED across
  iteration and rwsem fairness blocks new readers behind the waiter. Quiesce belongs at DLM
  admission, not the rwsem ([[ccloop-c7ee71c6-sess32-282-283-barrier-convoy-lesson-and-incident]]).
- **dmesg persists across module reloads.** Raw counts mix builds; `epsrc` line numbers differ
  per build. Always `dmesg -C` at deploy or filter by `realns`.
- **Instrumented nodes self-straggle.** P44-MODGRANT does a sync slot read per dir modify —
  never attribute pace from instr-node windows alone.
- **The wrong authority sensor costs a build cycle**: `i_dlm_mode` is not valid mid-drain
  ([[ccloop-c7ee71c6-sess33-EX-gate-shipped-P234-sensor-lesson]]).
- **Capture fence/shutdown forensics immediately** — the kmsg ring rotates within about one
  board of churn.
