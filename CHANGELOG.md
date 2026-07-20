# Changelog

All notable changes to MXFS, newest first.

This is the single-page view of MXFS's history. It aggregates the per-subsystem
`## History` / `## Version History` sections that live in each subsystem's own
doc (`tools/*.md`, `dlm/*.md`, `packaging/*.md`); those sections remain in place
and are reproduced here verbatim. The authoritative current version lives in
`VERSION` — the build never reads it from this file.

Two lineages are preserved: the **version-tagged** tools/packaging history
(0.6.0 → 0.9.x) and the **dated** DLM subsystem dev logs.

## [0.11.16] — 2026-07-18

**ICLUSTER Phase 1 complete — inode-cluster DLM granularity for regular
files, live behind `mxfs.icluster_dlm=1` (load-time only, default 0).**
Regular files on the CAW transport acquire/release dinode coherence
through ONE on-disk resource per inode cluster (`ino & ~(ipc-1)`,
LTYPE_ICLUSTER) instead of one per inode — the op-budget fix for the
per-file-touch device-op wall (see 0.11.12-15: five op-shave fixes left
dir_reuse flat because granularity, not probe count, is the wall).

- Mediating layer REWORKED from refcounts to a **coverage-sweep design**
  (session-4 audit): the release decision scans covered in-core inodes
  for granted modes / in-flight acquires instead of trusting per-grant
  counters.  The per-inode machine has half a dozen recovery paths that
  set `i_dlm_mode = NL` without a release call (P72 orphan escape, P106
  phantom bail, unmount teardown, single→multi wipe), the PR→EX upgrade
  is lock-lock-unlock, and a nowait admit counts on one side only — any
  counter imbalance either wedges the cluster (leak) or split-brains it
  (steal).  The sweep makes all of them converge by construction.
- Grant retention: the cluster disk grant is kept at idle and released
  only under a pending peer BAST with a clean sweep; fan-out arms the
  existing per-inode drain machinery on covered in-core granted inodes
  (absent/NL inodes are skipped — their no-slot recovery paths would
  issue per-inode device ops that don't exist under cluster granularity).
- Routed call sites: central ilock_begin slow-path acquire,
  publish-on-create, deferred-publish walker 1 (walker 2 is dir-only —
  dirs keep per-inode resources), both bast_process release branches,
  evict/free release (`is_free` piggybacks the tombstone CAS iff the
  call performs the cluster release), unmount-teardown release skip,
  `xfs_ilock_nowait`/IOLOCK try-admit (fast-coverage only, bracketed by
  `i_dlm_acq_inflight` so sweeps can't miss the window), EDEADLK
  upgrade standoff mapped to a self-BAST (drain + release + clean
  re-acquire), iget visibility nudge gains a cluster PR nudge, ioend
  nested-EX admit and reload `sc_grant_held` consult the cluster grant
  (per-inode probes would false-negative on routed files and adopt
  stale disk over live in-core state).
- Everything is inert at `icluster_dlm=0` (default): routed predicates
  compile to the legacy calls exactly.

## [0.11.12 → 0.11.15] — 2026-07-18

Per-file DLM device-op reduction series (ccloop 72513a13 sess3).  A kprobe
op-ledger over the dir_reuse phases attributed every SCSI command in the
hot paths; these releases removed the largest avoidable classes.  (Round
time is still bounded by per-file lock granularity — batching work next.)

- 0.11.12: find_slot probe chains read in 16-slot SPANS (one READ(16)+FUA
  per span instead of per slot); P125-AG-DIVERGE on-disk assertion moved
  behind mxfs.p125_ag_diverge (default off — it cost xfsaild 5.3 FUA
  reads per create on every AG-metadata buffer write).
- 0.11.13: dir-EX fast-path on-disk held-verify re-throttled on CAW
  transport (100ms/inode; a TCP-focused change had made it per-serve =
  4.8 FUA chain-walks per create); sess6 phantom counters + P42 + the
  sess107 enforce now share ONE rawmode slot read per verified serve.
- 0.11.14: UDP GRANT NUDGE — releasing/handing-off nodes multicast
  MXFS_GRANT_MAGIC when the CAW'd slot had other waiters; blocked
  acquirers sleep on a PAL condvar and wake immediately instead of eating
  the up-to-25ms poll backoff (acquire-poll sleep in an 8-node create
  phase: 4.6s → ~6ms).  Poll remains the lossless backstop.
- 0.11.15: grant-time stamping of i_dlm_heldchk_j (fresh grants skip
  p108/dir-serve/cluster-durable on-disk held-verifies — one-shot inodes
  were paying ~2 chain walks each); close-demote suppressed for unlinked
  inodes (0.11.11's demote forced xfs_inactive to re-acquire EX from
  scratch, ~5 extra ops per rm'd file); P87 grant-persist readback
  sampled 1/64 for inode grants (AG grants still every-grant); BAST poll
  relax interval 1000→4000ms (UDP hint resends at 100ms are the primary
  waiter-discovery path; the poll sweep was the #1 idle read source).

## [0.11.11] — 2026-07-18

Write-once EX demote (ccloop 72513a13 sess2→3): a REGULAR file's cached
EX self-demotes ex_close_release_ms (default 250ms) after the last close
of a written file, so a peer's first read pays no EX handoff.  Cross-node
cold stat 6.1ms → 4.4ms.  Note: no net dir_reuse round win (the demote
drain competes with the create stream and rm re-acquisition was fixed in
0.11.15); default retained pending the lock-granularity work.

## [0.11.10] — 2026-07-18

CAW lock-wait liveness extension (ccloop 72513a13 sess2):

- The 120s CAW acquire timeout existed to detect dead holders, but dead
  holders are already detected and purged by disklock lease expiry (slot
  bits cleared → waiter promotes).  Under 32-node fio saturation the
  hold-time tail of LIVE holders (dio-completion convoys on ILOCK feeding
  AG/extent-conversion chains) crosses 120s: the waiter then surfaced
  -ETIMEDOUT into userspace (fio create failed on test28, board-killing)
  or into mxfs_dlm_ilock_begin's force-shutdown (the 0.11.8 board: ONE
  wedged holder → 31 peer shutdowns in one second).  Upstream XFS never
  times out allocation waits; erroring on a provably-live holder is a
  semantic bug.
- mxfs_dlm_caw grant waits now extend past the base timeout WHILE every
  blocking holder (slot-holder bitmap ∩ heartbeat tracker via a new
  v5_mount→disklock liveness oracle) is provably alive, up to a hard
  cap MXFS_CAW_WAIT_HARDCAP_MS=480s — so a live-but-wedged holder (P113
  family) still surfaces as a timeout instead of hanging forever.
  P-WAIT-EXTEND logs each extension episode.  Slowness stays visible at
  the harness layer via RULE-0 per-test budgets.

## [0.11.9] — 2026-07-18

Instrumentation for the dir_reuse@32 AIL-drain wedge (all-32-node
shutdown, 16:35Z): buffer allocation-generation stamps
(b_mxfs_alloc_gen / ili_mxfs_buf_gen) prove or refute li_buf recycling
at P113-DRAIN-WEDGE time; P-BUF-FREE-WITH-ITEMS screams with a stack if
a buffer is freed with log items still attached.  dir_reuse@32/cawd
PASSed 32/32 on this build (first ever) — wedge did not recur; traps
stay armed.

## [0.11.8] — 2026-07-18

mmap-fault vs bast-drain ABBA deadlock fix (ccloop 72513a13 sess2, RULE-4
live capture on test20 during 32/cawd mmap_coherency):

- A page fault's readahead/read_folio path adds folios to the page cache
  LOCKED, then takes xfs_ilock(ILOCK_SHARED) → the per-inode cluster DLM.
  With no outer counted hold, that inner acquire slept behind the inode's
  own bast drain — which was itself spinning in invalidate_inode_pages2 →
  __folio_lock on the folio the faulting task had locked.  Mutual wait,
  permanent: python3 D-state in P73-WAITSTALL (state=DEMOTING,
  work_busy=RUNNING) for 20+ min vs mxfs-ino-bast kworker in
  folio_wait_bit_common; the wedged inode then blocked the AG's AIL push,
  wedging the AG bast drain and the next chunk's fio in cancel_work_sync
  (relatime atime-EX BASTs during mmap_coherency's 32×32 cross-read
  supplied the demotes; 31 nodes timed out at the verify barrier).
- Fix in pal/linux/xfs_file.c: counted cluster-ilock hold across the
  whole fault, mirroring the buffered-read syscall path's IOLOCK_SHARED
  ordering (DLM hold before any folio lock).  xfs_filemap_fault takes
  PR around filemap_fault; __xfs_write_fault takes EX around
  page_mkwrite (same inversion via iomap's locked folio → ILOCK_EXCL).
  DLM hold only — no i_rwsem in fault context (rwsem→mmap_lock order).
  bast_notify already defers (state=BAST, no work queued) while holders
  are counted, and the FIX-1 nested-hold arms admit the inner acquires;
  the last ilock_end refires the deferred release.

## [0.11.7] — 2026-07-18

Buffer-lifecycle and teardown hardening (ccloop 72513a13), from two
root-caused crash families on the 32/cawd boards:

- test25 guest panic (BUG mm/slub.c:553, double kmem_cache_free in
  xfs_buf_free_callback during 32-node dir_reuse churn; its mid-write
  death then CRC-tore a shared dir da3_node block and shut down the
  readers).  All frees funnel through xfs_buf_free → single chokepoint:
  new b_mxfs_freeflag tripwire makes a second xfs_buf_free a
  P-BUF-DOUBLEFREE alert + no-op, and new P-BUF-RELE-ZERO poison guards
  in xfs_buf_rele_cached/_uncached stop a zombie rele from wrapping
  b_hold and resurrecting the buffer into a second free (also prevents
  the double perag-put/hash-remove side effects).  Ranked producers
  (P-RAFIX hold-steal; sync-credit completion misroute) stay under
  observation — the guards now convert any recurrence into a caught
  stack instead of a panic.
- Recurring "Unable to access opcode bytes at 0xffffffffc1..." panics
  (4-20 per node in serial-log history): bio_endio/end_clone_bio firing
  into UNLOADED mxfs text.  Root: disklock stop_heartbeat's Bug-99
  5s join ABANDONED a heartbeat thread stuck in a slow 512-byte slot
  read; teardown+rmmod then outran the thread and its in-flight bio.
  Fix: the timed join now escalates to a blocking join (bounded by the
  guest SCSI command timeout + EH) — never abandon a kthread running
  module code.  Also closes the abandoned-thread park-loop leak and the
  disklock-ctx free-while-live UAF.

## [0.11.6] — 2026-07-18

Deferred extent-free AG-DLM patience (ccloop 72513a13). At 32/cawd
(direct-iSCSI rig, single path) the fio_perf saturation phase collapsed
eight nodes: a peer-held AG outlived the 120s CAW poll, the -ETIMEDOUT
surfaced through __xfs_free_extent into xfs_defer_finish_noroll, and the
defer machinery escalated it to a SHUTDOWN_CORRUPT_INCORE + cluster
withdrawal cascade (holders' release drains legitimately take minutes
under cluster-wide saturation — observed AG pages held 10+ min).

- xfs_extent_free_finish_item: convert the AG-DLM -ETIMEDOUT into the
  existing -EAGAIN requeue (re-log intent, roll, retry; each cycle
  re-registers the CAW waiter that BASTs the holder), bounded by new
  modparam `mxfs.efi_agwait_max` (default 8 ≈ 16 min patience;
  0 = legacy fatal-on-first-timeout).  New xefi_agwait counter
  (both xefi alloc sites already zalloc).  P-EFI-AGWAIT log per cycle.
- xfs_defer_finish_noroll: name an -ETIMEDOUT shutdown explicitly
  (attribution backstop for any OTHER intent type hitting the same).
- tests/suite/dlm_scaling.sh: per-node rate floor re-derived from
  measured 32-node bands (48-58 ops/s on two rigs, median 54 — the
  structural CAW publish pace sits ON the old 50 floor): N<=16 keeps 50,
  N>16 now 30 (collapse detector, not exact-pace assertion).
- Harness: run.sh/<dlm> axis carries all four deployment conditions
  (tcp|cawp|cawd|caw), rig-aware power-cycle recovery, per-condition
  device defaults; scripts/rig.sh (new) switches rigs; ladder_rung.sh
  takes a condition; matrix_check.py --cond; showstat base-transport
  match.  fuser -km footgun fixed in rig.sh node cleanout.

## [0.11.5] — 2026-07-18

NET2 §11 step 5 — membership plane (MEPOCH); gate 5 GREEN (engine
harness-only, NOT in Kbuild; the disklock.h MEPOCH layout and the
net2_msg.h wire family landed in 0.11.4's kernel build — srcversion
unchanged 3E0347D1B1DBA8468BDA751, not deployed).

- **§7.C single-decree epoch authority** (`dlm/net2_epoch.{c,h}`, first
  build + review fixes): bootstrap adopts the max valid committed record
  over all 64 HB slots (fresh image ⇒ epoch-1 self-quorum); proposer =
  lowest alive voter of E; voters (3 lowest of E's mask, 5 at ≥16) stage
  candidates PREPARED in their own records before ACKing; a later
  proposer adopts any PREPARED candidate — own or found on disk — and
  completes the SAME decree; commit targets old ∪ new members; periodic
  disk scan gives catch-up adoption and the zero-network self-fence.
- **Self-fence centralized at adoption** (review fix): fires on the
  member→excluded-with-fenced-bit transition, covering rx-COMMIT and
  disk-scan uniformly; a bootstrap adoption (no prior view) is a REJOIN
  of a bumped incarnation and never self-fences.  Clean LEAVE = removal
  whose fence_ok proof rides the proposal but whose fenced bit stays
  clear — leavers never self-fence; only real fences set the bit.
- **Epoch-0 records are incarnation-bump carriers**: skipped as
  committed candidates in bootstrap/scan (a pre-join bump could
  otherwise be adopted as an empty membership); `suspect_since` stamps
  only on the fresh transition so re-asserted suspicion cannot hold off
  the 2×probe proposer takeover forever.
- **Observer/SUSPECT machine** (`dlm/net2_membership.{c,h}`): 3
  independent observers (lease/probe/disk), ≥2 missing ⇒ SUSPECT;
  same-{inc,nonce} reconnect within grace ⇒ ACTIVE (a different
  incarnation never resumes the old one); grace ⇒ FENCING; DEAD only
  via incarnation-qualified fence_done.  Persisted-incarnation bump
  (+1, never 0, content-preserving incl. a stale PREPARED) and the
  boot-nonce helper live here.
- **User PAL gains `mxfs_pal_crc32c`** (pal/linux/user.c): table-driven
  Castagnoli matching kernel `crc32c()` raw semantics exactly (verified
  against the standard check vector and cross-validated against the
  independent chk_mxfs decoder).
- **`tools/chk_mxfs` decodes MEPOCH**: per-slot record at HB offset 456
  (epoch/members/fenced/voters/flags/inc, own magic + crc32c), PREPARED
  labeled and excluded from the committed summary line; corrupt CRC is
  an error.  Verified against records sealed by the engine on a
  loop-device volume, positive and negative.
- **Gate 5** (`tests/net2/gate5_mepoch.sh`): 8 mepoch scenarios (the 7
  success-criteria checks + the SUSPECT/inc-bump machine, 102 checks)
  × 4 seeds + N2_DEBUG pass + full-suite ASan sweep; 108s wall vs 120s
  pinned budget.
- **Harness port fix (root-caused)**: a full suite creates 42 vclusters;
  the old 256-port stride pushed the last clusters' listeners into the
  ephemeral range (33496 ≥ 32768), where a transient outbound source
  port owns the address and fails the bind — a rare last-scenario
  env-start FAIL under ASan.  Stride is now 16 (max port 23656) and
  gate run_matrix surfaces harness stderr diagnostics on failure.
- **Gate 2 matrix re-pinned to its own scope** (`run midcomms`, new
  harness group): steps 4-5 grew `run all` to 38 scenarios, blowing the
  19-scenario 45s budget from outside; gates 4/5 own their groups'
  sweeps (same re-scope gate 1 got when gate 2 took the matrix).  All
  four user gates re-run green after the stride change: g1 9s/30s,
  g2 39s/45s, g4 210s/300s, g5 108s/120s.

## [0.11.4] — 2026-07-17

NET2 §11 step 4 — lock plane (shard machine); gate 4 GREEN (harness-only,
NOT in Kbuild; net2_midcomms.c/net2_link.c fixes below DO ride mxfs.ko —
srcversion CA4E3BEF091ED5F4777EF8D, not deployed).

- **Lock plane green across the full §13.2 matrix**: 11 shard scenarios
  (killpoints ×9 poison points, partitions, reconfigure, closed-set
  recovery, 2-permanent-loss, idempotent failover, xfer-no-vote, waiter
  order, epoch-mid-op) × 4 seeds + full-suite ASan sweep, all PASS
  (`tests/net2/gate4_shard.sh`, wall 199 s, budget 300 s).
- **Leader completeness enforcement** (`dlm/net2_shard.c`,
  `dlm/net2_lock.c`): committed log entries are immutable (divergent
  write at seq ≤ commit ⇒ NACK, duplicate detection by full op
  identity); a NACK revealing a more-complete follower makes the leader
  ABDICATE into a snapshot pull from it (never "backfill" downward); new
  `term_proven` serve-gate — a leader answers client ops only after an
  entry of its own term commits on the quorum (barrier kicked by
  `net2_shard_prove_term`); lazily-created rank-0 with peers present
  pulls-from-all before serving (empty answers are completeness votes).
- **Snapshot wire + suffix transfer** (`dlm/net2_msg.h`): SNAPSHOT_CHUNK
  body 16→32 B — carries base + src_last (the §7.B "max commit_seq wins"
  vote; previously the base never crossed the wire and the fastest —
  emptiest — source claimed the stream); snapshots now ship the source's
  un-applied log suffix (commit+1..last) as 96 B log records so the
  pulling leader inherits and re-commits acked-but-unwatermarked entries
  (leader completeness survives transfer).
- **Closed-set recovery fixes**: a pull that finds no server state
  anywhere alive runs the §7.B recovery barrier instead of concluding an
  empty table; the recovering leader now installs its OWN client-held
  records (the implicit self-report previously only set the bit).
- **Election term escalation** (`dlm/net2_shard.c`): each candidacy round
  uses a fresh term above anything seen/voted — two simultaneous
  self-voted candidates at a constant term+1 livelocked forever
  (seed-0xBEEF kp4 hang).
- **Membership-epoch bridge at dispatch** (`dlm/net2_shard.c`): the
  lockplane dispatch now accepts the same E-1 window midcomms does (and
  the E+1 wave-front) — exact-match dropped the new leader's barrier
  APPENDs during the non-atomic epoch-commit wave, wedging SH_ELECTING.
- **Delayed-ACK arming kick** (`dlm/net2_midcomms.c`, in mxfs.ko): arming
  an ack deadline now wakes the egress worker; without it the 5 ms
  delayed ACK waited out the 100 ms idle sleep and every one-way exchange
  paid the peer's RTO (retx ≈ every message).
- Harness: `sh_reconfig` op-through resources de-collided from the
  spread (200+2 = 100+17·6 = 202 made the check a legitimate EX-vs-PR
  wait); `sh_two_loss` second-phase EX driven cross-node (same-node
  acquire-at-higher-mode is an upgrade under the CAW per-node-slot
  semantics net2_lock mirrors); `sh_partitions` last phase isolates a
  CURRENT follower (leadership migrates in the earlier phases) and keeps
  the orphan-carrying original leader connected; diagnostic N2DBG traces
  (CSEND/LSRX/RESULT/ADV/CHUNK0/SNAPREQ/RECOV-*/ABDICATE/EPOCH-DROP)
  kept — gated on N2_DEBUG, compiled out under __KERNEL__.

## [0.11.3] — 2026-07-17

NET2 §11 step 3 — CAW-neutral shared-code lift; gate 3 GREEN.

- **`dlm/dlm_shared.{c,h}`** (NEW, in Kbuild + the user harness):
  verbatim moves of `resource_hash_raw`/`resource_equal` (from dlm.c),
  `lock_compat`/`holders_for_mode_const`/`is_compatible`/
  `recompute_granted_mode` (from dlm_caw.c), and the v0.3.83 EX/PW
  single-holder popcount validity check (lifted out of
  `slot_appears_corrupt` as `caw_slot_holders_popcount_ok`).  Deduped
  in the process: dlm.c's own `lock_compat` copy, dlm_caw.c's
  `fnv1a_hash` (byte-identical to resource_hash_raw; 17 call sites
  renamed), and dlm_caw.c's two `mxfs_pal_popcount64` #ifdef variants
  (now in dlm_shared.h).  dlm_caw.h is not self-contained
  (`mxfs_dlm_bast_cb` comes from dlm.h) — dlm_shared.h includes dlm.h
  first, mirroring dlm_caw.c's include order.
- **Gate 3** (`tests/net2/gate3_cawsanity.sh`, NEW): forced
  `run.sh 2 caw prep_cluster` (marker records srcversion — a lifted
  build must re-form) + posix_multi + dlm_fairness on test1/test2 with
  `MXFS_DEV=/dev/mapper/mpatha` (LUN is dm-multipath since the
  0.10.120 ladder; bare /dev/sda is held by multipathd).  PASS:
  211/211 + 5/5 checks, prep 18 s, wall 32 s vs 300 s provisional
  budget → pinned 120 s.  CAW behavior provably unchanged.
- Userspace tools rebuilt (top-level `make clean` had removed them —
  run.sh's fs-prep needs tools/mkfs_mxfs on the NFS view).

## [0.11.2] — 2026-07-17

NET2 gate 2 FULLY GREEN — checkpoint A executed (first Kbuild edit for
the net2 engine, user-approved via the ccloop authorization block) and
the kernel 2-node smoke passes on test1/test2. srcversion
EAE6D695EB942023794C82B; only test1/test2 ever loaded it (the other 30
VMs stay on 0.10.120 — CAW criteria-met status undisturbed).

- **Kbuild**: dlm block gains net2.o, net2_link.o, net2_overlay.o,
  net2_midcomms.o, net2_fault.o — first `__KERNEL__` compile of the
  engine. Two real kernel-only findings, both fixed: frame-size
  warnings (>1KB stack) in `net2_midcomms.c` resume_flush/rto_scan from
  64-entry on-stack snapshot arrays — reworked to 16-entry chunked
  snapshots (`NET2_ENQ_BATCH`, re-locking between chunks; the snapshot
  exists because link->lock ranks above sess->lock) with COMM_AMBIGUOUS
  now reported per-session (identity fields are immutable post-create).
  User matrix re-verified green after the rework (the mc_ambiguity /
  mc_restart scenarios exercise exactly those paths).
- **Port registry**: `MXFS_PORT_NET2_LINK_BASE 7610` (link listen =
  base + slot, 7610..7673; 7605 stays membership-only) — the §14
  addition proposed at checkpoint A, user-approved.
- **Kernel smoke driver**: modparam-gated selftest in net2.c
  (`net2_selftest=1 net2_selftest_slot= net2_selftest_peer=
  net2_selftest_peer_slot=` [+ msgs/port_base]), hooked from module
  init/exit via the xfs_super.c declare-directly convention. Creates a
  standalone ctx (no mount, no seam), echoes reliable PINGs with PONG
  replies sent from recv-cb context (the step-7 seam's dispatch shape),
  asserts full ACK coverage, prints one dmesg marker, tears down; msgs
  capped at 24 so ping+pong ≤ 48 < the 64-entry tx ring (the recv cb
  must never block on window backpressure — it runs on the link recv
  thread that also processes incoming ACKs).
- **Smoke run 1 lesson (test-driver bug, engine correct)**: the early
  finisher tore its ctx down within ms of its own pass, dropping the
  peer's tail ACKs; the peer then hit COMM_AMBIGUOUS at exactly
  ambiguity_ms with retx=0 (no-route enqueues never reach the wire) —
  precisely the engine's specified peer-death behavior. Fix: 3 s
  post-pass linger before teardown (grace, not protocol). Run 2: both
  nodes PASS — 32/32 acked, 16/16 both kinds, retx=0, clean rmmod;
  13 s wall vs 180 s provisional budget → pinned 60 s.
- gate2_midcomms.sh --kernel-smoke implemented (was checkpoint-A-gated
  stub): reset both nodes (umount+rmmod, virsh power-cycle fallback),
  back-to-back insmods with swapped slot params, dmesg marker harvest,
  per-node srcversion verify, RULE-0 enforcement in-script.

## [0.11.1] — 2026-07-17

NET2 §11 step 2 (core engine) lands user-mode; gate 2's user matrix is
green. The kernel 2-node smoke is PENDING checkpoint A (the first Kbuild
edit, explicit user go-ahead) — mxfs.ko is byte-identical in behavior
(srcversion still 5221BFFE...; cluster stays 0.10.120).

- **Link layer** `dlm/net2_link.{c,h}` — TCP neighbor links forked from
  peer.c's lifecycle with three deliberate changes: lower-SLOT-initiates
  (identity is slot+incarnation; also removes peer.c's accept/connect
  cross-races), a per-link egress worker draining 5 priority queues by
  weighted deficit round-robin (20/30/25/20/5% quanta, fresh:retx 3:1
  sub-quantum, standalone ACKs first) replacing caller-context sends
  under send_lock, and free link teardown/reconnect (the retransmit ring
  owns delivery — a link event is a routing event, never node death).
  SYN/SYN_ACK TLV handshake (UUID/volume/fs_gen/nonce/features/wire-ver,
  fail-closed), fault injection at the frame boundary both directions.
- **Midcomms** `dlm/net2_midcomms.{c,h}` — sessions keyed
  {slot, incarnation, nonce}; per-direction u64 seq space, retransmit
  ring 64, cum-ack + 32-bit SACK, RTO 200 ms ×2 capped 2 s on a 50 ms RT
  tick; delayed ACK (5 ms / 8 frames) via egress cond_timedwait (PAL has
  no timer); msg_id dedup ring 1024; DELIVER-ON-RECEIPT (no reorder
  hold — ordering would defeat the priority classes; handlers are
  effect-idempotent per §6/§7.B); epoch stamped at enqueue with the E-1
  bridge on rx; >10 s unacked or coherence-class overflow ⇒
  COMM_AMBIGUOUS counter + callback stub (freeze wiring is step 6);
  session resume across reconnects, supersede on new incarnation with
  explicit abort dispositions (folded into stats.retired).
- **Routing provider** `dlm/net2_overlay.{c,h}` — vtable with the MESH
  provider (direct links, lazy retirement after drain); overlay slots in
  at step 8 without touching callers.
- **Engine core** `dlm/net2_ctx.h` + `dlm/net2.c` — ctx/lifecycle
  (deterministic stop: RT → links/listener → session abort), recv demux,
  `net2_pri_for_type()`, view updates, peer address book, evidence
  surface (`mxfs_net2_get_stats`/`get_session_stats`), fault control,
  `mxfs_net2_link_reset` test surface.
- **Harness step 2** `tests/net2/harness/vcluster.c` — in-process
  virtual cluster: N real ctx instances over localhost TCP through the
  user PAL, deterministic identities from the scenario seed, compressed
  time ÷10 + pinned real-time subset. `scen_midcomms.c`: 15 scenarios
  covering the §13.1 matrix (loss/dup/reorder/delay incl. ACK loss,
  reset at framing points + truncation desync, per-class backpressure
  [GRANT -EAGAIN vs coherence freeze-signal, never silent], restart +
  slot reuse + stale incarnation, epoch change mid-op with E-1 bridge,
  window/SACK/serial-arithmetic boundaries, malformed + cross-cluster
  rejects, COMM_AMBIGUOUS), each asserting the §13 standing invariants
  from the counters.
- **Gate 2 (user part) GREEN**: `tests/net2/gate2_midcomms.sh` — 19/19
  scenarios ×3 seeds + real-time subset + AddressSanitizer sweep (0
  errors, 0 leaks); ThreadSanitizer sweep clean on all mutex-guarded
  engine state (the only reports are the peer.c-precedent volatile
  stop-latches, documented in docs/net2.md). Budget pinned 45 s
  (27 s actual). Kernel `make modules` clean, 262 s.

## [0.11.0] — 2026-07-17

NET2 transport implementation begins (DLM_PLAN.md v2, one effort, gated
checkpoints — see DLM_IMPL_PLAN.md). Step 1 of 12 (protocol foundation):

- **Port registry** `include/mxfs/mxfs_ports.h` — names reflect wire
  reality (7602 = legacy lease + CAW BAST dual-use documented; 7603 = v5
  lease; 7605 reserved for NET2 membership). All port literals/defines in
  mount.c, v5_mount.c, lease.h, discovery.h, dlm_caw.h now read the
  registry; zero behavior change.
- **NET2 wire format v1** `dlm/net2_wire.h` — 64-byte LE outer header,
  field-by-field pack/unpack (never native-struct), SYN TLV block,
  feature bits, structural validation; static asserts compile in kernel
  AND user builds.
- **API surface** `dlm/net2.h` (identity, 5 priority classes, tunables,
  lifecycle), evidence counters `dlm/net2_stats.h` (§13), deterministic
  dual-build fault injection `dlm/net2_fault.{c,h}` (seeded xorshift64*,
  shared rule-string parser for modparam + harness).
- **User-mode protocol harness** `tests/net2/` — first dlm-linking
  userspace binary (standalone Makefile; not wired into top-level build).
  Gate 1 green: golden wire vectors (checked in), 100k-frame seeded fuzz,
  TLV round-trip/truncation, fault-engine determinism goldens; kernel
  `make modules` clean (srcversion 5221BFFE305AF21A).

Kernel module behavior is unchanged (port indirection only); the cluster
deployment remains 0.10.120/F2443A0C until §11 step-2 smoke.

## [0.10.0] — 2026-07-07

Repository normalization and first public release. No functional code changes.

- **Versioning normalized** onto one scheme: `VERSION` set to `0.10.0`; the
  man-page `.TH` headers (previously the `1.0.0` placeholder) and the
  `include/mxfs/mxfs_common.h` fallback macros (previously `0.0.0`) brought into
  line; the stale `mxfs_0.5.7_amd64.deb` artifact removed (packaging rebuilds
  from `VERSION`). `0.10.0` sits cleanly above the highest version already
  referenced in-tree (0.9.28) while staying pre-1.0.
- **Public-release docs added**: `README.md`, `LICENSE`, and this consolidated
  `CHANGELOG.md`.

---

## Release history — tools & packaging (version-tagged)

### mkfs.mxfs — formatter


- v0.1.0 (2026-03-23): Three bugs in `format_xfs_native()`. (1) AG geometry: `agblocks` via floor division, last AG larger than agblocks. Fix: ceiling division. (2) FSB encoding: `logstart` as linear `log_ag * agblocks + 5`, but XFS packs as `(agno << agblklog) | agbno`. Fix: packed encoding. (3) Log zeroing: used `packed_fsb * blocksize` for physical offset, but packed FSB != linear address when agblocks != 2^agblklog. Fix: use `(log_ag * agblocks + 5) * blocksize`. CRC32C was already correct.
- v0.9.27 (2026-03-18): Fixed fdblocks calculation — was adding 4 AGFL blocks per AG to sb_fdblocks, but AGFL blocks are reserved (not allocatable) and not counted in AGF.freeblks. Caused mount-time warning: "free_blocks from AGF sum differs from sb->fdblocks (stale sb)". Discrepancy was exactly 4 x agcount blocks (196 blocks on a 50GB device with 49 AGs).
- v0.9.13 (2026-03-12): Cleaned up output — removed duplicate post-format summary (layout already shown pre-format), removed mount hint.
- v0.7.1 (2026-03-10): Added FINOBT (free inode btree) initialization. Each AG now gets a FINO btree root block (block 4). AG 0 finobt mirrors the inobt record. Superblock features_ro_compat includes FINOBT bit. Inode chunk moved to block 16 (8-block aligned after FINOBT+AGFL), rootino changed from 64 to 128. AG 0 BNO/CNT btrees now have two free extent records (gap + main). Fixed sb_fdblocks to include AGFL blocks. resize_mxfs also updated.
- v0.7.1 (2026-03-06): Reversed on-disk layout. MXFS super now at offset 0 (prevents `mount -t xfs`). XFS data at end (enables future resize). Added `xfs_data_offset` to on-disk super. UUID generated upfront (not inside format_xfs_native). format_xfs_native takes `base_offset` parameter.
- v0.7.0 (2026-03-06): Native XFS v5 formatting. Eliminates mkfs.xfs dependency entirely.
- v0.6.4 (2026-03-06): Initial implementation. Replaces manual `disklock_offset=`/`journal_offset=` mount options.

### chk_mxfs — check / repair / geometry


- **0.9.13** (2026-03-11): Structural btree repair for damaged AGs. Inobt/finobt root reset: when all records are garbage (count=0) and AGI confirms no inodes, rewrites root as empty leaf. BNO/CNT btree rebuild: when btree blocks contain wrong magic (e.g., XFSB copies) and AG has no inodes, writes fresh single-extent leaves at standard positions (blocks 1,2), updates AGF roots/levels/freeblks/longest. Counting fix: validate_inobt_leaf skips totals accumulation for count=0 garbage records (prevents ifree > icount underflow). Superblock fdblocks repair now triggers on BNO btree sum mismatch.
- **0.9.12** (2026-03-11): Comprehensive CRC repair for all 8 structure types (MXFS super, journal super, journal slots, XFS superblock, AGF, AGI, btree blocks, inodes). Counter repairs for AGI icount/freecount from inobt, AGF freeblks from BNO btree, XFS SB icount/ifree/fdblocks from AG sums. Bug 123 fix: XFS SB counter repair used wrong CRC offset (0xC0 instead of 0xE0). Version derived from mxfs_common.h MXFS_VERSION macros.
- **0.6.2** (2026-03-10): Deep validation: free space btree (BNO/CNT) walk with record ordering, inode btree (inobt/finobt) walk with freecount/bitmask verification, inode spot-check (magic/CRC/format/mode/nlink), cross-check totals against superblock counters, per-AG summary report.
- **0.6.0** (2026-03-06): Initial implementation. Validates MXFS super, journal, disklock, and XFS structures with CRC32C verification.


### resize_mxfs — online grow


- v0.6.0 (2026-03-10): Added FINOBT root block (block 4) to new AGs. AGI now includes finobt fields (free_root=4, free_level=1). NEW_AG_HEADER_BLOCKS increased from 4 to 5.
- v0.6.0 (2026-03-06): Initial implementation. Adds new XFS AGs after existing data, updates XFS and MXFS superblocks. Supports dry run, verbose mode, block devices and regular files. Iterative resize (multiple grow operations) tested and working.

### packaging — DKMS · .deb · .rpm


- v0.8.2: Initial packaging with DKMS .deb builder
- v0.8.3: Added .rpm builder, PVE storage plugin, auto-detect OS, Bug 105 fix (TCP keepalive)

---

## Subsystem development history (dated dev logs, preserved verbatim)

### mount — VFS orchestration & public API


- 2026-02-15: Initial implementation with full mount orchestration, all callback bridges, and complete public API for filesystem operations.
- 2026-02-15: Fixed timestamps to use wall-clock time (BUG-3 fix). Changed all 5 timestamp locations from `mxfs_pal_time_ms() / 1000` (monotonic, time since boot) to `mxfs_pal_time_real_sec()` (wall-clock, seconds since Unix epoch). Affects: mxfs_create(), mxfs_mkdir(), mxfs_symlink(), mxfs_chmod(), mxfs_chown().
- 2026-02-15: BUG-B fix -- Added `mxfs_inode_cache_invalidate()` call in `mxfs_rmdir()` before freeing the inode to prevent stale cache reuse corruption.
- 2026-02-15: BUG-C fix -- Added mtime/ctime updates in `mxfs_write()` for both inline and extent-based write paths. Uses `mxfs_pal_time_real_sec()`.
- 2026-02-15: BUG-D fix -- Changed `mxfs_statfs()` to query live counters from allocator via `mxfs_alloc_get_counters()` instead of returning stale mount-time superblock values.
- 2026-02-15: Added data block deallocation in `mxfs_unlink()`. When nlink reaches 0, walks the inode's extent map and calls `mxfs_free_blocks()` for each extent before freeing the inode.
- 2026-02-16: Fixed BUG-1 (BAST not firing). Rewrote `dlm_bast_cb()` to handle both local and remote holders. Local holders: flush caches and release lock. Remote holders: send `MXFS_MSG_LOCK_BAST` over TCP. Previously only attempted local cache flush regardless of holder location, which did nothing for remote holders.
- 2026-02-16: Fixed BUG-2 (unmount deadlock). Added `NODE_LEAVE` broadcast at start of `mxfs_unmount()` so peers can purge the departing node's locks immediately. Added `MXFS_MSG_NODE_LEAVE` handler in `peer_msg_cb()` that calls `mxfs_dlm_purge_node()`. The primary deadlock was caused by BUG-1's BAST callback being invoked while holding DLM table_rwlock, which is fixed in dlm.c (see below).
- 2026-02-16: Added BAST debug logging: INFO-level messages for BAST send (local and remote) and BAST receive paths to trace cross-node lock coordination.
- 2026-02-16: Added `dlm_membership_cb()` callback: wired to DLM membership_cb, fires when active node list changes and DLM lock table is purged. Calls `dir_cache_drop_all()` and `inode_cache_drop_all()` to flush dirty data and discard all cached lock state, forcing next access to re-acquire fresh DLM locks from the correct master.
- 2026-02-16: Restructured `mxfs_unmount()` to prevent DLM lock timeout: flushes all dirty caches (dir/inode/block) BEFORE sending NODE_LEAVE and shutting down peers, sets DLM shutting_down flag to fail-fast remote lock requests, releases all DLM locks before destroying caches.
- 2026-02-16: BUG-F fix -- AG affinity broken: all nodes had preferred_ag=0. Root cause: `load_node_uuid()` ignored the UUID file path and derived node_id from hostname (identical on all VMs). Fix: added `mxfs_pal_read_file()` to PAL, rewrote `load_node_uuid()` to read `/etc/mxfs/node.uuid` (16 raw bytes), hash with FNV-1a for unique node_id per node.
- 2026-02-18: BUG-X fix -- `mxfs_rmdir()` allowed deletion of non-empty directories containing only regular files. The old check `nlink > 2` only detected subdirectories (each subdir increments parent nlink for `..`) but regular files do not affect nlink. Fix: replaced nlink heuristic with `mxfs_dir_readdir()` using a counting callback (`rmdir_count_cb`) that skips `.` and `..` entries. Returns -ENOTEMPTY if any real entries exist. Inode lock released before readdir (which acquires its own locks) and re-acquired afterward for modification.
- 2026-02-18: Write path optimization -- replaced per-block read-modify-write loop in `mxfs_write()` with contiguity-aware bulk write. New loop detects contiguous physical block runs via extent map lookups, then writes entire run via `mxfs_block_cache_write_range()` in a single locked section. For newly allocated blocks (`is_new=true`), skips unnecessary disk reads. Combined with coalesced flush and 1MB I/O buffer, this targets ~31x sequential write overhead.
- 2026-02-18: Read path optimization -- replaced per-block read loop in `mxfs_read()` with contiguity-aware bulk read. The old loop did 25,600 separate 4K reads for 100MB (each taking rwlock, cache_ensure, memcpy, release rwlock). New loop: (1) detects contiguous physical block runs via extent map lookups (same pattern as write path), (2) reads entire contiguous run via `mxfs_block_cache_read_range()` in a single locked section, (3) block cache read-ahead (`cache_ensure_readahead`) prefetches up to 256 blocks (1MB) on a cache miss in a single disk I/O. Hole regions are also coalesced (contiguous holes zero-filled in one memset). Reduces ~25,600 disk reads to ~100 for a 100MB sequential read.
- 2026-02-18: Direct I/O fast path for single-node operation. Added `mxfs_has_peers()`, `mxfs_read_direct()`, and `mxfs_write_direct()`. When peer_count == 0 (no cluster members), mxfs_read() and mxfs_write() bypass the block cache entirely, issuing direct mxfs_pal_bdev_read/write calls to the device. Eliminates per-block hash lookups, LRU management, cache eviction, and memcpy through the block cache layer. Still uses inode cache for extent map resolution. Handles block-aligned and unaligned I/O (unaligned falls back to temp buffer for read-modify-write). Falls through to the normal cached path when peers are present (coherency needed). Combined with VFS I/O buffer increase (1MB -> 4MB in frontend/linux/mxfs_file.c), improved read throughput from 66.4 to 91.3 MB/s (+37%) and write throughput from 50.6 to 59.2 MB/s (+17% new file) / 81.1 MB/s (overwrite).
- 2026-02-19: Wired alloc single-node optimization into mount. Sets `mxfs_alloc_set_single_node(mnt->alloc, true)` after alloc creation (before peers connect), and switches to false in `discovery_peer_cb()` when the first peer is discovered. This defers block cache flushes in the allocator to fsync/unmount when running single-node.
- 2026-02-19: fsync integrity hardening -- added unconditional `mxfs_pal_bdev_flush(mnt->dev)` at the end of `mxfs_fsync()`. Previously, device flush depended on flush_inode_to_disk finding a dirty inode (calls bdev_flush) and block_cache_flush finding dirty cache entries (calls bdev_flush). In edge cases (double fsync, BAST-evicted inode), neither path would issue a device flush, leaving data written via mxfs_write_direct (submit_bio_wait REQ_OP_WRITE) in the device's volatile write cache. The unconditional flush closes this gap. Audit confirmed virt_to_page zero-copy and single-node alloc skip are both correct. Data integrity verified: 10MB+50MB random pattern survives unmount/remount on iSCSI LUN.
- 2026-02-19: Bulk read fix -- 50MB cross-node read caused soft lockup and node unresponsiveness. Root cause: VFS read path did N+1 DLM lock acquire/release cycles (stat + N chunks), allowing BASTs to evict the inode between each chunk and creating a BAST storm under multi-node load. Fix: (1) Added `mxfs_read_bulk()` API that acquires inode PR lock once for the entire read and delivers data via callback in 4MB chunks. Internally uses new `mxfs_read_pinned()` helper. (2) Added `mxfs_pal_cond_resched()` to PAL for voluntary preemption. (3) Block cache `read_range()` now yields rwlock every 256 blocks (1MB) to unblock BAST handlers and lease renewals. (4) VFS read_iter rewritten to use `mxfs_read_bulk()`, eliminating separate `mxfs_stat()` call and VFS-level buffer management. Added `cond_resched()` in both read callback and write loop.
- 2026-02-19: Fixed remote BAST send failure handling in `dlm_bast_cb()`. Previously discarded `mxfs_peer_send()` return value, so transient TCP disconnects silently dropped BASTs. At 4+ nodes with 3 PR holders, losing BASTs meant holders never released their locks and never invalidated dir caches, serving stale data. Fix: added 3-retry loop with 50ms backoff and ERR-level logging on exhaustion.
- 2026-02-19: Fixed simultaneous unmount cross-node deadlock. When 2+ nodes unmount at the same time, each node's `mxfs_unmount()` flushes dirty caches which acquires new DLM locks, but the lock master (the other unmounting node) rejects the request. Both block indefinitely. Fix: set `mnt->dlm->shutting_down = true` BEFORE flushing caches (was after). Entries where we already hold a sufficient lock flush normally; entries requiring new lock acquisition are skipped (data was either already flushed during normal operation or will be recovered by journal on next mount). Changes: mount.c.
- 2026-02-19: Journal wiring into mount/unmount (Phase 1, Steps 4-6). Mount: after journal_create and claim_slot, if `journal_offset` mount option is set, opens on-disk journal (auto-formats if not found), opens the claimed slot, replays if dirty (previous crash), marks slot dirty. Unmount: writes clean unmount marker and marks slot clean before release. Added `journal_offset` mount option to mxfs.h, frontend parser, show_options. Wired journal to inode cache (`mnt->icache->journal = mnt->journal`) so `flush_inode_to_disk()` journals inode writes before applying to disk. Changes: mount.c, mxfs.h, inode_cache.h, inode_cache.c, journal.h, journal.c, mxfs_super.c, mxfs_internal.h.
- 2026-02-19: Journaling Phase 2 -- Multi-node recovery + full write coverage. (1) `lease_expire_cb()` now performs actual journal replay for dead nodes: finds the dead node's slot, acquires DLM EX lock on a JOURNAL resource keyed by dead_node_id for cross-node serialization, calls begin_recovery/replay/finish_recovery, releases lock. Runs in workqueue context so blocking is safe. (2) Wired journal into alloc (`mnt->alloc->journal`) and dir_cache (`mnt->dcache->journal`) during mount. (3) `mxfs_create()` now uses compound transactions: begins a single journal txn before alloc+inode+dir operations, sets it as `compound_txn` on the journal ctx so sub-operations log into it rather than creating separate transactions, commits/aborts at the end for atomic create semantics.
- 2026-02-19: Fixed chmod/chown/utimes not persisting to disk. `mxfs_chmod()` and `mxfs_chown()` marked the inode dirty but never called `mxfs_inode_cache_flush_inode()`, so changes only lived in the in-memory inode cache and were lost on remount/eviction. Fix: added `mxfs_inode_cache_flush_inode()` calls in both functions (matching `mxfs_truncate()` which already did this correctly). Also added new `mxfs_utimes()` function for explicit atime/mtime updates, and wired ATTR_ATIME/ATTR_MTIME handling into the Linux VFS `setattr` handler.
- 2026-02-19: Journal recovery on peer disconnect (fast path). Previously, multi-node journal recovery only triggered via `lease_expire_cb()` (180-second timeout). Node death is detected via TCP disconnect in seconds, but `peer_disconnect_cb` only purged DLM locks without replaying the dead node's journal. Fix: (1) Extracted journal recovery logic into shared `recover_dead_node_journal()` helper. (2) `peer_disconnect_cb` now also purges disklock, marks journal for recovery, and spawns a short-lived kthread for journal replay (deferred because the callback may run from `mxfs_peer_send()` in non-blocking context). (3) `lease_expire_cb` retained as fallback safety net, calls the same helper directly (runs in lease monitor kthread, safe to block). (4) DLM EX lock on JOURNAL resource prevents double-replay when both paths fire. (5) Added post-recovery cache invalidation (dir/inode/block cache drop_all) to ensure replayed metadata is not served stale from cache. (6) Recovery thread handle stored in `mnt->recovery_thread` (protected by `mnt->recovery_lock` mutex), joined before spawning a new one and during unmount. Changes: mount.c, mount.h.
- 2026-02-19: Fixed lease monitor not detecting dead peers (Bug 30). Two root causes: (1) `peer_disconnect_cb` called `remove_node()` which unregistered the peer from the lease system, preempting the lease monitor from ever detecting the dead node. Since lease renewals are sent over TCP, the renew thread's sends would eventually fail and trigger `peer_disconnect_cb`, removing the node before the 180s lease timeout fired. Fix: `peer_disconnect_cb` now calls `purge_node_dlm()` (new helper) instead of `remove_node()`, keeping the node in the lease table. Only definitive events (graceful NODE_LEAVE, lease_expire_cb) call `remove_node()` which unregisters from lease. (2) Related lease.c fix: JOINING nodes were not monitored for expiry (monitor only checked ACTIVE state). Changes: mount.c (new `purge_node_dlm()` helper, updated `peer_disconnect_cb`).
- 2026-02-19: Fixed DLM dead master re-mastering hang (Bug AA). After a node dies and `peer_disconnect_cb` fires, new lock requests whose FNV-1a hash mapped to the dead node entered an infinite retry loop, causing `ls -la` to hang in D-state. Root cause: `purge_node_dlm()` called `mxfs_lease_get_active_nodes()` to refresh the DLM active node list, but the dead node was still registered as ACTIVE in the lease system (by design -- lease expiry runs independently via timeout). The DLM's FNV-1a hash therefore still included the dead node as a candidate master, and new lock requests sent to it would fail. Fix: `purge_node_dlm()` now filters the dead node out of the active node list before passing it to `mxfs_dlm_update_active_nodes()`, so the DLM immediately recomputes mastering without the dead node. Changes: mount.c.
- 2026-02-22: Bug 45 fix take 2 -- REVERTED dir_add_entry retry loops from take 1 in mxfs_create/mkdir/symlink. The retry loop caused two regressions: (1) duplicate directory entries — retrying dir_add_entry without checking if the first attempt already committed the entry produced 200 duplicates in a 4-node 200-file-each test (535/800 unique, worse than 766/800 before); (2) D-state deadlock — the retry thread held the dir cache rwsem read lock longer than expected, starving the membership callback (mxfs_dir_cache_drop_all) and lookup (mxfs_dir_lookup) waiting for write lock on ino 128. Fix: removed retry loops entirely. All three functions now make a single mxfs_dir_add_entry call. On any error (including -ETIMEDOUT), the orphan inode is freed back to the allocator with error logging. The 120s DLM timeout (MXFS_LOCK_WAIT_TIMEOUT_MS) provides ample time for legitimate contention to resolve without retries. Changes: mount.c.
- 2026-02-19: Added `mxfs_sync_fs()` public API function. Flushes all dirty dir cache entries, all dirty inodes, all dirty blocks, and issues a device flush. Called by the Linux VFS `sync_fs` superblock operation to implement `sync(2)` and `syncfs(2)`. Without this, `sync` had no effect on MXFS and dirty inode metadata (size, extents, timestamps) stayed only in memory until BAST, eviction, or unmount.
- 2026-02-19: Fixed multi-node direct I/O (oflag=direct) D-state hang. Added `mxfs_write_bulk()` and internal `mxfs_write_pinned()` functions -- the write analog of `mxfs_read_bulk()`/`mxfs_read_pinned()`. `mxfs_write_bulk()` acquires the DLM EX lock once for the entire write and delivers data via callback in chunks, avoiding per-chunk DLM round-trips that caused BAST storms under multi-node load. For a 256MB write with 4MB chunks, DLM lock acquisitions reduced from 64 to 1. `mxfs_write_pinned()` extracts the core write logic from `mxfs_write()` into a helper that operates on an already-locked cached inode, supporting both the single-node direct path and the multi-node block cache path. `mxfs_write()` is preserved for backward compatibility with existing callers. Added `mxfs_write_chunk_fn` callback type and `mxfs_write_bulk()` declaration to mxfs.h public API.
- 2026-02-19: BAST deferral -- moved blocking local BAST processing off the DLM recv thread to a dedicated worker thread (`bast_worker_fn`). Previously, `dlm_bast_cb()` directly called `mxfs_dir_cache_bast_cb()` and `mxfs_inode_cache_bast_cb()` inline on the DLM recv thread. These cache flush handlers do disk I/O (writing dirty inodes, flushing block cache), which blocks the recv thread for milliseconds. Under heavy 4-node write load, the resulting TCP read stalls cause buffer overflow and peer disconnects. Fix: local BASTs are now queued as `struct bast_work_item` entries on a lock-protected linked list (`mnt->bast_head/bast_tail`). The `bast_worker_fn` thread drains the queue and processes items serially, calling the same cache flush handlers but in its own thread context. Allocation failure falls back to inline processing. Worker thread is started during DLM init (before callbacks are wired) and stopped during unmount (before DLM lock release), draining any remaining items. Changes: mount.h (6 new fields), mount.c (struct bast_work_item, bast_worker_fn, dlm_bast_cb rewrite, init/shutdown).
- 2026-02-23: Bug 50 fix -- membership change handler dropped dirty cache entries without flushing to disk, causing silent data loss of this node's modifications. Root cause: `dlm_membership_cb()` called `dir_cache_drop_all()` first, whose internal `dir_cache_flush_all()` calls `mxfs_inode_cache_get()` which triggers epoch-mismatch detection in `cache_get_locked()` (the DLM epoch was advanced by `update_active_nodes()` before calling the membership callback). The epoch mismatch evicts dirty inode cache entries and reloads from stale disk data, silently losing this node's modifications. Fix: added explicit flush-before-drop in both `dlm_membership_cb()` and `recover_dead_node_journal()`. Flushes inode cache first (direct `bdev_write`, no DLM needed), then block cache, then dir cache. After inode flush, on-disk data is current so any subsequent inode reload by `dir_cache_flush_all` gets correct data. The drop_all calls then find everything clean and just discard entries. This mirrors the unmount path which also flushes all three caches before teardown. Changes: mount.c (`dlm_membership_cb`, `recover_dead_node_journal`).
- 2026-02-23: Bug 50b fix -- corrected flush order in both `dlm_membership_cb()` and `recover_dead_node_journal()`. The original Bug 50 fix flushed inode -> block -> dir, but the correct order is dir -> inode -> block. Dir cache flush needs in-memory inode extent maps to locate directory data blocks on disk. If inode cache is flushed first, the DLM epoch advance causes `inode_cache_get()` inside `dir_cache_flush_all()` to see an epoch mismatch, evict the dirty inode (discarding its extent map), and reload from disk. With the extent map gone, dir entries cannot be written. This caused 1994 of 2000 directory entries to be silently lost on membership change. Fix: reorder flushes to dir -> inode -> block, matching the unmount path and `mxfs_sync_fs()`. Changes: mount.c (`dlm_membership_cb`, `recover_dead_node_journal`).
- 2026-02-26: Bug 57 fix -- remote BASTs received via `MXFS_MSG_LOCK_BAST` in `peer_msg_cb()` were processed inline in the peer recv thread, causing deadlocks. The `complete_bast()` handler acquires `cache->rwlock`, but a concurrent `touch`/`create` thread may hold that rwlock while waiting for a DLM grant message that arrives on the same recv thread -- classic AB/BA deadlock. fix: extracted BAST queueing into `queue_bast_to_worker()` helper function and route remote BASTs through the same bast_worker thread used for local BASTs. The recv thread stays free to deliver DLM grant messages, breaking the deadlock. Allocation failure falls back to inline processing (same as local BAST path). Also reduced high-volume DLM_TRACE logging for inode 128 cache hits and puts from LOG_INFO to LOG_DEBUG to prevent kernel ring buffer overflow that was losing critical diagnostic messages. Changes: mount.c (`queue_bast_to_worker`, `peer_msg_cb`, `dlm_bast_cb`), inode_cache.c (log level adjustments).
- 2026-02-23: Bug 50d fix -- replaced `dir_cache_flush_all()` + `dir_cache_drop_all()` in both `dlm_membership_cb()` and `recover_dead_node_journal()` with new `dir_cache_discard_all()`. The flush-based approaches (Bug 50/50b/50c) all failed because `dir_cache_flush_all()` during membership change triggers epoch-mismatch inode reload, then writes this node's cached dir entries (stale subset) to the physical blocks identified by the reloaded extent map, overwriting the departing node's complete directory. The fix eliminates the flush entirely: dir entries are always eagerly flushed during normal operations via `flush_dir_immediate()`, so the on-disk directory is always current. The new `discard_all()` drops all dir cache entries without writing, with logging of discarded dirty entries for diagnostics. Changes: dir_cache.h, dir_cache.c (`mxfs_dir_cache_discard_all`), mount.c (`dlm_membership_cb`, `recover_dead_node_journal`).
- 2026-02-28: Bug 66 fix -- async cache flush for DLM membership changes. `dlm_membership_cb()` previously performed synchronous cache flush/discard operations (inode flush, block flush, dir discard, inode drop, block invalidate) that block on disk I/O for 10-100+ seconds under load. This starved lease renewals because the cache operations held write locks and blocked the callback path, causing false node death detection. Fix: added a dedicated `cache_flush_worker_fn` thread ("mxfs-cflush") that runs independently of the DLM callback. The DLM membership callback now sets `cache_flush_pending=1` and signals the worker via condvar, returning immediately. The worker performs the identical flush+discard sequence (inode flush, block flush, dir discard, inode drop, block invalidate) in its own thread context. Uses 1-second condvar timeout for responsive shutdown. Falls back to synchronous flush if the worker thread could not be created at mount time. Thread is created after caches are initialized in `mxfs_mount()`, and stopped+joined before cache teardown in `mxfs_unmount()`. Changes: mount.h (5 new fields: cache_flush_thread, cache_flush_lock, cache_flush_cond, cache_flush_pending, cache_flush_stop), mount.c (cache_flush_worker_fn, dlm_membership_cb rewrite, init in mxfs_mount, cleanup in mxfs_unmount).
- 2026-03-01: Bug 69 fix -- extended membership change cooldown to peer disconnect path. The Bug 68 cooldown only applied to `lease_expire_cb`, but the 4-node test showed 44 epoch changes driven primarily by TCP disconnects (peer read failures), not lease expirations (only 1 fired). Under heavy I/O, TCP timeouts cascade: one node's stall causes DLM TCP timeouts on other nodes, triggering `peer_disconnect_cb` for each one. The DLM purge + cache invalidation from the first disconnect creates an I/O storm that stalls TCP on more peers. Fix: `peer_disconnect_cb` now checks `last_membership_change` against `MXFS_MEMBERSHIP_COOLDOWN_MS` before proceeding with the full node removal (DLM purge + disklock purge + journal recovery). If in cooldown, logs a warning and returns. The node will be caught by lease expiry if truly dead. The cooldown does NOT prevent TCP reconnection -- the peer subsystem handles that independently after the callback returns (peer_connect_force on the send path). Both paths now stamp `last_membership_change` when they proceed, creating a shared cooldown window. Changes: mount.c (`peer_disconnect_cb` cooldown check + timestamp, updated comments on `MXFS_MEMBERSHIP_COOLDOWN_MS` and `peer_disconnect_cb`), mount.h (updated `last_membership_change` comment).
- 2026-03-01: Membership stabilization timer -- prevents full DLM lock table purges on transient TCP flaps. Previously, every TCP disconnect + reconnect caused two back-to-back calls to `mxfs_dlm_update_active_nodes()`, each doing a full lock table purge and failing all pending requests. Under 4-node concurrent metadata workloads with dozens of TCP flaps per test, this destroyed all cached lock state repeatedly and made performance unusable. Fix: added a dedicated stabilization worker thread (`membership_stab_worker_fn`) that defers the `mxfs_dlm_update_active_nodes()` call until the membership has been stable for `MXFS_MEMBERSHIP_STABILIZE_MS` (3 seconds). The `mxfs_dlm_purge_node()` call on disconnect is NOT deferred -- per-node lock cleanup is still immediate. The `update_active_nodes()` call (which purges ALL lock table entries and rebuilds mastering across all buckets) is queued via `queue_membership_update()`. On a TCP flap (disconnect + reconnect within 3s), the timer resets on the reconnect event, then fires with the original full node set -- `update_active_nodes()` detects no net change and performs no purge. On genuine node departure, the timer fires with the departed node absent from the lease table, and `update_active_nodes()` detects the change and purges correctly. Falls back to immediate update if the thread could not be created at mount time. Shutdown: the stop flag causes the worker to process any pending update immediately before exiting, ensuring DLM sees the final membership state before subsystem teardown. Changes: mount.h (5 new fields: `membership_stab_lock`, `membership_stab_cond`, `membership_stab_thread`, `membership_stab_pending`, `membership_stab_ts`, `membership_stab_stop`), mount.c (`MXFS_MEMBERSHIP_STABILIZE_MS` define, `queue_membership_update()`, `membership_stab_worker_fn()`, `purge_node_dlm()` rewrite, `peer_connect_cb` and `discovery_peer_cb` updated, init in `mxfs_mount()`, cleanup in `mxfs_unmount()`).
- 2026-03-02: Bug 78 fix -- membership stabilization timer never fires because repeated discovery announcements from already-known peers continuously reset the timestamp. Root cause: `discovery_peer_cb()` called `queue_membership_update()` on EVERY multicast discovery announcement, including repeated announcements from already-known peers (sent every 500ms initially, then every 2s). Each call reset `membership_stab_ts` to current time, so the 3-second stabilization window never expired. Symptoms: DLM epoch never advanced beyond 1, all remote lock requests timed out (120s), all operations on non-master nodes hung in D-state, cross-node file creates returned ETIMEDOUT. Fix: check the return value of `mxfs_peer_add()` (returns -EEXIST for known peers) and return early from `discovery_peer_cb()` when the peer is already registered. Only genuinely new peers trigger `mxfs_lease_register_node()` and `queue_membership_update()`. The connection attempt (`mxfs_peer_connect`/`mxfs_peer_connect_force`) is still always performed for reconnection after TCP flaps. Changes: mount.c (`discovery_peer_cb`).
- 2026-03-03: Bug 83 fix -- DLM disconnect cascade prevention for 8+ node scaling. Three coordinated changes: (1) **Per-peer disconnect cooldown**: Changed `last_membership_change` (single global timestamp) to `last_peer_disconnect[MXFS_MAX_NODES]` (per-peer array, indexed by `node_id % 64`). Different peers are now processed independently -- only the SAME peer is suppressed within the 30s cooldown window. `lease_expire_cb` uses a separate global timestamp (`last_lease_expiry`) because cascading lease expiries are always correlated. (2) **queue_membership_update throttle**: Removed the dangling `mxfs_pal_mutex_unlock(mnt->membership_stab_lock)` left over from the Bug 81 workaround. Added 3-second throttle using `membership_stab_ts` -- if called within 3s of the last update, queues the event to the stabilization timer thread instead of updating immediately. Prevents O(N^2) DLM lock table scans during 8+ node startup. (3) **Updated comments and cooldown documentation** to reflect per-peer tracking. Changes: mount.h (`last_membership_change` replaced with `last_peer_disconnect[MXFS_MAX_NODES]` + `last_lease_expiry`), mount.c (`peer_disconnect_cb` per-peer cooldown, `lease_expire_cb` separate global cooldown, `queue_membership_update` throttle, comments updated).
- 2026-03-04: Bug 86 fix -- peer_connect_cb (inbound TCP accept path) was missing mxfs_disklock_monitor_node() call. Peers connecting inbound were never added to disklock's monitored[] array, so the heartbeat monitor loop skipped them. Symptom: disklock death detection only worked for peers discovered via UDP multicast, not peers that connected via TCP accept. Fix: added `if (mnt->disklock) mxfs_disklock_monitor_node(mnt->disklock, node_id)` in peer_connect_cb, matching discovery_peer_cb. Changes: mount.c (peer_connect_cb).
- 2026-03-01: Bug 70 fix -- membership stabilization worker busy-spins at 100% CPU during the 3-second stabilization window, causing soft lockup warnings (ktime_get_with_offset stuck for 500+ seconds under vCPU contention). Root cause: the `while(1)` loop's `mxfs_pal_cond_timedwait()` was guarded by `if (!mnt->membership_stab_pending)` — so when a pending event existed but `elapsed < MXFS_MEMBERSHIP_STABILIZE_MS`, the thread skipped the sleep and spun polling `mxfs_pal_time_ms()` continuously. Under ESXi vCPU starvation the membership_stab_ts could advance erratically, keeping the thread in the spin for the full 517s observed in test6's dmesg. Fix: replaced the guarded sleep with a computed `wait_ms` that is always passed to `mxfs_pal_cond_timedwait()`. When pending is non-zero, `wait_ms = remaining stabilization window time`; when pending is zero, `wait_ms = 200ms` (idle poll); when stop is set, skip sleep entirely. This eliminates the spin: the thread sleeps for exactly the remaining window time, then wakes and fires `update_active_nodes()`. Changes: mount.c (`membership_stab_worker_fn`).
- 2026-03-04: CAW DLM NULL pointer safety audit -- verified all `cache->dlm` and `cache->icache->dlm` references in inode_cache.c and dir_cache.c are safe when `dlm` is NULL (CAW mode). Both `mxfs_dlm_get_epoch()` and `mxfs_dlm_purge_stale_for_resource()` already have NULL guards that return 0, making epoch checks always pass (0 == 0, no stale eviction) and purge calls no-op. Fixed one real bug: the journal recovery thread spawn guard at mount.c line 778 checked `mnt->dlm` (TCP DLM only) instead of `mnt->dlm_lock_fn` (transport-agnostic). This prevented `recover_dead_node_journal()` from running in CAW mode despite the function itself correctly using transport-agnostic dispatch. Changes: mount.c (recovery thread guard).
- 2026-03-04: CAW DLM transport abstraction -- added transport-agnostic DLM dispatch layer to support both TCP-based and disk-based (Compare-and-Write) lock managers. Changes: (1) **mxfs.h**: added `enum mxfs_dlm_transport` (CAW=0 default, TCP=1) and `dlm_transport` field to `struct mxfs_mount_opts`. (2) **mount.h**: added `dlm_caw.h` include, function pointer typedefs (`mxfs_dlm_lock_fn`, `mxfs_dlm_unlock_fn`, `mxfs_dlm_convert_fn`), and new fields to `struct mxfs_mount` (`dlm_transport`, `dlm_caw`, `dlm_lock_fn`, `dlm_unlock_fn`, `dlm_convert_fn`, `dlm_dispatch_ctx`). (3) **mount.c**: added `dlm_bast_cb_caw()` BAST callback for CAW mode (casts first parameter back to mount struct since CAW DLM passes cb_data through the dlm_bast_cb typedef), six dispatch wrapper functions (`dlm_lock_tcp_wrapper`, `dlm_unlock_tcp_wrapper`, `dlm_convert_tcp_wrapper`, `dlm_lock_caw_wrapper`, `dlm_unlock_caw_wrapper`, `dlm_convert_caw_wrapper`), transport-branching in `mxfs_mount()` (CAW path: create/start CAW DLM, skip TCP peer/membership; TCP path: unchanged), CAW cleanup in `mxfs_unmount()` and error paths, `purge_node_dlm()` updated for CAW, `recover_dead_node_journal()` uses dispatch function pointers instead of direct mxfs_dlm_lock/unlock calls. (4) **Kbuild**: added `dlm_caw.o` to the build. (5) **dlm_caw.c**: renamed `current` variable to `cur_slot` throughout to avoid conflict with Linux kernel's `current` macro (`get_current()`).
- 2026-03-05: Bug 88 fix -- CAW transport discovery callback bailed out completely. `discovery_peer_cb()` had `if (!mnt->peer) return;` at the top, which returned immediately when CAW transport was active (CAW sets `mnt->peer = NULL` since it has no TCP peer connections). This meant discovered nodes were never registered with the lease system, never monitored by disklock, and the allocator never exited single-node mode. Symptoms: continuous "lease: renewal from unregistered node NNNN" messages in dmesg, mkdir hanging forever (CAW DLM lock acquisition could never coordinate with unregistered peers). Fix: restructured `discovery_peer_cb()` to move the early bail-out inside a conditional `if (mnt->peer)` block that wraps only the TCP-specific operations (peer_add, peer_connect). The common operations (volume/self check, alloc single-node exit, lease register, disklock monitor, queue_membership_update) now execute regardless of transport. For CAW dedup, uses `mxfs_lease_has_node()` instead of the TCP peer table's EEXIST return code. Changes: mount.c (`discovery_peer_cb`).
- 2026-03-07: Page cache support API -- added 7 new public API functions for kernel page cache integration. `mxfs_set_page_invalidate_cb()` registers a callback invoked from `complete_bast()` to flush/invalidate page cache before DLM lock release. `mxfs_inode_lock_shared()`/`mxfs_inode_lock_exclusive()` acquire PR/EX DLM locks on inodes and return file size (lock stays cached until BAST). `mxfs_inode_unlock()` releases the reference via new `mxfs_inode_cache_put_by_ino()` helper. `mxfs_get_block_map()` translates logical file blocks to physical disk blocks using the cached extent map (returns HOLE/UNWRITTEN flags). `mxfs_update_inode_size()` updates ci->size and marks dirty when a write extends the file. `mxfs_alloc_file_block()` allocates a single block via `mxfs_alloc_blocks()`, inserts into extent map, and marks inode dirty. These functions enable the Linux VFS frontend to use the kernel page cache for data I/O while libmxfs manages DLM coherency, replacing the custom block cache for data reads/writes. Changes: mount.c (7 new functions), inode_cache.h/inode_cache.c (`mxfs_inode_cache_put_by_ino`), mxfs.h (declarations already present).
- 2026-03-08: Adaptive speculative preallocation -- `mxfs_alloc_file_block()` now uses tiered preallocation: 16 blocks (64KB) for first 64KB, 256 blocks (1MB) for 64KB-1MB, 2048 blocks (8MB) beyond 1MB. Previously fixed at 256 blocks. On first call for a file offset, allocates a full 256-block extent and inserts into the extent map. Subsequent calls within the same extent return the already-mapped block without DLM or allocator overhead. Fixed sequential write regression caused by page cache integration (8.5 MiB/s → 258 MiB/s, 30x improvement). Random write also improved via page cache absorption (539 → 31,500 IOPS). The preallocation size (256 blocks = 1MB) matches the kernel readahead window and XFS default extent hint. Changes: mount.c (`mxfs_alloc_file_block`).
- 2026-03-08: Bug 98 fix -- multi-LUN SO_REUSEPORT. Added SO_REUSEPORT to UDP discovery/lease sockets (pal_linux_kern.c) and TCP listen sockets (pal_linux_kern.c, pal_linux_user.c). Added `volume_id` field to NODE_JOIN peer handshake (peer.c/h) to reject cross-LUN connections. `mount.c` passes `volume_id` to `peer_init()`. Enables multiple MXFS mounts on the same node binding the same ports. Tested: 3 LUNs on 5 nodes, test2 dual-mount simultaneous — PASS. Changes: pal_linux_kern.c, pal_linux_user.c, peer.c, peer.h, mxfs_dlm.h, mount.c.
- 2026-03-08: Bug 100 fix -- use-after-free in mxfs_disklock_purge_node during unmount. Root cause: unmount destroyed disklock (step 14) BEFORE shutting down peer networking (step 15). Peer recv threads still running could call peer_disconnect_cb → disklock_purge_node on freed memory. Crashed with `preempt_count 1` in `mutex_unlock`. Fix: (1) moved `mxfs_peer_shutdown()` BEFORE `mxfs_disklock_stop_heartbeat/destroy` in mxfs_unmount(), (2) added `!mnt->mounted` early-return guard in peer_disconnect_cb, disklock_expire_cb, and lease_expire_cb to prevent callback processing during teardown. Verified: 5-node mount/unmount, zero kernel errors, zero D-state. Changes: mount.c.
- 2026-03-08: TCP DLM scale warning -- added `check_tcp_scale_warning()` helper and `tcp_scale_warned` flag to `struct mxfs_mount`. When a new node registers via `peer_connect_cb` or `discovery_peer_cb` and the TCP DLM cluster exceeds 16 nodes, emits a one-shot WARN-level dmesg message recommending CAW DLM. Based on 32-node test results: TCP DLM correct but only 27% metadata completion at 32 nodes due to single lock-master-per-resource bottleneck. 16-node tested at 100% pass. Changes: mount.h (`tcp_scale_warned` field), mount.c (`check_tcp_scale_warning`, calls in `peer_connect_cb` and `discovery_peer_cb`), docs/architecture.md (DLM Transport Scalability section).
- 2026-03-10: Bug 107 fix -- TCP disconnect now calls remove_node() for TCP DLM transport. Previously, peer_disconnect_cb only called purge_node_dlm() (keeping the dead node in active_nodes and lease table), which was correct for CAW DLM (disk-based transport independent of TCP) but wrong for TCP DLM (TCP connection IS the transport). With TCP DLM, the dead node stays in active_nodes, DLM routes lock requests to the dead master, gets ENOTCONN, and the filesystem is unavailable until lease timeout (~5 min). Fix: conditional dispatch -- TCP DLM calls remove_node() (lease_unregister + purge_dlm + disklock_unmonitor) for immediate re-mastering; CAW DLM keeps current purge_node_dlm() behavior. Verified: 4-node hard crash test, surviving nodes resumed I/O within seconds, zero ENOTCONN errors. Changes: mount.c (peer_disconnect_cb, remove_node comment).
- 2026-03-10: Bug 115 -- mknod support for device nodes, FIFOs, and sockets. Added `mxfs_mknod()` public API function. For block/char devices: uses XFS_DINODE_FMT_DEV format with sysv-encoded rdev stored as big-endian uint32_t at start of data fork, forkoff=1 (matching XFS behavior). For FIFOs/sockets: uses XFS_DINODE_FMT_EXTENTS with 0 extents. Uses compound journal transactions. Added `rdev` field to `struct mxfs_stat` and `struct mxfs_cached_inode`. Changes: mount.c (mxfs_mknod, mxfs_stat rdev), mxfs.h (mxfs_mknod decl, mxfs_stat rdev field), inode_cache.h (rdev field), inode_cache.c (FMT_DEV load/flush, get_be32 helper), mxfs_inode.c (VFS mknod wrapper, dir_iops .mknod), mxfs_super.c (init_special_inode for special files), mxfs_common.h (version 0.9.2).
- 2026-03-10: Bug 116 fix -- long symlink support (FMT_EXTENTS). Previously, `mxfs_symlink()` only created FMT_LOCAL (inline) symlinks and `mxfs_readlink()` rejected FMT_EXTENTS symlinks with -EIO. XFS supports symlink targets up to 1024 bytes (XFS_SYMLINK_MAXLEN), but the inline data fork capacity is typically ~336 bytes for V5 inodes. Targets exceeding this must be stored in extent-based data blocks. Fix: (1) `mxfs_symlink()` now checks if `target_len <= dfork_size`. If it fits, uses FMT_LOCAL (unchanged). If not, allocates data blocks, builds an extent map, writes the symlink target into the blocks (with per-block `xfs_dsymlink_hdr` headers for V5 CRC filesystems, raw data for V4), and sets the inode to FMT_EXTENTS. Added `symlink_write_remote_blocks()` and `build_symlink_hdr_v5()` static helpers. (2) `mxfs_readlink()` now handles FMT_LOCAL (inline, unchanged), FMT_EXTENTS, and FMT_BTREE symlinks. Added `readlink_remote()` helper that walks the extent map, reads data blocks, validates V5 headers (magic check), and copies the target data. The inode size field determines the target length. (3) Added XFS symlink constants to `xfs_format.h`: `XFS_SYMLINK_MAGIC`, `XFS_SYMLINK_MAXLEN`, `XFS_DSYMLINK_HDR_SIZE`, `XFS_SYMLINK_CRC_OFF`, and helper functions `mxfs_xfs_symlink_buf_space()` and `mxfs_xfs_symlink_blocks()`. Also added `ENAMETOOLONG` validation for target_len > 1024 in `mxfs_symlink()`. Changes: mount.c (mxfs_symlink, mxfs_readlink, 4 new static helpers), xfs_format.h (symlink constants and helpers), mxfs_common.h (version 0.9.3).
- 2026-03-06: Layout refactor -- MXFS metadata regions moved to start of device. On-disk layout changed from `[XFS][journal][disklock][super]` to `[super][journal][disklock][XFS]`. MXFS super now at offset 0 (prevents `mount -t xfs` mounting the raw device). XFS data region grows toward end (enables future resize). Changes: (1) **mxfs_super.h**: added `xfs_data_offset` field. (2) **mxfs.h**: added `xfs_data_offset` to `struct mxfs_mount_opts`. (3) **mount.h**: added `mxfs_bdev_t *xfs_dev` to `struct mxfs_mount`. (4) **pal.h**: added `mxfs_pal_bdev_clone_with_offset()` and `mxfs_pal_bdev_close_clone()`. (5) **pal_linux_kern.c / pal_linux_user.c**: added `base_offset` and `is_clone` to `struct mxfs_bdev`, applied base_offset in all I/O paths, implemented clone functions. (6) **mount.c**: auto-detect reads offset 0 (not end), extracts `xfs_data_offset`, creates `xfs_dev` clone, passes `xfs_dev` to block_cache/inode_cache/dir_cache/alloc (XFS data subsystems), keeps `mnt->dev` for journal/disklock/DLM/SCSI PR. Direct bdev_read/write in file I/O paths changed to use `xfs_dev`. Unmount closes clone before device. (7) **journal.h/journal.c**: added `xfs_dev` to journal ctx for replay writes through offset device. (8) **mkfs_mxfs.c**: reversed layout calculation, `format_xfs_native()` takes `base_offset` parameter, UUID generated upfront, version bumped to 0.7.1.
- 2026-03-10: Rename flags support (RENAME_NOREPLACE, RENAME_EXCHANGE). Extended `mxfs_rename()` with a `flags` parameter. RENAME_NOREPLACE (MXFS_RENAME_NOREPLACE): checks if destination exists and returns -EEXIST. RENAME_EXCHANGE (MXFS_RENAME_EXCHANGE): atomically swaps two directory entries by removing both and re-adding with swapped inodes and ftypes; no nlink changes since both entries continue to exist. Added `mxfs_mode_to_ftype()` static helper (extracts MXFS_FT_DIR/SYMLINK/REG_FILE from inode mode). Classic rename (flags=0) behavior is unchanged. Added `MXFS_RENAME_NOREPLACE` and `MXFS_RENAME_EXCHANGE` constants to mxfs.h (matching Linux RENAME_* values). Changes: mount.c (mxfs_rename, mxfs_mode_to_ftype), mxfs.h (flags constants, updated declaration).
- 2026-03-11: Replaced hostname-based UUID fallback with random UUID generation. `load_node_uuid()` now calls `mxfs_generate_random_uuid()` (which uses `mxfs_pal_get_random_bytes()`) when `/etc/mxfs/node.uuid` is missing, instead of deriving a deterministic UUID from the hostname. Eliminates the risk of UUID collisions when multiple nodes have similar hostnames. The old `generate_uuid_from_hostname()` function is removed entirely. Changes: mount.c (mxfs_generate_random_uuid replaces generate_uuid_from_hostname, load_node_uuid fallback path updated).
- 2026-03-10: Bug 113 -- fallocate support. Added `mxfs_fallocate()` public API for preallocating and deallocating file space. Three modes: (1) **mode=0**: basic preallocation -- allocates blocks covering [offset, offset+len), updates file size if the range extends past EOF, tries to allocate large contiguous extents to minimize fragmentation (primary use case for QEMU VM disk images). (2) **MXFS_FALLOC_FL_KEEP_SIZE**: same preallocation but does not change file size (preallocation beyond EOF). (3) **MXFS_FALLOC_FL_PUNCH_HOLE|KEEP_SIZE**: deallocates blocks in range, zeroes partial blocks at boundaries, does not change file size. Implementation: `fallocate_prealloc()` walks the logical block range, skipping already-allocated blocks, and allocates hole runs via `mxfs_alloc_blocks()`. `fallocate_punch_hole()` handles partial-block zeroing at boundaries via block cache writes, then calls `mxfs_extent_map_punch()` to remove/trim/split extents, and frees the physical blocks via `mxfs_free_blocks()`. Both paths acquire EX DLM lock, update timestamps, mark inode dirty, and flush to disk. VFS wrapper `mxfs_kern_fallocate()` in mxfs_file.c maps Linux FALLOC_FL_* flags, flushes/invalidates page cache, calls `mxfs_fallocate()`, and refreshes VFS inode size. Added `mxfs_extent_map_punch()` and `struct mxfs_freed_extent` to extent.h/extent.c. Changes: mxfs.h (MXFS_FALLOC_FL_* flags, mxfs_fallocate decl), mount.c (mxfs_fallocate, fallocate_prealloc, fallocate_punch_hole), extent.h (mxfs_freed_extent, mxfs_extent_map_punch), extent.c (mxfs_extent_map_punch), mxfs_file.c (mxfs_kern_fallocate, .fallocate in file_operations).
- 2026-03-12: Bug 128 fix -- fallocate prealloc stale data / unwritten extent support. `fallocate_prealloc()` inserted extents with `unwritten=false`, meaning reads of preallocated blocks returned stale physical block data instead of zeros. QEMU triggers this via paired `fallocate(PUNCH_HOLE)` + `fallocate(mode=0)` for guest BLKDISCARD/WRITE_ZEROES. Fix: (1) `fallocate_prealloc()` now inserts extents with `unwritten=true`. (2) New `mxfs_convert_unwritten()` converts a single logical block from unwritten to written by splitting the extent into up to 3 parts (unwritten prefix, written block, unwritten suffix). (3) `mxfs_get_block()` handles `MXFS_PGCACHE_F_UNWRITTEN`: read (create=0) returns 0 like a hole (kernel fills zeros); write (create=1) calls convert_unwritten and sets BH_New. The XFS bmbt_rec on-disk format already supported the unwritten bit (bit 8 of l0) and encode/decode/lookup all handled it — only the fallocate insert and get_block consumption were missing. Changes: mount.c (fallocate_prealloc unwritten=true, mxfs_convert_unwritten), mxfs.h (mxfs_convert_unwritten decl), mxfs_file.c (UNWRITTEN handling in get_block).
- 2026-03-12: Bug 129 fix -- negative df / free_blocks counter drift. The allocator initialized `ctx->free_blocks` from the XFS superblock `sb->fdblocks`, but the superblock was never written back on sync/unmount. After remount, the stale fdblocks caused the live counter to diverge from the AGF ground truth. Freeing blocks allocated in a prior mount session incremented the counter past `dblocks`, causing `df` to show negative usage (-1064% on pve2). Fix (3 parts): (1) `mxfs_alloc_create()` now sums `agf_freeblks` across all AGs as the initial `free_blocks` value instead of trusting `sb->fdblocks`, logging a warning when they differ. (2) `mxfs_free_blocks()` caps `ctx->free_blocks` at `sb->dblocks` with a warning log, preventing statfs from ever reporting free > total. (3) New `flush_superblock_counters()` writes fdblocks/icount/ifree back to the XFS superblock (with V5 CRC update) during `mxfs_sync_fs()`, keeping the on-disk superblock consistent for subsequent mounts and external tools. Changes: mount.c (flush_superblock_counters, mxfs_sync_fs call), alloc.c (AGF sum init, free_blocks cap).
- 2026-03-19: **Async bio submission + narrowed inode EX lock for O_DIRECT writes.** Two optimizations targeting the 2.26x sequential write and 24.7x random write gap versus XFS: (1) **mxfs_write_direct**: changed block-aligned data writes from `mxfs_pal_bdev_write` (serial `submit_bio_wait`) to `mxfs_pal_bdev_write_async` (pipelined, up to 16 concurrent bios). Same change for `mxfs_read_direct` using `mxfs_pal_bdev_read_async`. Partial-block (read-modify-write) paths remain synchronous. (2) **mxfs_write_bulk**: added single-node lock narrowing. When `mxfs_has_peers()` returns false, the EX lock scope is split: Phase 1 (EX lock held) does extent map lookup + block allocation + file size update. Phase 2 (lock released, PR reference only) does the actual data write via pipelined async bios. The EX lock is re-acquired for the next chunk's metadata phase. In multi-node mode, the EX lock is held across the entire write (unchanged) to prevent another node from reading stale data. The `single_node` flag is snapshot once per `mxfs_write_bulk` call for consistency. Error handling includes `finish_no_ci` label for cases where EX re-acquire fails after data write. Changes: mount.c (mxfs_write_direct, mxfs_read_direct, mxfs_write_bulk). Version: 0.9.28.

### dlm — distributed lock manager core


- 2026-02-15: Initial port from kernel/mxfs_dlm.c. Replaced kernel APIs (rw_semaphore, kmem_cache, completion, spinlock, ktime) with PAL equivalents.
- 2026-02-16: Fixed BAST deadlock. BAST callbacks were being invoked while holding `table_rwlock`, causing deadlock when the callback tried to call `mxfs_dlm_unlock()` which re-acquires the same lock. Fix: added `bast_record` struct and `fire_bast_callbacks()` to defer BAST firing until after `table_rwlock` is released. Applied to both `mxfs_dlm_lock()` and `mxfs_dlm_process_remote_request()`.
- 2026-02-16: Fixed cross-node BAST delivery failure. Root cause: `mxfs_dlm_update_active_nodes()` purges the entire lock table on membership change, but the inode/dir caches still have entries with stale `lock_mode` values, so BAST never fires (DLM finds no conflicts). Fix: added `membership_cb` callback that fires after lock table purge, wired to `dlm_membership_cb` in mount.c which calls `dir_cache_drop_all` and `inode_cache_drop_all` to flush dirty data and discard all cached lock state, forcing next access to re-acquire DLM locks from the correct master.
- 2026-02-16: Added `shutting_down` flag. When set, remote lock requests fail immediately with -ESHUTDOWN instead of sending TCP messages to potentially disconnected peers. Set during `mxfs_unmount()` before sending NODE_LEAVE.
- 2026-02-16: Fixed DLM lock timeout on unmount. Root cause: unmount sent NODE_LEAVE before flushing dirty caches; dir_cache_flush_all requires DLM locks via inode_cache_get_exclusive, but peers had already disconnected causing 30-second timeout. Fix: restructured unmount to flush all dirty data (dir/inode/block caches) while DLM and peers are still active, then set shutting_down, send NODE_LEAVE, release all DLM locks, and destroy caches.
- 2026-02-19: Fixed BAST not reaching all nodes at 3+ nodes (epoch-based stale lock detection). Root cause: during membership transitions, nodes update their active_nodes lists at different times via UDP discovery. A node that processes the membership change later than its peers could hold a cached DLM lock registered at a stale master. The new master doesn't know about this lock and won't send BASTs to the holding node, causing it to serve stale directory data indefinitely. Fix: (1) `mxfs_dlm_update_active_nodes()` now advances the DLM epoch on every membership change; (2) `struct mxfs_cached_inode` records `lock_epoch` when a DLM lock is acquired; (3) `cache_get_locked()` compares the cached epoch against the current DLM epoch on every cache hit -- if they differ, the cached entry is evicted and the lock is re-acquired from the correct master. This also protects against inodes that survive `drop_all` due to non-zero refcount during membership change processing. Changes: dlm.c, inode_cache.h, inode_cache.c.
- 2026-02-19: Added `mxfs_dlm_purge_stale_for_resource()` to break file lock starvation at 3+ nodes. Root cause: epoch-based eviction in inode_cache.c handles the inode cache side, but the DLM lock table on the new master can still hold stale remote lock entries from nodes that were the previous master. These stale entries represent locks that the remote node already dropped during its own epoch eviction, but the current master never received a LOCK_RELEASE for them. New lock requests queue behind these ghost holders and time out because no BAST will ever succeed. The new function purges all remote lock entries for a specific resource and promotes any unblocked waiters. Called from inode_cache.c when mxfs_dlm_lock() times out. Changes: dlm.h, dlm.c, inode_cache.c.
- 2026-02-19: Fixed BAST not reaching all PR holders at 4+ nodes. Three issues: (1) `dlm_bast_cb()` in mount.c silently discarded `mxfs_peer_send()` return value for remote BASTs — transient TCP failures caused holders to never receive BASTs and serve stale data. Fix: 3-retry loop with 50ms delay and ERR logging on exhaustion. (2) `mxfs_dlm_lock()` local master path set up the pending entry AFTER firing BASTs — fast holders could release and signal the pending before it existed, losing the grant signal. Fix: moved `pending_alloc/insert` before `fire_bast_records`. (3) `mxfs_inode_cache_bast_cb()` returned without releasing the DLM lock when the inode was not in cache — stale holder entry at master blocked conflicting requests. Fix: attempt `mxfs_dlm_unlock()` even when inode not cached. Changes: mount.c, dlm.c, inode_cache.c.
- 2026-02-19: Fixed simultaneous unmount cross-node deadlock. When 2+ nodes unmount at the same time, `mxfs_unmount()` calls `dir_cache_flush_all()` which calls `mxfs_inode_cache_get()` which calls `mxfs_dlm_lock()`. Each node needs a lock mastered by the other (also shutting down) causing both to enter D-state. Root cause: `shutting_down` was set AFTER cache flushes and only covered the remote-master lock path. Fix: (1) moved `shutting_down` check to the top of `mxfs_dlm_lock()`, before the remote/local branch, so both paths return `-ESHUTDOWN` immediately during shutdown; (2) removed the now-redundant remote-only check. Changes: dlm.c.
- 2026-02-19: Fixed DLM lock hang after dead-node recovery. Root cause: when a node crashes and `mxfs_dlm_update_active_nodes()` purges the lock table, threads sleeping in `pending_wait()` were not woken. Two scenarios: (1) Remote-master path: thread sent LOCK_REQ to the now-dead node and was waiting for a LOCK_GRANT that would never arrive. The thread would block for `MXFS_LOCK_WAIT_TIMEOUT_MS` (120s) in D-state, blocking all filesystem operations behind it via VFS-level dentry locks (`d_alloc_parallel`, `do_unlinkat`). (2) Local-master path (incompatible queue): thread's WAITING lock entry was freed by the table purge, but the thread was still sleeping on its pending entry. Subsequent cleanup would access freed memory (use-after-free on `newlk`). Fix: (1) added `fail_all_pending()` which iterates all pending entries and completes them with `MXFS_DLM_RETRY`, called from `update_active_nodes` after purging the lock table. (2) Refactored `mxfs_dlm_lock()` into `dlm_lock_impl()` (core logic) + `mxfs_dlm_lock()` (retry wrapper). On `MXFS_DLM_RETRY`, the wrapper retries up to 3 times with the updated master assignment. The retry typically succeeds immediately because the surviving node is now master for all resources with an empty lock table. (3) In the local-master incompatible path, `MXFS_DLM_RETRY` from `pend->status` skips the `newlk` cleanup (the entry was already freed by the table purge), preventing use-after-free. Changes: dlm.c.
- 2026-02-27: **Added error checking to send_grant().** The `ctx->send_cb()` return value in `send_grant()` was previously ignored. Now checks the return value and retries once after a 10ms delay on failure. If the retry also fails, logs a warning with the target node, error code, and resource details. The requesting node's `pending_wait` timeout handles ultimate recovery. Also added null-check and warning to `fire_bast_records()` when `bast_cb` is NULL. Changes: dlm.c.
- 2026-02-25: Added DLM_TRACE debug logging for inode 128 (root dir) to diagnose dual-EX grant issue where both nodes hold EX simultaneously after BASTs stop firing. Conditional on `resource->ino == 128 && resource->type == MXFS_LTYPE_INODE` (dlm.c) and `ino == 128` (inode_cache.c) to avoid noise. Traces: dlm_lock entry, local master grant/already-granted/add-to-waiters paths, process_remote_request entry with all existing holders dumped, conflict check result, BAST fire decisions and targets, fire_bast_records per-BAST fire, dlm_unlock entry removal and promote_waiters result, promote_waiters per-promotion grants, process_remote_release entry/found/ENOENT, inode_cache cache_get_locked EX-skip hit, inode_cache_put bast_pending vs EX-left-cached, bast_cb entry/deferred/inline. All prefixed "DLM_TRACE:" for grep. Added local `mode_name()` helper to inode_cache.c. No logic changes. Changes: dlm.c, inode_cache.c.
- 2026-02-28: **Bug 67** — Fixed DLM lock deadlock after membership epoch change. Root cause: when a membership change occurs, `fail_all_pending()` wakes all pending lock requests with `MXFS_DLM_RETRY`. The retry loop in `mxfs_dlm_lock()` calls `dlm_lock_impl()` again, which recalculates the master (may be different). But if the old master's grant arrives AFTER the retry sends a new request to the new master, the old grant completes the new pending entry (stale grant from wrong epoch). The new request to the new master then never gets a matching pending entry, causing a hang. Additionally, the retry loop only did 3 retries, which exhausted under repeated rapid membership changes, returning -EAGAIN and causing permanent lock starvation. Fix: (1) Added `request_epoch` field to `struct mxfs_dlm_pending` to record the DLM epoch when a remote lock request is sent. (2) In `dlm_lock_impl()` remote-master path, `pend->request_epoch` is set to `ctx->current_epoch` after `pending_alloc()`. (3) `pending_signal_resource()` now accepts an `epoch` parameter. When non-zero, it only matches pending entries whose `request_epoch` matches the grant epoch; stale grants from a previous epoch are logged at DEBUG level and silently discarded. Internal callers (promote_waiters, purge_node, etc.) pass 0 to match any pending entry. (4) `mxfs_dlm_process_remote_grant()` now accepts and passes `grant_epoch` from the wire message header to `pending_signal_resource()`. (5) `peer_msg_cb()` in mount.c extracts `resp->hdr.epoch` and passes it to the updated grant handler. (6) `fail_all_pending()` is unchanged -- it still wakes ALL pending entries regardless of epoch. (7) Increased retry count from 3 to 10 to handle multiple rapid membership changes. Changes: dlm.h, dlm.c, mount.c.
- 2026-02-23: **Bug 51** — Fixed dual-EX grant race causing data corruption on 2-node concurrent writes. Root cause: `mxfs_dlm_process_remote_request()` had an "already granted" shortcut that returned LOCK_GRANT immediately when the sender already had a GRANTED entry at sufficient mode, without checking for conflicts with other holders or pending waiters. This was exploitable via a send-ordering race: when a node's BAST handler (recv thread) and its next lock request (main thread) race for `peer->send_lock`, the LOCK_REQ can arrive at the master before the preceding LOCK_RELEASE. The master finds the sender's OLD GRANTED(EX) entry and takes the shortcut, sending LOCK_GRANT without BAST. The subsequent LOCK_RELEASE removes the old entry, leaving the master with no record of the sender's grant while the sender believes it holds EX. Both nodes now hold EX simultaneously, each allocating data blocks from different AGs; the last to flush the inode wins, orphaning the other node's data. BASTs stop firing entirely because the master has no conflicting entries. Fix: three changes: (1) In `mxfs_dlm_process_remote_request()`, the "already granted" shortcut now verifies that no other node has a conflicting GRANTED lock AND no other node has a WAITING/BLOCKED request before re-affirming the grant. If conflicts or waiters exist, the old entry is removed, any unblocked waiters are promoted via `promote_waiters()`, and the new request falls through to the normal queue-and-BAST path. (2) In `mxfs_dlm_process_remote_release()`, the fallback that removed WAITING/BLOCKED entries when no GRANTED entry was found has been removed. This prevents the stale LOCK_RELEASE (arriving after the re-request handling already removed the old GRANTED entry) from destroying the sender's new WAITING entry. (3) Defense-in-depth: the local-master "already granted" shortcut in `dlm_lock_impl()` now performs the same safety check. Changes: dlm.c.
- 2026-03-10: **Bug 106** — Fixed DLM grant epoch mismatch causing lock timeouts at 3+ nodes with incremental joins. Root cause: `send_grant()` stamped the grant message with `ctx->current_epoch` (the master's local epoch). But the stale-grant filter in `pending_signal_resource()` (Bug 67) discards grants where `grant_epoch > request_epoch`. Since each node counts membership changes independently, the master's epoch can be higher than the requester's epoch (e.g., master saw 3 transitions while requester saw 2). Valid grants are silently discarded, causing 30-second DLM lock timeouts for the affected nodes. Any operation on the filesystem hangs. Fix: (1) Added `mxfs_epoch_t request_epoch` field to `struct mxfs_lock` to store the requester's epoch when a WAITING entry is created. (2) Changed `send_grant()` to accept an explicit `epoch` parameter instead of always using `ctx->current_epoch`. (3) Direct grants in `process_remote_request()` pass the request's epoch. (4) Waiter promotions (from unlock, purge_stale, BAST response) pass `wk->request_epoch`. (5) Added `request_epoch` parameter to `mxfs_dlm_process_remote_request()` signature; mount.c passes `req->hdr.epoch`. The requester now always receives a grant stamped with its own epoch, so the Bug 67 filter never rejects valid grants. Changes: dlm.h, dlm.c, mount.c.
- 2026-03-11: Added `mxfs_dlm_is_single_node()` — queries `active_nodes.count` under mutex. Used by inode_cache.c and dir_cache.c to skip `invalidate_range` and `bdev_flush` on single-node mounts where the block cache is always authoritative. No other node can modify blocks, so cache invalidation is unnecessary. When a second node joins, count increments and invalidation resumes automatically.
- 2026-03-04: **Transport-agnostic dispatch typedefs.** Moved `mxfs_dlm_lock_fn`, `mxfs_dlm_unlock_fn`, and `mxfs_dlm_convert_fn` typedefs from mount.h to dlm.h so they are available to consumers (inode_cache.h, alloc.h) without circular include dependencies. These typedefs define the transport-agnostic function pointer signatures for DLM lock/unlock/convert operations. Changes: dlm.h (added typedefs), mount.h (removed duplicate typedefs).

### dlm_caw — CAW (disk) transport


- 2026-03-24: Fix self-BAST on PR→EX upgrade in mxfs_dlm_caw_lock. The
  is_compatible check at the "compatible — add ourselves" path didn't exclude
  the requesting node's own holder bit. For a PR→EX upgrade, our own PR was
  seen as conflicting with the EX request, bypassing the in-place upgrade and
  falling through to the waiter/BAST path — which BAST'd ourselves. Fix: use
  compatible_excluding_self when our_mode != NL. The code after the compat
  check already handled upgrades correctly (lines 687-693 clear old mode).
- 2026-03-04: Initial implementation — complete module with all 10 API
  functions, BAST poll/multicast, node purge, lock convert, release_all.
  Compiles clean with gcc -Wall -Wextra -Werror.
- 2026-03-04: Heap-allocate lock slot buffers in caw_wait_for_grant,
  mxfs_dlm_caw_lock, mxfs_dlm_caw_unlock, mxfs_dlm_caw_convert,
  mxfs_dlm_caw_release_all, and mxfs_dlm_caw_purge_node to fix kernel
  frame-size warnings (struct mxfs_caw_lock_slot is 512 bytes; two on
  the stack exceeded the 1024-byte limit). Uses goto cleanup pattern
  for consistent free on all return paths.
- 2026-03-05: Yield-on-contention fairness. Added yield_to/yield_set_ms
  fields to lock slot (16 bytes from reserved, now 392 bytes). On unlock
  with waiters, sets yield_to = waiters bitmap so waiting nodes get
  priority over the releasing node. Non-priority nodes back off 10-20ms
  (jittered). 5-second stale yield_to timeout prevents deadlock on node
  death. Adaptive BAST poll: 10ms under contention, 100ms otherwise.
  purge_node and release_all clear yield_to bits. Fixes 8-node starvation
  where some nodes got 0/500 files due to unfair CAW races.
- 2026-03-05: Tuned CAW polling parameters for faster lock handoff under
  contention. POLL_INITIAL_MS: 5->1, POLL_MAX_MS: 100->25, BAST_POLL_MS:
  100->50, BAST_POLL_FAST_MS: 10->5, YIELD_BACKOFF_MS: 10->3. 7-node
  subdirectory test: 3/7 nodes achieved 500/500 (1500/3500 total), 0
  duplicates, 0 panics. 4 nodes had mkdir race bug (directories created as
  regular files under parallel CAW contention). Working nodes achieved ~250
  files/min vs ~5 files/min in flat-dir test (50x improvement). test9 hit
  CAW lock wait timeouts (120s) on inode operations after completion.
- 2026-03-05: Bug 93 fix — CAS MISCOMPARE on empty slot creation. When
  creating a new lock slot (ENOENT path), the compare buffer was zeroed
  (`memset(cur_slot, 0, ...)`), but the empty disk sector could contain
  non-zero data (stale/uninitialized). Changed to `read_slot()` the
  actual disk content for the CAS compare buffer. This was the root cause
  of 100% CAS failure rate that prevented mounting after ungraceful
  shutdown — `find_slot` returned ENOENT because the probe chain was
  intact but the hash didn't match existing slots, and every attempt to
  claim the empty slot failed because the zero-compare didn't match disk.
- 2026-03-06: Bug 95 fix — BAST poll thread unmount hang. The poll thread
  used `mxfs_pal_sleep_ms()` (kernel `msleep()`, uninterruptible) which
  blocked up to 200ms after `ctx->running` was set to false. Replaced with
  condvar timed-wait (`stop_cond`/`stop_lock`). `mxfs_dlm_caw_stop()` now
  signals the condvar after setting `running = false`, waking the poll
  thread instantly. Added `stop_cond` and `stop_lock` fields to
  `mxfs_dlm_caw_ctx`, created in `_create()`, destroyed in `_destroy()`.
- 2026-03-08: Bug 101 fix — node_bit collision causing data corruption.
  `node_bit = 1ULL << local_node` where local_node is a random 32-bit
  node_id (hash of UUID). Shift >= 64 is UB; on x86 masked to node_id%64,
  causing birthday-problem collisions (test1 and test2 both had
  node_id%64=32). Two nodes sharing the same holder bit means the DLM
  grants simultaneous EX locks → uncoordinated writes → zeroed directory
  inodes. Fix: `mxfs_dlm_caw_create()` now takes a `uint8_t node_slot`
  (0-63) from disklock's unique heartbeat slot claiming. `node_bit =
  1ULL << node_slot` is always safe. `purge_node()` also takes `uint8_t
  dead_slot` instead of `mxfs_node_id_t`. Changes: dlm_caw.c/h,
  disklock.c/h (claim_slot, find_node_slot), mount.c (early disklock
  init for CAW, slot lookup in purge). Verified: 4-node 400/400 metadata,
  0 duplicates, 4x64MB data I/O MD5-verified cross-node.
- 2026-03-09: I/O resilience and priority — two improvements for SAN
  latency spikes and high-node-count deployments:
  (1) Transient I/O retry with exponential backoff. `read_slot()` and
  `caw_slot()` now retry up to 5 times on I/O errors (not MISCOMPARE)
  with 10ms initial backoff doubling to 200ms max. Prevents transient
  iSCSI/SAN transport timeouts from failing DLM operations. Logs each
  retry attempt at WARN level for diagnostics.
  (2) Priority I/O for DLM lock operations. New `mxfs_pal_bdev_read_prio()`
  PAL function uses `REQ_PRIO | REQ_SYNC` in kernel to give lock slot
  reads priority over data I/O in the block scheduler. CAW writes already
  bypass the block layer via `scsi_execute_cmd`. This creates effective
  queue separation — lock I/O gets a priority lane so heavy data writes
  from multiple nodes don't starve lock acquisition. New constants:
  `MXFS_CAW_IO_MAX_RETRIES` (5), `MXFS_CAW_IO_BACKOFF_MS` (10),
  `MXFS_CAW_IO_BACKOFF_MAX_MS` (200). Changes: dlm_caw.c/h, pal.h,
  pal_linux_kern.c, pal_linux_user.c.
- 2026-03-09: Bug 102 fix — mount-time stale lock purge. Added
  `mxfs_dlm_caw_purge_dead_nodes(ctx, dead_mask)` which takes a 64-bit
  bitmap of dead node slots and purges all their holder/waiter bits in a
  single pass through 65536 lock slots. Called from mount.c after
  `disklock_claim_slot()` and `dlm_caw_create()` but before `dlm_caw_start()`.
  The dead_mask always includes our own slot (stale bits from a previous
  crashed mount) plus all heartbeat slots that are not ACTIVE. This
  eliminates the 120s DLM lock wait timeout on first access to inodes with
  stale holder bits after ungraceful shutdown. Previously required `mkfs -f`
  to clear. Changes: dlm_caw.c/h, mount.c, mxfs_common.h (version 0.8.0).
- 2026-03-19: Single-node bypass (v0.9.28). When no peers exist, CAW DLM
  lock/unlock/convert skip disk I/O entirely and operate in-memory. BAST poll
  thread skips disk scanning. On peer discovery (single->multi transition),
  `mxfs_dlm_caw_flush_held_to_disk()` writes all in-memory held locks to disk
  via normal find_slot + CAW path before clearing the bypass flag. New fields:
  `single_node` (bool), `mem_locks[]` (resource+mode tracking array),
  `mem_lock_count`, `mem_lock_mutex`. New APIs: `mxfs_dlm_caw_set_single_node()`,
  `mxfs_dlm_caw_flush_held_to_disk()`. mount.c sets single_node=true at CAW
  start and calls set_single_node(false) in discovery_peer_cb. Changes:
  dlm_caw.c/h, mount.c.

### peer — TCP transport

- 2026-02-15: Ported from kernel to portable C using PAL
- 2026-02-16: Fixed recv thread shutdown crash (NULL deref in tcp_recvmsg). Root cause: mxfs_peer_shutdown closed+freed the socket while recv threads were still blocked on it. Fix: two-phase shutdown — Phase 1 calls mxfs_pal_tcp_shutdown(SHUT_RDWR) on all peer sockets to unblock recv threads, Phase 2 joins recv threads then closes+frees sockets. Added mxfs_pal_tcp_shutdown to PAL (kernel: kernel_sock_shutdown, userspace: shutdown(SHUT_RDWR)).
- 2026-02-19: Fixed listener socket leak on unmount. Port 7600 stayed LISTEN after umount, blocking rmmod. Root cause: mxfs_peer_shutdown called mxfs_pal_tcp_shutdown on the listen socket to unblock the accept thread, but kernel_sock_shutdown(SHUT_RDWR) on a LISTEN-state TCP socket does NOT wake kernel_accept — it only sets shutdown flags. The accept thread stayed blocked forever, thread_join hung, and mxfs_pal_tcp_close for the listen socket was never reached. Fix applied in PAL layer (pal_linux_kern.c): mxfs_pal_tcp_shutdown now sets sk_err=EINTR and calls sk_error_report after kernel_sock_shutdown, which force-wakes all waiters on the socket including the accept queue.
- 2026-02-19: Fixed peer socket leak at 3+ nodes. Port 7600 stayed LISTEN after umount with 3+ nodes, blocking rmmod. Root cause: the accept thread blocks in tcp_recv reading a NODE_JOIN handshake from a newly accepted connection; this `newsock` was a local variable invisible to the shutdown path. With 3+ nodes, inbound connections arrive frequently during unmount, making the race highly likely. Fix: added `pending_sock` field to `mxfs_peer_ctx`; accept thread publishes newsock before blocking recv and clears it after; shutdown path shuts down pending_sock to unblock the accept thread. Also added running checks after accept returns and after recv fails to exit promptly during shutdown.
- 2026-02-19: Fixed asymmetric multicast peer connection failure (Bug AA). When UDP multicast between ESXi hosts was asymmetric (test2's packets never reached test3), the lower-ID-initiates rule prevented any connection. Fix: refactored `mxfs_peer_connect()` into `peer_connect_impl()` with `skip_id_check` parameter; added `mxfs_peer_connect_force()` that bypasses the ID check; auto-reconnect on send failure now also uses force mode; `discovery_peer_cb` in mount.c now calls `mxfs_peer_connect_force()` when a higher-ID node discovers an unconnected lower-ID peer.
- 2026-02-19: Added connect callback (Bug AB fix). Accept handler now fires `connect_cb` after accepting an inbound connection, so the mount layer can register the peer with the lease manager and DLM active node list. Without this, fallback-connected peers were invisible to the DLM and cluster membership stayed at N-1 nodes.
- 2026-02-19: Added aggressive TCP keepalive to PAL `mxfs_pal_tcp_set_opts()`. Previously keepalive was enabled but used Linux defaults (idle=7200s, interval=75s, count=9), taking ~2+ hours to detect a dead peer after a crash. Now sets idle=10s, interval=5s, count=3 for ~25 second dead node detection. Applied in both kernel PAL (tcp_sock_set_keepidle/keepintvl/keepcnt, available since 5.7) and userspace PAL (setsockopt TCP_KEEPIDLE/KEEPINTVL/KEEPCNT). Affects both outbound (connect) and inbound (accept) sockets since both call `mxfs_pal_tcp_set_opts()`.
- 2026-02-19: Fixed TCP keepalive not detecting hard-powered-off peers. When a node is abruptly powered off (via govc or similar), there's no RST or FIN -- the node silently vanishes. TCP keepalive probes alone were insufficient because the kernel's retransmit timer could keep the connection alive indefinitely even after all keepalive probes failed. Fix: added `TCP_USER_TIMEOUT` (25000ms) to `mxfs_pal_tcp_set_opts()` which tells the kernel to abort the connection after 25 seconds of unacknowledged data. The kernel's `tcp_keepalive_timer` checks `icsk_user_timeout` and immediately aborts when elapsed time exceeds the threshold. This ensures the recv thread's `kernel_recvmsg()` call returns `-ETIMEDOUT`, triggering `peer_handle_disconnect()` and the disconnect callback chain. Applied to both kernel PAL (`inet_csk(sk)->icsk_user_timeout` via lock_sock) and userspace PAL (`setsockopt(TCP_USER_TIMEOUT)`).
- 2026-02-19: Increased TCP_USER_TIMEOUT from 25000ms (25s) to 120000ms (120s) to fix DLM transport flapping at 4+ nodes. The 25s timeout was too aggressive under concurrent multi-node metadata workloads -- transient TCP retransmit delays caused by heavy DLM traffic would trip the timeout, resulting in spurious peer disconnects and "endpoint not connected" errors. The 120s value provides a generous margin over the keepalive budget while still detecting genuinely dead peers within 2 minutes. Applied to both kernel PAL (inet_csk(sk)->icsk_user_timeout and kernel_setsockopt fallback) and userspace PAL (setsockopt TCP_USER_TIMEOUT).
- 2026-02-27: **Elevated peer recv and accept threads to RT priority.** Under 4-node concurrent metadata stress, peer recv threads (normal CFS priority) were being starved by block I/O completions, preventing DLM grant messages from being read from TCP sockets. This caused metadata threads to block for 120s and nodes to go SUSPECT. Fix: changed `start_recv_thread()` and `mxfs_peer_start()` to use `mxfs_pal_thread_create_rt()` instead of `mxfs_pal_thread_create()`, giving all peer recv threads and the accept thread SCHED_FIFO at lowest RT priority (matching lease renew/monitor threads). This ensures DLM messages are always serviced promptly regardless of CFS scheduler load.
- 2026-02-27: **Added send retry with exponential backoff in mxfs_peer_send().** On TCP send failure, retries up to 3 times with 10ms/50ms/200ms delays before disconnecting and triggering reconnect. This handles transient TCP congestion at 4+ nodes where send failures resolve quickly after a brief backoff. The send_lock is released during sleep to avoid blocking other senders. The socket state is re-validated after each sleep in case BAST or disconnect handler changed the peer state. Changes: peer.c.
- 2026-02-28: **Fixed inbound peer IP not saved for outbound fallback reconnection (Bug 65).** When a peer connected inbound (via the accept thread), the remote IP address was not extracted from the accepted socket and stored in the peer entry's `host` field. This meant `peer->host` remained empty (zeroed). If the connection later dropped and outbound fallback reconnection was attempted via `mxfs_peer_connect_force()`, it called `mxfs_pal_tcp_connect("", 7600)` which failed immediately. Fix: added `mxfs_pal_tcp_getpeername()` to the PAL layer (kernel: `kernel_getpeername()` + `%pI4` formatting, userspace: `getpeername()` + `inet_ntop()`). The accept thread now calls this on the accepted socket and stores the result in `peer->host` before starting the recv thread. The inbound connection log message now includes the peer IP. Changes: pal.h, pal_linux_kern.c, pal_linux_user.c, peer.c.
- 2026-03-02: **Bug 81: EAGAIN handling in recv thread.** Added `-EAGAIN` check after the header `mxfs_pal_tcp_recv()` call in `mxfs_peer_recv_fn()`. With the new 30s `sk_rcvtimeo` set in PAL `mxfs_pal_tcp_set_opts()`, `kernel_recvmsg()` returns `-EAGAIN` on receive timeout instead of blocking indefinitely. The recv thread now continues the loop (re-checks `ctx->running` and peer state) instead of treating the timeout as a fatal error and disconnecting. This prevents spurious peer disconnects when a peer is temporarily slow under congestion. The payload recv is NOT given EAGAIN handling because a timeout mid-payload means the TCP stream may be partially consumed and out of sync — disconnect is correct in that case.
- 2026-02-20: **Fixed use-after-free crash in recv thread (Bug 43).** NULL pointer dereference in `remove_wait_queue` called from `sk_wait_data` -> `tcp_recvmsg_locked` -> `mxfs_pal_tcp_recv` -> `mxfs_peer_recv_fn`. Root cause: three code paths called `mxfs_pal_tcp_close()` on a peer socket while the recv thread was still blocking in `mxfs_pal_tcp_recv()` inside `sk_wait_data()`. Since `tcp_close` frees the socket structure, the recv thread's wait queue entry referenced freed memory. Fix: all three locations now call `mxfs_pal_tcp_shutdown()` first (sends SHUT_RDWR, unblocks the recv thread from `sk_wait_data`), join the recv thread to ensure it has exited, then call `mxfs_pal_tcp_close()` to safely free the socket. The three locations fixed: (1) accept thread connection replacement — old socket shutdown before close, recv thread joined between shutdown and close; (2) `peer_connect_impl` stale socket cleanup — same shutdown-join-close pattern; (3) `mxfs_peer_send` failure path — uses shutdown-only (not close), leaves `peer->sock` non-NULL so `peer_connect_impl` (called via `peer_connect_force` reconnect) can find and properly clean it up with the full shutdown-join-close sequence.
- 2026-03-03: **Bug 83: Eliminated inline send retries in mxfs_peer_send().** The previous implementation retried 5 times with 200-1000ms delays (holding send_lock during the total ~35s retry window), then called peer_connect_force inline (blocking for thread join + TCP handshake). At 8+ nodes, this stalled all DLM traffic to the peer for 30+ seconds, causing cascading timeouts on other peers. Fix: on first send failure, immediately shutdown socket, set DISCONNECTED, unlock send_lock, fire disconnect_cb, return -ENOTCONN. No retries, no inline reconnect. Reconnection happens via discovery announcements (every ~2s) which already call peer_connect_force. Changes: peer.c (mxfs_peer_send). Also reduced PAL-level EAGAIN retry from 6 to 3 and sk_sndtimeo from 5s to 2s in pal_linux_kern.c, reducing worst-case PAL send time from 30s to 6s.
- 2026-03-03: **Restored short peer-level send retries in mxfs_peer_send().** Bug 83 removed ALL peer-level retries (immediate disconnect on first PAL send failure), which was too aggressive — a single TCP hiccup killed the connection. Added back a short retry loop: 3 retries with delays of 200ms, 500ms, 1000ms (1.7s total), compared to the old 5 retries with 3.2s total. Critically, the send_lock is dropped during sleep to avoid stalling DLM traffic to this peer. After each sleep, re-validates peer state (ACTIVE + sock non-NULL) before retrying. On success, returns immediately. If all 3 retries fail, falls through to the existing disconnect logic (shutdown, set DISCONNECTED, fire disconnect_cb, return -ENOTCONN). Changes: peer.c (mxfs_peer_send).
- 2026-03-08: **Multi-LUN SO_REUSEPORT support (Bug 98).** Added SO_REUSEPORT to the TCP listen socket in both kernel and userspace PAL, allowing multiple MXFS mounts on the same node to share TCP port 7600. Added `volume_id` field to `mxfs_peer_ctx` and `mxfs_dlm_node_msg` (NODE_JOIN handshake). The accept loop validates inbound volume_id against its own — connections for a different volume are rejected immediately (closed), forcing the sender to retry via SO_REUSEPORT routing. Outbound connect validates the reply volume_id similarly. The `mxfs_peer_init()` signature now takes a `volume_id` parameter, passed from `mnt->volume_id` in mount.c. Tested: 3 LUNs across 5 nodes with test2 holding 2 simultaneous mounts (vdb + vdc), cross-node data integrity verified, concurrent 64MB writes on all 3 LUNs. Changes: mxfs_dlm.h (node_msg struct), peer.h/c (volume_id in ctx, handshake, validation), pal_linux_kern.c (TCP SO_REUSEPORT), pal_linux_user.c (TCP SO_REUSEPORT), mount.c (pass volume_id).
- 2026-03-02: **Fixed duplicate connection race causing use-after-free (Bug 80).** Kernel oops (NULL pointer dereference) in `remove_wait_queue` -> `_raw_spin_lock_irqsave` from `sk_wait_data` in a recv thread, where RDI=0 (the spinlock address was NULL). Root cause: race between `peer_connect_impl` (outbound reconnect via send failure auto-reconnect) and the accept thread (inbound reconnect). After `peer_connect_impl` joined the old recv thread, it dropped `send_lock` to close the old socket. During that window, the accept thread could accept a new inbound connection, install a new socket, and start a new recv thread. Then `peer_connect_impl` would overwrite `peer->sock` with its outbound socket (leaking the accept thread's socket) and overwrite `peer->recv_thread` (orphaning the accept thread's recv thread). The orphaned recv thread was still blocked in `kernel_recvmsg` on the leaked socket. When the leaked socket was eventually freed, `remove_wait_queue` hit a NULL wait queue head from `sock_orphan`. Fix: (1) After joining the old recv thread in `peer_connect_impl`, re-check `peer->state` and `peer->sock` under `send_lock` -- if the accept thread already reconnected (ACTIVE state with valid sock), skip the outbound connect. (2) Before installing the new outbound socket, check again under `send_lock` for accept-thread reconnection and discard the outbound socket if so. (3) Changed `peer_handle_disconnect` to use `mxfs_pal_tcp_shutdown` instead of `mxfs_pal_tcp_close` -- the socket pointer is kept non-NULL so the next connection setup properly joins the recv thread before freeing the socket. Changes: peer.c (peer_handle_disconnect, peer_connect_impl).

### journal — per-node journal slicing

- 2026-02-15: Ported from kernel to portable C using PAL (slot coordination only)
- 2026-02-19: Added journal write engine, circular buffer, transaction API, two-pass replay, checkpoint, unmount marker. All on-disk structures with CRC32C. Clean build on kernel 6.8.
- 2026-02-19: Added `bool slot_dirty` to `struct mxfs_journal_ctx`, set by `mxfs_journal_slot_open()` from the on-disk slot header flags. Enables mount code to detect if the previous shutdown was unclean and trigger replay.
- 2026-02-19: Wired into mount/unmount and inode flush (Phase 1 Steps 4-6). Mount: open/format/slot_open/replay/mark_dirty. Unmount: write_unmount/slot_mark_clean. Inode cache: txn_begin/log_write/commit before bdev_write in flush_inode_to_disk. Added `journal_offset` mount option (frontend + libmxfs).
- 2026-02-19: Phase 2 -- Multi-node recovery + full write coverage. Added `mxfs_journal_find_slot_by_node()` to look up a slot by node ID. Added compound transaction support via `compound_txn` field: when set, `txn_begin()` returns the compound txn, `txn_commit()`/`txn_abort()` are no-ops for sub-operations. Used by `mxfs_create()` for atomic create. Wired journal into alloc and dir_cache. Alloc: inode chunk writes journaled, block frees emit REVOKE. Dir cache: block and leaf dir writes journaled. Mount: `lease_expire_cb()` does full multi-node recovery (find slot, DLM EX lock on JOURNAL resource, begin/replay/finish).
- 2026-02-19: Fix ENOSPC when journal is full. Added `checkpoint_locked()` internal helper (advances tail to head without writing a CHECKPOINT entry, since journal may be out of space). Modified `write_entry()` to auto-checkpoint and retry when space is insufficient. Added proactive checkpoint at 75% capacity (free < 25% of data sectors). ENOSPC only returned when a single transaction exceeds the entire journal capacity.
- 2026-02-19: Fix dead-node journal recovery slot lookup failure. The in-memory `slots[]` table is per-node and has no knowledge of remote nodes' slot assignments. When a remote node crashed, `mark_needs_recovery()` and `find_slot_by_node()` returned -ENOENT because the dead node's slot was never in the surviving node's in-memory table. Fix: added `scan_disk_for_node_slot()` helper that reads on-disk slot headers to find DIRTY slots owned by a given node. Both `mark_needs_recovery()` and `find_slot_by_node()` now fall back to on-disk scan when the in-memory lookup fails, populating the in-memory slot entry from disk so the full recovery flow (begin_recovery, replay, finish_recovery) works correctly.
- 2026-02-19: Batched journal commits for metadata performance. `txn_commit()` no longer issues a `bdev_flush()` or updates the slot header per transaction. Instead, it writes journal entries + COMMIT entry and increments `unflushed_commits`. The device flush is batched and performed by the new `mxfs_journal_flush()` function, called from `mxfs_sync_fs()`, `mxfs_fsync()`, `mxfs_journal_checkpoint()`, and `mxfs_journal_write_unmount()`. All existing flush paths (checkpoint, checkpoint_locked, write_unmount) reset `unflushed_commits`. This eliminates per-txn flush overhead (~50ms on iSCSI), reducing 1000-file create from ~53s to near-native speed. No on-disk format changes. Crash semantics: last batch of unflushed commits may be lost (same as ext4's 5s commit interval).
- 2026-03-06: Added `xfs_dev` field to `struct mxfs_journal_ctx`. Journal replay now writes XFS metadata through `ctx->xfs_dev` (which has base_offset applied) instead of `ctx->dev`. This supports the new front-of-device layout where XFS data starts at a non-zero offset. Journal sector I/O (slot headers, entries) continues using `ctx->dev` with absolute offsets. Falls back to `ctx->dev` if `xfs_dev` is NULL (legacy layout).
- 2026-03-11: **Bug 122 fix -- removed compound_txn (v0.9.11).** Root cause: `compound_txn` was a global field on `struct mxfs_journal_ctx` shared by all threads. When concurrent create/mknod operations ran simultaneously, Thread A could pick up Thread B's compound_txn via `txn_begin()`, then Thread B would commit+free that txn while Thread A still held a pointer to it — use-after-free. Crash signature: `mxfs_journal_txn_log_write` dereferencing garbage `txn->tail` pointer (e.g., `0x75a73a8f13250e04`). Triggered by rsync (many concurrent file creates). Fix: removed compound_txn entirely from journal.h/journal.c and mount.c. Each sub-operation (inode flush, dir write, alloc) now creates its own independent transaction. Atomicity of create (alloc + init + dir_entry) is not needed — partial creates produce orphan inodes that are harmless and cleaned up by chk_mxfs. Files changed: journal.h, journal.c, mount.c.

### disklock — heartbeat & node slots

- 2026-02-15: Ported from kernel to portable C using PAL
- 2026-02-19: Fixed unmount hang — replaced uninterruptible sleep with condvar timed wait in heartbeat thread; stop() broadcasts condvar before joining
- 2026-03-04: Fixed frame size warning in disklock_hb_fn() — moved both 512-byte heartbeat buffers (hb for write path, rhb for monitor path) from stack to heap via mxfs_pal_alloc(). Combined 1024+ bytes on stack exceeded kernel frame limit.
- 2026-03-04: Added per-node monitoring thread integrated into heartbeat thread, epoch change detection, expire callback, SCSI PR preempt on death, disklock_offset mount option
- 2026-03-04: Bug 86 fix -- peer_connect_cb (inbound TCP accept path) was missing mxfs_disklock_monitor_node() call. Peers that connected inbound (without going through discovery_peer_cb) were never added to the monitored[] array, so the heartbeat monitor loop skipped them entirely. Fix: added disklock_monitor_node call in peer_connect_cb alongside lease_register_node, matching discovery_peer_cb.
- 2026-03-08: Bug 99 fix -- unmount hang in disklock_stop_heartbeat. Root cause: heartbeat thread stuck in blocking disk I/O (e.g., iSCSI timeout), thread_join waits forever. Fix: (1) heartbeat loop checks `running` flag between each I/O call, (2) new `mxfs_pal_thread_join_timeout(5000)` replaces blocking join — logs warning and continues if thread doesn't exit within 5s. Changes: disklock.c, pal.h, pal_linux_kern.c, pal_linux_user.c.
- 2026-03-08: Bug 100 fix -- use-after-free in disklock_purge_node during unmount. Root cause: unmount destroyed disklock BEFORE shutting down peer networking. Peer recv threads still running could call peer_disconnect_cb → disklock_purge_node on freed memory. Crashed with `preempt_count 1` in `mutex_unlock` inside `mxfs_disklock_purge_node`. Fix: (1) moved peer_shutdown BEFORE disklock_stop/destroy in mxfs_unmount(), (2) added `!mnt->mounted` early-return guard in peer_disconnect_cb, disklock_expire_cb, and lease_expire_cb. Changes: mount.c.
- 2026-03-10: Bug 108 fix -- disklock expire callback reported wrong node_id ("node 0" instead of actual). Root cause: expire callback passed rhb->node_id from the heartbeat sector read, but when the sector was already zeroed (by disklock_purge_node from peer_disconnect_cb path) or the read failed, rhb->node_id was 0. Fix: use ctx->slot_node_id[slot] (populated by monitor_node at discovery time) as the authoritative node_id for the expire callback. This is reliable regardless of on-disk heartbeat state. Changes: disklock.c (disklock_hb_fn expire callback).
- 2026-03-08: Bug 101 fix -- unique heartbeat slot claiming. Old approach:
  node_id % 64 caused collisions (e.g. test1 node_id=527944736 and test2
  node_id=3065900128 both mapped to slot 32). New: claim_slot() scans all
  64 HB slots and claims the first empty one. Re-claims own node_id from
  previous mount. local_slot stored in ctx, used for heartbeat writes and
  as CAW DLM node_bit. Added find_node_slot() for reverse lookup (used by
  monitor_node, unmonitor_node, purge in mount.c). monitor_node now finds
  actual slot on disk instead of using node_id%64. unmonitor_node uses
  slot_node_id[] in-memory mapping. purge_node scans HB area for actual
  slot. Changes: disklock.c/h, dlm_caw.c/h, mount.c.

### lease — lease manager

- 2026-02-15: Ported from kernel to portable C using PAL
- 2026-02-19: Fixed false SUSPECT under I/O load at 3+ nodes (Bug 29)
  - Added MXFS_LEASE_SUSPECT_MISSES=3 missed renewal counter
  - Monitor resets counter when renewal arrives on time
  - INFO-level log on each transient miss before SUSPECT
- 2026-02-19: Fixed unmount hang -- replaced uninterruptible sleep (msleep) with condvar timed wait in both renew and monitor threads; stop() broadcasts condvar before joining
- 2026-02-19: Fixed lease starvation under heavy I/O at 4+ nodes
  - RT-priority threads via mxfs_pal_thread_create_rt() (sched_set_fifo_low)
  - Timing: renew 5s->1s, duration 30s->60s, timeout 90s->180s->600s, suspect misses 3->6
  - Send budget: 500ms cap prevents blocked TCP send from consuming renewal interval
  - New PAL function mxfs_pal_thread_create_rt() added to pal.h and both PAL implementations
- 2026-02-19: Fixed lease monitor not detecting dead peers (Bug 30)
  - **Root cause 1**: JOINING nodes were never monitored for lease expiry. The monitor
    only checked ACTIVE state for missed renewals and SUSPECT state for timeout. A node
    that was discovered (registered as JOINING) but died before sending its first
    lease renewal would linger in JOINING state forever, never detected as dead.
    Fix: monitor now treats JOINING identically to ACTIVE for missed renewal detection.
  - **Root cause 2**: peer_disconnect_cb (TCP disconnect handler) called remove_node()
    which unregistered the peer from the lease system. This preempted the lease monitor
    from ever detecting the dead node via lease expiry. Since lease renewals are sent
    over TCP, the renew thread's TCP sends to the dead peer would eventually fail,
    triggering peer_disconnect_cb, which removed the node from lease monitoring before
    the 180s timeout could fire. Fix: peer_disconnect_cb now calls purge_node_dlm()
    instead of remove_node(), keeping the node in the lease table so the monitor can
    complete the ACTIVE->SUSPECT->DEAD transition. Only definitive events (graceful
    NODE_LEAVE, lease_expire_cb) unregister from lease.
  - **Why TCP keepalive also failed**: the 1-second lease renewal sends reset the TCP
    keepalive idle timer on every send, preventing keepalive probes from ever firing.
    With small 48-byte renewal messages, the TCP send buffer (128KB+) takes ~45 minutes
    to fill, so TCP send errors were extremely delayed.
- 2026-02-19: Increased lease timeout from 180s to 600s (10 minutes)
  - Under heavy 4-node concurrent write load, lease renewals can be delayed long enough
    to exceed the 180s hard timeout, causing nodes to be falsely declared dead
  - 600s provides sufficient margin for sustained write bursts while still detecting
    genuinely dead nodes within a reasonable timeframe
  - Only MXFS_LEASE_TIMEOUT_DEFAULT_MS changed; duration (60s) and renew interval (1s) unchanged
- 2026-02-20: Switched lease heartbeats from TCP unicast to UDP multicast
  - At 16+ nodes (120 TCP peer connections), DLM traffic congests TCP, blocking lease
    sends and causing false node-death declarations with cascading failures
  - Single UDP multicast packet (port 7602) replaces N TCP unicast sends
  - New UDP recv thread listens for heartbeats from other nodes
  - Removed send_cb/send_cb_data (TCP send callback) from lease context
  - Removed MXFS_MSG_LEASE_RENEW handler from mount.c DLM message handler
  - Removed lease_send_cb() from mount.c
  - Added mxfs_le64_to_cpu/mxfs_cpu_to_le64 to pal.h for wire format
  - Wire format: mxfs_lease_udp_msg with magic 0x4D584C48, version 1, volume UUID filtering
  - mxfs_lease_create() now takes volume_uuid, mcast_addr, lease_port, use_broadcast
  - UDP socket setup follows same pattern as discovery module (multicast join / broadcast)
- 2026-02-22: Fixed lease renewal starvation under heavy metadata I/O (Bug 47)
  - Under 4-node concurrent metadata stress (200 file creates per node in same directory),
    lease renewals delayed 70-87s. With SUSPECT_MISSES=6 and 2s monitor interval, nodes
    went SUSPECT after ~72s (60s duration + 6*2s misses), triggering membership flaps,
    cache purges, 228 duplicate dir entries and 362 lost files.
  - **Root cause**: UDP recv thread was normal CFS priority while renew/monitor were RT.
    Under heavy I/O, the recv thread got starved by block I/O completions and DLM message
    handling, leaving heartbeat packets unprocessed in the kernel socket buffer for 60+ seconds.
    Even though the sending node's RT renew thread sent packets successfully, the receiving
    node's CFS recv thread never processed them before the monitor counted 6 misses.
  - **Fix 1**: Upgraded UDP recv thread to RT priority (mxfs_pal_thread_create_rt).
    All three lease threads (renew, monitor, recv) now run at SCHED_FIFO low priority.
  - **Fix 2**: Increased MXFS_LEASE_SUSPECT_MISSES from 6 to 60 as defense-in-depth.
    Total time before SUSPECT: ~180s (60s duration + 60*2s = 120s of missed monitor checks).
    Exceeds DLM lock timeout (120s) and all observed starvation bursts. Dead node detection:
    SUSPECT at ~3 min, DEAD at 10 min (600s hard timeout unchanged).
- 2026-03-01: Fixed cascading membership flapping under heavy I/O
  - **Problem**: Under 4-node concurrent metadata I/O on a single ESXi host, lease heartbeat
    starvation causes cascading membership flapping. Missed renewals -> SUSPECT -> cache flush
    + lock purge -> I/O storm -> more missed renewals on other nodes -> death spiral. 679 missed
    lease renewals on test4, epoch reached 40+, 3 of 4 nodes crashed.
  - **Fix 1**: Increased MXFS_LEASE_SUSPECT_MISSES from 60 to 150. Total time before SUSPECT:
    ~360s (60s duration + 150*2s = 300s of missed monitor checks). Dead nodes are detected via
    TCP disconnect in seconds; lease timeout is a safety net, not primary detection.
  - **Fix 2**: Added membership change cooldown (MXFS_MEMBERSHIP_COOLDOWN_MS = 30s) in mount.c
    lease_expire_cb. If a node was removed within the last 30s, further lease expiry callbacks
    are skipped (logged and deferred). Breaks the cascade at the membership change level.
  - **Fix 3**: Reduced MXFS_LEASE_RENEW_DEFAULT_MS from 1000 to 500. Doubles renewal attempts
    per duration window (120 vs 60), giving the renew thread more chances to succeed under
    I/O pressure. Duration:renew ratio now 120:1.
  - **mount.h**: Added `last_membership_change` field to `struct mxfs_mount`
  - **mount.c**: Added MXFS_MEMBERSHIP_COOLDOWN_MS constant, cooldown logic in lease_expire_cb
- 2026-03-01: Bug 69 fix -- extended membership change cooldown to peer disconnect path
  - **Problem**: The 30s cooldown (Bug 68) only applied to lease_expire_cb, but the 4-node test
    showed 44 epoch changes driven primarily by TCP disconnects (peer read failures), not lease
    expirations (only 1 fired). Under heavy I/O, one node's stall causes DLM TCP timeouts on
    other nodes, triggering peer_disconnect_cb for each one. The DLM purge + cache invalidation
    from handling the first disconnect creates an I/O storm that stalls TCP on more peers,
    cascading into rapid-fire membership changes.
  - **Fix**: Added the same cooldown check to peer_disconnect_cb. Both peer_disconnect_cb and
    lease_expire_cb now check last_membership_change before proceeding. If within the 30s
    cooldown window, the disconnect is logged as a warning and skipped. The node will still be
    caught by lease expiry if it is truly dead (6-minute window). The cooldown does NOT prevent
    TCP reconnection attempts -- the peer subsystem handles reconnection independently after
    the callback returns (peer_connect_force on the send path).
  - peer_disconnect_cb now also stamps last_membership_change when it proceeds, so the cooldown
    is shared between both paths (a peer disconnect suppresses both subsequent disconnects AND
    subsequent lease expiries within the window, and vice versa).
  - **mount.c**: Cooldown check + timestamp update in peer_disconnect_cb, updated comments
  - **mount.h**: Updated last_membership_change comment to reflect both paths

### discovery — UDP multicast

- 2026-02-15: Ported from kernel to portable C using PAL
- 2026-02-17: Documented broadcast requirement for nested ESXi; added environment guide
- 2026-02-19: Fixed unmount hang -- replaced uninterruptible sleep with condvar timed wait in sender thread; added UDP socket shutdown in stop() to unblock recv thread immediately

### scsipr — SCSI PR fencing

- 2026-02-15: Ported from kernel to portable C using PAL
