## 0.11.397 (sess48) — 2026-08-03 — token campaign step 3a: authority trailer live in the log

- `XFS_BLF_MXFS_AUTHORITY (1<<5)` + 24-byte big-endian `struct
  mxfs_blf_authority` {version, class, resource, grant_epoch, owner_slot,
  owner_boot} in xfs_log_format.h (classes NONE/AG/SB; bits 5-10 were
  free, 11-15 are BLFT).
- Writer in pal/linux/xfs_buf_item.c: every multi-node, non-stale buf
  format region emits the trailer in the SAME region after the dirty map
  (local blf+token buffer → one xlog_format_copy of base_size+24; the
  returned-pointer blf_size mutations preserved).  Size side reserves the
  identical 24 bytes via the shared pure predicate
  mxfs_buf_item_wants_authority — the estimate and emission can never
  disagree (CIL shadow-buffer overrun class).  Content captured at CIL
  format time per the step-2b ruling: daddr→agno→pag_mxfs_grant_epoch
  (class AG), xfs_sb_buf_ops → class SB, epoch 0/unclassifiable → class
  NONE (fail closed at the future gate).  Stale/cancel segments stay
  untokenized.
- Passive: recovery's only format-region check (xfs_buf_log_check_iovec)
  is bitmap-bounds, so the trailer is invisible until the step-3b parser.
  Verified live: guards + matrix 9/9 + rsync lap + **crash_consistency
  204/204** (real dirty-log replay of tokened records) all clean on the
  32-node fleet.

## 0.11.396 (sess48) — 2026-08-03 — token campaign step 2a: grantee epoch plumbing

- `mxfs_dlm_caw_read_ex_grant_epoch` (dlm_caw.c, clone of the sess19
  read_generation idiom) + v5 wrapper `mxfs_v5_dlm_ag_grant_epoch`
  (CAW only; TCP -ENODEV = fail closed).  The fresh AG EX acquire path in
  xfs_mxfs_dlm.c (the sess19b post-grant slot-read block, slot-stable /
  pre-pag_dlm_lock window) reads the epoch its granting CAS stamped into
  the new `pag->pag_mxfs_grant_epoch` (xfs_ag.h — the durable counterpart
  of the in-memory ag_dlm_tenure_id; 0 = no authority, token writers must
  fail closed).  Deployed fleet-wide; guards + matrix + soak cycle clean.

## 0.11.395 (sess48) — 2026-08-03 — foreign-replay token campaign step 1: ex_grant_epoch

- New on-disk field `ex_grant_epoch` in `struct mxfs_caw_lock_slot` (8 of
  the 352 reserved bytes; 512-byte layout + _Static_assert intact): the
  generation of the CAS that granted the current exclusive-class (EX/PW)
  holder.  Stamped inside `caw_grant_epoch_update` — the single helper
  every grant path already calls after its generation bump (initial
  acquire, waiter promote, convert-upgrade, batch, claim-recycle) — so it
  is durable before the grantee can touch covered metadata and unique per
  acquisition (unlike dir_epoch, which moves only on cross-node handoff).
  0 = no-authority sentinel (fresh slots pre-grant, tombstones, repaired
  slots — repair deliberately does NOT carry it forward: unknown EX
  history must fail closed at replay).  At fencing, the frozen slot (dead
  node's EX bit + this epoch) becomes the held-at-death authority
  manifest for the foreign-replay token gate (GPT-ruled design; see
  ccmemory sess48-GPT-ruling-foreign-replay-token-design).  Passive until
  the replay gate lands — no behavior change; deployed fleet-wide, guards
  clean (matrix 9/9, reap CLEAN), first soak cycle clean.

## 0.11.387-394 (sess48) — 2026-08-03 — P53 fossil family: media-vs-transit decided, two roots proven and fixed

- 387-388 (instrumentation): in-kernel media-vs-transit discriminator
  P-IUNL-DISCRIM at every store-overlay mismatch — after the store lock
  drops, A/B-read the cluster sectors PLAIN (target-cache-coherent view)
  and SCSI-FUA (media view), decode the same slot, print img/committed/
  plain/fua + wr_epoch.  All specimens: WRITE-NOWHERE-IN-TARGET with
  wr_epoch STAMPED — the covering cluster write completed but CARRIED THE
  FOSSIL; the LIO transit/FUA-read-path theory is dead (candidate fix F
  plain-bio-in-window would have done nothing).
- 389-390 (A-prime v4): install site 4 = WRITE side — overlay committed
  iunlink values onto the outgoing inode-cluster payload in xfs_buf_submit
  before xfs_buf_verify_write (P-IUNLSTORE-WRSITE names the dirty
  pipeline); retire is now payload-verified (stamp wr_epoch only when the
  completed write actually carried the record's value; same-gen value
  mismatch = P-IUNLSTORE-FOSSILWR alarm; different-gen slot also retires).
- 391 (ROOT #1 FIXED): the in-core fossil reverter = the
  mxfs_iflush_cluster_merge_dirs bli_dirty save/restore of
  di_next_unlinked — buffer-level flag skips exactly when the iunlink
  write was checkpointed (BLI detached), installing the platter's
  pre-write chain value in-core; xfsaild then destaged the fossil (the
  390-c1 WRSITE bli=0 comm=xfsaild specimens).  It also restored without
  a CRC recompute (nu IS inside the di_crc region) and could revert a
  FOREIGN slot's fresher disk value.  Both memcpy arms fixed: restore
  removed, replaced by install site 5 = one store overlay after the merge
  loop.  Discrim FUA leg gated off under mxfs_fua_disable (sess113
  forced-FUA-under-buffer-lock wedge vector; plain-only verdicts).
- 392 (A-prime v5, GPT-ruled): records are AG-TENURE-SCOPED — (ino,gen)
  is unsound cross-tenure (nu carries no ordering; a stale record can
  graft an abandoned past over a peer's newer same-gen chain value — the
  391-c3 inverted-P53 autopsy).  mxfs_iunl_store_purge_ag before all four
  mxfs_v5_dlm_ag_unlock sites (RELLEAK = unhomed record at a post-drain
  release = drain-gap alarm); overlay refuses to graft against a LIVE
  in-core inode whose i_next_unlinked disagrees (P-IUNLSTORE-LIVESKEW;
  icache peek is coherent — all nu writers and overlay sites hold the
  cluster buffer lock).
- 393 (diagnostics): P-IUNLSTORE-QUERY store dump at every P53;
  AGPURGE-ALIVE proof-of-life; tests/iunl_soak_sweep.sh marked per-cycle
  fleet sweep (dmesg persists across preps — raw greps count prior
  builds).
- 394 (ROOT #2 FIXED): the fossil nu SURVIVES INODE REUSE — a lost
  remove leaves the dead chain value on the platter; reuse-create stamps
  a NEW di_gen around it at iflush (which never writes nu), blinding
  every gen-keyed defense (GENSKEW keep-and-skip, gen-scoped records);
  the next unlink of the reused ino trips P53 → EFSCORRUPTED shutdown
  (392-c2 and 393-c3 fatals, both decoded via QUERY=NO-RECORD +
  the RELLEAK record naming the exact fossil value).  Fix: P-CREATE-NUFIX
  in xfs_inode_init — a just-allocated ino provably cannot be on any
  unlinked list, so a non-NULLAGINO dinode nu is a fossil by proof;
  cleared + CRC + 4-byte buffer log inside the create transaction.
  First soak cycle: 61 fossils healed on the hot node, fleet clean.
- Soak state at close: 394 c1-c2 clean (laps 32/32, matrix 9/9, reap
  guard clean, relleak=0 mid-run, liveskew=0, wrsite=0, fossilwr=0);
  c3 interrupted by host-side co-tenant load waves (80-190), not an
  mxfs defect; multi-cycle P53-zero soak continues.
- Rig note: 393-c1 saw 5 nodes hard-hang then receive external NMI
  injections (unattributed; concurrent claude sessions on the host are
  the suspect) → panic/reboot → heartbeat fencing cascade; wedge stacks
  lost to the reboots.  All 32 nodes re-armed with kernel.sysrq=1 for
  next-time stack capture.

## 0.11.373 (sess46) — 2026-08-02 — NEW OPEN D-REAP-IFREE-EFSCORRUPTED-SHUTDOWN-372 + probe completion

- NEW CRITICAL (OPEN): during an openunlink_matrix at SHIP config (knob=0,
  fresh mkfs, 0.11.372) test2's inactivation hit xfs_ifree rc=-117
  (EFSCORRUPTED) → 0x1 shutdown → withdrawal; later cases' rm EIO'd as
  fallout (multi_opener/mmap_only rows).  One occurrence; three targeted
  repro attempts clean (fresh-prep matrix; aged rsync-lap→matrix;
  crash-killed-mid-flight→matrix).  Full evidence + protocol in the
  ledger.  test2's dmesg ring was lost to re-preps before a full pull —
  standing rule: full dmesg capture on the shutdown node BEFORE recovery.
- Probe completion: the observed -117 printed NO P-DIFREE line, so the
  last un-probed -EFSCORRUPTED exit under xfs_difree (finobt-getrec
  i!=1) now prints P-DIFREE-CORRUPT site=finobt-getrec — every exit in
  the difree family self-names on the next occurrence.
- Ship-config verification on 372/373: matrix 9/9 (fresh prep), cache
  654/654, zsl 644/644, dirent_durability 30r/0 loss, posix, mmap, fence,
  drc 8-rounds PASS at load 23; rsync 6-test lap ×2 clean (P217=0 ×8 laps
  total).

## 0.11.370-372 (sess46) — 2026-08-02 — routed open-unlink: pace repair + admit hardening

- 370→371: the B6 probe's bespoke per-slot fresh-read chain walk (paying
  chain-length SERIAL sector reads per routed ifree, for bit-carrying
  tombstones that provably cannot exist — every tombstone site gates on
  open_holders==0, dedup merges before tombstoning, repair/claim now
  preserve) collapsed dir_reuse round pace at knob=1 into iget-miss lookup
  storms (creators' destages starved behind rm-rf ifree waves;
  lookup_fail=103).  Probe rewritten find_slot-based (hint + span,
  claim-identical rules; -ENOENT = authoritative absence).  open_clear's
  chain-walk variant reverted to single-record find_slot for the same
  reason (dup residual: crash mid-dedup strands a loser bit until fencing
  — safe direction).  Dedup's loser-tombstone CAS now bumps generation.
- 372: open-admit hardened — the fast path additionally requires the
  INODE's grant to be cluster-backed (i_dlm_routed_iclus), closing the
  neighbor's-cluster-grant hole (the cwr .md5 open fast-pathed on the
  data file's live cluster grant while its own grant stayed local and its
  dirty 33 bytes stayed outside the handoff drain).  Every open now
  converts; local grants shrink to never-opened metadata-only inodes,
  whose dinode bytes ride the cluster buffers make_durable drains — so the
  368 covered_active/fan_out widenings (measured: handoff serialization,
  no pace gain from reverting alone, but the selfclear starvation risk)
  are REVERTED to sticky-keyed; the selfclear skip-ino fix stays.
- Pace recalibration (ledger + memory): knob=1 dir_reuse has ZERO margin
  against its 8-round floor even on 362 (58 checks = 8 rounds — 3/round +
  fixed checks, NOT 58/3); crash-after-unlink-heavy-workload overruns come
  from a ~100s post-workload interaction at knob=1, not a device backlog
  (idle LUN baseline measured at ~30 iops/node = bast_poll + heartbeat).
  Both are default-ON checklist items for the candidate config; ship
  config (knob=0) code paths from sess46 all short-circuit on
  mxfs_icluster_dlm==0.
- tests/clean_load_run.sh: clean-host-load-window criteria runner (the
  external game-server bursts cycle load 17→88; a one-shot pre-run load
  gate races the next burst — rows must be judged only on runs whose
  recorded hostload stamps stayed clean; a clean-window FAIL is real and
  never retried away).

## 0.11.364-369 (sess46) — 2026-08-02 — routed open-unlink: five defects burned down to matrix 9/9

The 363 implementation failed openunlink_matrix 7/9 on the routed config;
each failure was RULE-4 instrumented, rooted, and fixed one build at a time.
All are icluster-config (knob=1) defects; knob=0 ship config untouched
except where noted.

- 364: P90 INTENT POISONING — the per-inode bast-release publish set
  i_mxfs_open_pub=true for ROUTED inodes whose unlock rides iclus (which
  ignores p_open_op); the release sweep then believed the bit durable and
  skipped its SET; the cluster released with nothing on disk (basic DATA
  LOST, defer=0, P90 fired + zero P-ICLUS-OPENSET).  P90 now excluded for
  routed inodes.
- 365: gate rekeyed from the sticky bit to the CONFIG predicate
  (mxfs_dlm_iclus_covered) — a fresh create's first grant is a mode-0-era
  per-inode grant (sticky lands on the NEXT acquire), so the sticky-bit
  gate left exactly the just-created-then-rm'd files poisoned.
- 366: P95-OPEN-STALE-INCARNATION — an open whose ilock-ride acquire
  adopted a peer-freed image (P116-ZOMBIE-ADOPT, in-core mode 0) completed
  and served the tombstone (reads returned '').  Now -ESTALE → VFS re-walk
  → clean ENOENT.  Applies to all configs (P116 exists at knob=0 too).
  openunlink_matrix hold_fd: pidfile-wait replaces sleep-1 so the matrix
  deterministically tests its intended fd-held-BEFORE-rm ordering.
- 367: SPLIT-BRAIN CLOSURE — a covered inode on a mode-0-era per-inode
  LOCAL grant (no disk slot) satisfied C3's mode check while a peer's
  routed rm acquired the CLUSTER resource nobody held: free with no BAST,
  no sweep, no bit (P19-B3DEC will_skip=0 with zero opener-side
  interaction).  mxfs_iclus_open_admit now refuses the fast path without a
  live cluster grant (!ic ⇒ false), and the open_protect slow path forces
  the conversion (P95-OPEN-CLUSTER-CONVERT: same-mode routed acquire =
  iclus claim + sticky + conv_pi).  MATRIX 9/9 from this build on.
- 368: local grants made first-class in the cluster protocol —
  covered_active counts and fan_out arms covered REG inodes still on
  LOCAL grants (config predicate; dirs stay excluded).  Root: cc `cwr`
  1-of-654 flake — node11's fresh 33-byte .md5 (local-grant, dirty) was
  invisible to the whole iclus release, so the cluster handed off before
  its drain and 31 readers cold-read empty exp while agreeing on the data
  file.  Structural, pre-existing at knob=1 since Phase A.
- 369: 368's widening starved the -EDEADLK SELFCLEAR escape — the spinning
  acquirer's OWN local grant (undemotable while it holds the ILOCK) kept
  covered_active true; under a host load-63 burst two nodes exhausted
  into 0x8 shutdowns.  The selfclear's covered_active now skips the
  acquiring ino (its grant is what the acquire converts).  Verified: 369
  rode out a load-79 burst with 32/32 mounted, zero shutdowns; matrix 9/9.

## 0.11.363 (sess46) — 2026-08-02 — routed open-unlink protection (iclus + open_tracking coexist)

- D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY campaign (GPT closure item 1 —
  write-unit authority via ICLUSTER): the icluster_dlm=1 / open_tracking
  mutual exclusion is LIFTED.  Routed files' open-holder bits are now
  published per the GPT C9-ordering ruling (publication-before-release
  replaces the per-inode release-CAS fold):
  - mxfs_dlm_caw_open_set: durable standalone SET; allocates a live
    bit-only slot when the routed resource has no record (claim discipline
    verbatim from the lock claim: fresh compare read, live-magic → lost
    race re-probe, same-resource tombstone inherit); concurrent fresh-claim
    dups resolved by merge-to-canonical + tombstone-loser
    (caw_open_set_dedup) so a knob=0 reboot can't inherit the sess47
    two-EX-holders state.
  - mxfs_iclus_disk_release: single choke point for the on-disk cluster
    release (normal last-ref, BAST-notify immediate, -EDEADLK selfclear);
    gates on mxfs_iclus_publish_open_bits — any covered routed inode with
    protected activity gets a durable SET first; failure retains the grant
    via the existing CAS-failure retry arm (fail closed).
  - Admission gate (GPT soundness fix): mxfs_iclus_open_admit refuses the
    C3 open-protect fast path while the cluster is mid-transition
    (ic->busy) or disk grant gone; the slow path re-acquires through
    mxfs_iclus_lock.  Closes the open-admitted-after-sweep race.
  - close-during-SETTING race (GPT): i_mxfs_open_setting marker; C4's
    last-close clear defers to the sweep's post-SET recheck, which clears
    if activity died mid-SET (no permanent stale bit).
  - Routed B6: mxfs_dlm_caw_open_probe — claim-less chain walk returning
    GPT result classes (bits found across live/tombstone/dup records;
    provable absence only on a clean walk to the zero terminator; garbage
    or cap-hit → defer).  xfs_inactive's B6 guard routes covered inodes
    through it; per-inode files keep the fail-closed slot read.
  - Retention invariant (GPT (iii)): caw_repair_slot now preserves
    open_holders (was memset-wiped — a live hole in shipped per-inode
    tracking); caw_claim_inherit_epoch inherits tombstone-carried bits
    (sess40 contract was half-implemented: saved, never restored);
    bit-carrying foreign tombstone at a chosen claim insertion point is
    resurrected live instead of wiped (P-OPENBITS-TOMB-RESURRECT), same in
    open_set.
  - open_clear: chain walk clearing this node's bit from EVERY
    same-resource record (live, tombstone-carried, dup) — first-match-only
    left dup/idle-gap bits deferring peers' reaps until fencing.
  - Flipping icluster_dlm's DEFAULT remains a cluster protocol change that
    must bump MXFS_PROTO_GEN (C7 heartbeat gate excludes mixed clusters);
    knob=1 experiments are same-build by prep construction.

## 0.11.362 (sess45) — 2026-08-02 — rsync rename mass-shutdown: containment + attribution kit

- NEW CRITICAL D-RSYNC-RENAME-DIRTY-CANCEL-MASS-SHUTDOWN-361: 17/32 nodes
  independently hit xfs_trans_cancel(DIRTY) Caller xfs_rename (0x8 shutdown +
  withdrawal) inside rsync_paired; known stale-base dirent-erasure family; the
  shipped pre-dirty revalidate guarded src always but target only for
  RENAME_EXCHANGE — rsync's temp→existing-final rename was unguarded.
- CONTAINMENT (GPT-ruled): full target-expectation preflight for non-exchange
  renames, both polarities (known target vanished/retargeted; absent target
  materialized), strictly pre-dirty (WARN_ON_ONCE + clean abort), returning
  -ESTALE so do_renameat2's retry_estale re-walks both names and retries —
  a vanished target degrades to a successful plain rename after restart, not
  a shutdown and not user-ENOENT (P217-RENAME-TGT-PREFLIGHT).
- ATTRIBUTION KIT: P217-RENAME-DIRTYCANCEL probe at the cancel label (errno,
  dirty bit, names, pre/post src-dir image cookie iv/bytes/fmt/dgen/ve —
  separates below-locks image swap from helper-order failures);
  mxfs.reload_stamp_at_commit micro-revert lever restoring the pre-sess45
  reload stamp TIMING (same values, commit point) for lap A/Bs of the
  amplifier hypothesis without a binary rollback.

## 0.11.361 (sess45) — 2026-08-02 — P195 Option B: adopt at EX acquire (GPT contract)

- D-DIRENT-PUBLISH-STALE-BASE-P195-360 fix, per the gpt_ruling_sess44 contract:
  new explicit `i_dlm_base_valid` bit for the dir-base coherence baseline pair
  (valid_epoch, cached_grant_gen), knob `mxfs.dir_adopt_at_acquire` (default 1).
  Gate at the dir-EX authorization boundary (fast-path cached serve): armed on
  sentinel (bit unset) or epoch != (both directions; epoch query paid only on
  the no-token leg), arming the SAME proven reload pipeline (P63/gg_refresh) at
  post_release=true; gen movement is counted, not armed (sess63: gen-only
  refresh resurrected deletes — release-time invalidation makes the gen leg
  redundant per the contract's UNLESS clause).
- Stamp discipline: the baseline is published ONLY at the reload's
  install-complete point (after from_disk + type re-wiring + sf union-merge)
  via mxfs_dir_base_stamp (WRITE_ONCE pair, smp_store_release valid), using the
  PRE-read (epoch, gen) so mid-reload movement leaves the stamp behind and the
  next authorization re-adopts.  Invalidation: release drain (bast_process, pre
  wire-unlock — a same-epoch re-grant can never skip a needed adopt), reload
  commit-to-adopt (aborted install stays invalid), phantom-EX bail, inode
  init + BOTH create-reuse funnels (reset_inode_for_create/rearm_unpublished —
  the reuse paths never reset the sess28 baseline quadruple; now they do,
  knob-gated for A/B purity).
- Creator publish stamp SUBORDINATED (contract item 6): with the knob on, a
  self-created dir's first real EX grant always stamps through the helper
  (closes the fresh-create window where the sentinel leg could adopt a
  not-yet-destaged disk image over the live create); creator_baseline_stamp
  stays as the gate-off A/B lever.
- Fail-closed: a tenure that already mutated is never adopted over
  (P216-B-DIRTY-SKIP + counter); P34J demote-wait bails leave the gate armed
  (level-held retry, counted).  Per-reason counters in P6-DIRPATH stats dump
  (P216-B-STATS).  P195 probe now prints bvalid.
- Fixed three missing-braces bugs (indentation lied): the evict-path epoch
  syncs (newtenure/tenure_evict) and the reload commit-point stamp all stamped
  i_dlm_dir_valid_incarn UNCONDITIONALLY — converting "no baseline" into "live
  baseline of 0" (permanently stale), the exact raw-compare feed of the
  captured P195 hit.

## harness (sess44) — 2026-08-02 — prep_fs refuses claimed devices; tcp rig unwired

- tests/setup/prep_fs.sh now REFUSES to mkfs a device with /sys/block holders —
  on the current rig the legacy tcp/cawp default /dev/sda enumerates as a PATH
  MEMBER of the caw multipath map, and only multipathd's exclusive claim turned a
  prep of the tcp condition into a lucky EBUSY instead of writing into a live
  path of the shared caw LUN. Verified: 2/tcp prep now fails with the diagnosis.
- Rig fact recorded in the ledger (D-MATRIX-UNMEASURED): the tcp condition has NO
  wired disk on this fleet (no mxfs-shared in VM XML, no host device) — the tcp
  matrix column is unrunnable until the rig is re-wired.

## 0.11.360 (sess44) — 2026-08-02 — ifree revalidate: find the real bucket (strand root)

- D-OUTAGE-REMOUNT-MUTUAL-IFREE-SKIP-STRAND root PROVEN + fixed: the revalidate's
  bucket fallback agino%64 is an upstream-ism (MXFS parks unlink entries on the
  UNLINKER'S SLOT bucket), so an adopted mirror (i_unlinked_bucket unset — the
  post-outage reload shape) computed the wrong bucket, read it empty, and every
  node skipped the free forever ("bucket-empty-peer-freeing" mutual skip). Now an
  empty computed bucket triggers a 64-head scan for our agino: found => proceed on
  the real bucket (P-IFR-BUCKET-MISMATCH logs the proof), not found => skip as
  before. Proof run: computed=4 actual_head_at=1 then P82-REM bucket=1 rc=0, 30s
  convergence; 3/3 outage-arm PASS. Board rerun on 360 pending for closure.

## 0.11.359 (sess44) — 2026-08-02 — reap-work UAF fix shape — FIXED AND VERIFIED
- CLOSED same session: deployed, mechanism proven live (the gate caught a recovery
  batch re-arming the destroyed reap work during teardown: P89-REAP-SCHED-AFTER-
  DESTROY (batch-complete)), then ~10 prep churn cycles + full 32/caw and 8/caw
  boards (27/27 both) with ZERO new panic signatures fleet-wide (~8 expected at
  the historical rate).

- D-REAP-WORK-UAF-PANIC-AFTER-UNMOUNT (critical, NEW): 5 kernel GP-fault panics
  captured on host serial logs ("Workqueue: events 0x<garbage>" — a work_struct
  executed from freed mount memory), all within minutes of prep unmount/remount
  churn, all silently self-healed by panic-reboot — the hidden cause behind the
  frozen-HB-slot "departure wave", the "did not release mxfs" power-cycles, and
  the mystery reboots. Mechanism (hypothesis with strong code+timing evidence):
  m_mxfs_reap_work re-armed AFTER mxfs_defer_reap_destroy's cancel by late
  reap-adds (unmount-time eviction of a deferred zombie) or a recovery batch
  finishing mid-teardown; the 30s timer then fires into freed memory.
- Fix shape == instrumentation: all six arm sites now go through
  mxfs_reap_sched(), gated on m_mxfs_reap_dead (set at destroy entry, cleared
  at init); a post-destroy arm becomes a loud no-op logging
  P89-REAP-SCHED-AFTER-DESTROY. Durable bucket state carries the skipped duty.
- VERIFICATION PENDING: deploy, hammer preps (reproducer = prep churn: 5 panics
  in ~8 preps on .355-.358), sweep serial logs for zero recurrence and for the
  new warn line proving the mechanism.

## 0.11.358 (sess44) — 2026-08-02 — D-DESTAGE-TEAR CLOSED: guard race arms + stall knob; boards green

- D-DESTAGE-TEAR-BUCKETLESS-ORPHAN -> FIXED AND VERIFIED (see OPEN_DEFECTS.json for the
  full dossier). GPT gap-review drove four purpose-built race arms
  (tests/guard_race_arms.sh joiner|abandoned|stale_resume|inherit), all passing live:
  joiner exclusion (claim skips a held guard, 2/2), abandoned-guard change-detection
  takeover (peer with different uptime reclaims a corpse guard in 105s and frees the
  orphan), stale-holder fencing (paused holder resumes after takeover: refresh CAS
  fails, P99-GUARD-LOST, rc=-116, ZERO post-takeover sweeps), and joiner-inherits-
  deferred-bucket (rejoiner re-claims its slot; ordinary last close frees in 10s with
  zero recovery events).
- mxfs.ubsweep_stall_ms (debug, default 0): after the hold, stall WITHOUT refreshing,
  then resume — makes the pause-takeover-resume race directly testable.
- Boards on this build: 32/caw 27/27 PASS and 8/caw 27/27 PASS (policy row red at the
  open-defect count, as designed).
- NEW ledger entries (RULE 6): D-MASS-TEARDOWN-DEPARTURE-WAVE-WEDGE (major — still-
  mounted tail nodes saw cleanly-departed peers as 62s-frozen slots during a 32-node
  mass teardown, fencing wave wedged 4 umounts, harness power-cycled them) and
  D-RELOAD-FREED-ADOPT-BOGUS-IMODE (minor, fix shipped in .357, verification pending).

## 0.11.357 (sess44) — 2026-08-02 — freed-shell adopt: skip iops rewire (bogus i_mode)

- Adopting a peer-freed incarnation (P103/P116 reload, mode=0) ran the S_IFMT-change
  vtable rewire; xfs_setup_iops on a mode-0 shell routes through init_special_inode(0)
  and logs 'bogus i_mode'. Rewire now skipped for mode==0 (freed shell has no namespace
  entry and cluster opens==0, so its vtables are never dereferenced; a later
  resurrecting reload still rewires — old_ifmt is captured per-reload). Ledgered minor;
  verification = next observed P116 adopt with zero bogus lines.

## 0.11.356 (sess44) — 2026-08-02 — ubsweep_hold_ms debug knob (guard race widener)

- mxfs.ubsweep_hold_ms (debug, default 0): hold the recovery guard N ms (refreshing
  every 500ms) between P99-UBSWEEP-START and the sweep, so joiner/abandonment races
  against the guarded unclaimed-bucket pass become testable windows instead of ~100ms.

## 0.11.349 (sess41) — 2026-08-01 — transaction-atomic untrusted replay (tear containment)

- Foreign/adopted replay: if a recovered transaction contains ANY untagged image
  (buf/dquot/quotaoff/icreate), skip the WHOLE transaction including its inode items
  (P227-FR-ATOMIC-SKIP). Kills the proven half-applied-unlink tear (dirent present ->
  nlink=0 inode on no bucket). GPT-approved as containment; KNOWN LIMITS ledgered:
  multi-transaction ops can still tear at op granularity; landed home writes are not
  rolled back; the authority protocol remains the real fix (defect stays OPEN).
- tests/openunlink_deaths.sh unlinker_death now accepts the two legal outcomes
  (α zombie swept+freed; β unlink evaporated atomically) and fails on any torn state.

## 0.11.348 (sess41) — 2026-08-01 — dead-opener bits never stripped (opener_death root)

- PROVEN (opener_death case, ino=291): mxfs_dlm_caw_purge_node's candidacy predicates
  (batch fast-skip, per-slot fallback, CAS-loop break) tested the five holder classes and
  waiters but NOT open_holders. A dead node whose only footprint is an open bit — the
  NORMAL publish-then-release open-unlink shape — was skipped, the 6027 strip never ran,
  and every peer's B6 deferred forever against a dead opener (reap retried at 30s for
  7+ minutes, open_holders=0x1 unchanged after 'shared purges done').
- All three predicates now include open_holders & dead_mask.
- Also observed: slot-0 death recovery (lowest-slot member) elects the new lowest (slot 1)
  correctly; recovery completion latency ~5min is lease-expiry-bound (separate topic).

## 0.11.347 (sess41) — 2026-08-01 — sweep/worker must not trust cached nlink (leak root #3)

- PROVEN (unlinker_death run 2): sweep read stale-high cached nlink=1 (survivor==opener never
  observed dead peer's droplink) -> skipped the ADOPTED enqueue -> close-time RETIRE entry had
  no authority -> B4 leak. Sweep now enqueues EVERY bucket-chained inode (chain membership is
  the on-disk truth); the reap worker takes a coherence ilock (acquire-side reload when
  stale/NL) BEFORE its gen/nlink checks and BEFORE the authority-flag restore.

## 0.11.346 (sess41) — 2026-08-01 — adopted freer authority (sweep leak root #2)

- PROVEN (unlinker_death rerun, ino=132): the sweep's in-core LOCAL_UNLINK restore was
  stripped by the fd-read's reload (sess19 clear-on-reload) before the retirement
  inactivation ran -> B4 skip (local_unlink=0) -> permanent leak. Authority must be
  re-derived per attempt, not parked on in-core flags.
- Sweep now enqueues MXFS_REAP_ADOPTED entries; the reap worker restores authority on a
  fresh iget under its gen check EVERY retry. Reap entries carry kind OWN/RETIRE/ADOPTED.
- New MXFS_IF_ADOPTED_UNLINK: grants B3/B4 freer authority but NEVER the P2L-OWNFREE
  disk-free bypass (only sound for a node's OWN unpublished life; an adopted freer can race
  a new slot-claimant's scoped recovery -> double-free). Cleared with LOCAL_UNLINK at all
  5 sites + XFS_IRECLAIM_RESET_FLAGS.

## 0.11.345 (sess41) — 2026-08-01 — opener-side zombie retirement (dentry-pin leak)

- PROVEN leak (death case, ino=132 never re-issued over 400 creates): after last close of a
  peer-unlinked file, the opener's dentry alias pins the zombie — cross-node unlink never
  d_deletes the opener's dentry and nothing re-looks the path up, so evict/inactivation waits
  for memory pressure. Unbounded liveness (GPT invariant 8 language).
- Fix: retire-only reap entries (mxfs_defer_reap_add_mode): last close with nlink==0 queues
  one; the worker d_prune_aliases + irele (P92-REAP-RETIRE) — WITHOUT restoring LOCAL_UNLINK
  (false freer authority would arm the P2L-OWNFREE disk-free bypass on a non-unlinker).
  Freer-authority entries also prune before their irele (same pin can block the freer).
- tests/openunlink_deaths.sh: rejoin via prep_node.sh (nodes do not auto-mount); retirement
  asserted by STATE (ino re-issue probe), not capped prints.

## 0.11.344 (sess41) — 2026-08-01 — C8 survivor sweep (GPT invariant 8)

- mxfs_survivor_sweep_slot: after the elected survivor's foreign-slice replay of dead slot S
  completes (recovery_complete), walk bucket S in every AG; iget each chained zombie, restore
  ADOPTED authority (MXFS_IF_LOCAL_UNLINK + i_unlinked_bucket) so B4 does not block, irele into
  normal inactivation (B1-B6 decide free/defer/skip). P97-SWEEP-START/AG/DONE.
- Retry: m_mxfs_sweep_pending_slots bitmap; failed pass stays pending; reap worker retries at
  its 30s cadence and reschedules while sweeps remain. Bucket itself is the durable record.
- Closes the runtime-fence zombie leak: a dead unlinker's deferred open-unlink zombies were
  unreachable until some future mount claimed the slot.

## 0.11.343 (sess41) — 2026-08-01 — D-PEER-TRUNCATE-INVISIBLE fix

- RELOAD-SIZE-DROP-SKIP now fires ONLY on mid-tenure reloads (!post_release). Its sess45
  premise ("a peer never truncates our file to 0") is workload lore, not POSIX: a peer
  truncate under clean EX handoff left the prior holder serving stale size AND re-reading
  the FREED extent through its kept extent map forever (proven ino=132/8388737; cross-file
  leak class if the block is reused). A post_release reload runs under a fresh tenure after
  our invariant-1 release drain, so a same-gen disk size-drop is a peer shrink: adopt
  (P96-RELOAD-PEER-SHRINK-ADOPT). Mid-tenure torn-own-image protection (P97 family) kept.
- tests/openunlink_matrix.sh: trunc_legal now asserts opener coherency (stat/read/fd-read);
  new trunc_partial case (peer shrink 30->10).

## 0.11.342 (sess41) — 2026-08-01 — open-tracking safety closure (GPT audit C1-C5,C10)

- C1: open-holder bit publication now RIDES THE RELEASE CAS (open_op param through
  mxfs_dlm_caw_unlock_gen / mxfs_v5_dlm_inode_unlock_open). The two-CAS shape (best-effort
  open_set then unlock) had a silent-failure window that released an open file unprotected.
  open_set removed (dead). Failed unlock retains grant AND bit state — consistent both ways.
- C3: OPEN-AT-NL hole closed — xfs_file_open ensures a cached DLM grant (mxfs_dlm_open_protect)
  after i_mxfs_open_n++; a dcache reopen of an idle-released/close-demoted inode previously
  carried no grant and no bit, so a peer unlink freed it under the live fd (default-config
  data loss; close_release made it common). Fail-closed: no grant => open fails -EIO (P95).
- C4: eager lazy-CLEAR at last close (mxfs_dlm_open_last_close, P91) — published bits no
  longer linger to evict (hours), so a peer deferred reap converges in seconds.
- C5: B6 defer guard fails CLOSED — open_holders query returns rc (+bitmap out-param);
  unreadable bitmap under EX => defer (P87-OPEN-DEFER-ERR), never read as empty.
  -EOPNOTSUPP (TCP, no tracking yet) proceeds; that exposure stays ledgered.
- C2: B5 log-recovery exemption REMOVED — a failed EX acquire during recovery-driven
  inactivation now skips the destructive free (mutual exclusion is not optional in recovery;
  survivor orphan frees acquire EX cleanly anyway).
- C10: envelope mount with icluster_dlm=1 + open_tracking REFUSED (iclus has no per-inode
  slot to carry open bits; open_set no-oped silently — verified). open_tracking=0 is the
  explicit experimental opt-out.
- Per GPT audit (memory ccloop-c7ee71c6-sess41-gpt-openunlink-audit-ruling). Remaining:
  C7 version gate, C8 survivor sweep, C9 TCP open tracking, 9-case matrix.

## 0.11.341 (sess40) — 2026-08-01 — TRUE ROOT: on-disk slot struct grew past 512

- **The claim-exhaustion cluster shutdowns were a SELF-INFLICTED REGRESSION
  from 0.11.333, and the earlier knob A/B that appeared to exonerate this
  work was INVALID** - mxfs.open_tracking gates behaviour, not struct
  layout, so both arms carried the broken layout.
  ROOT: the new uint64 open_holders added in 333 follows a uint32 field, so
  the compiler inserted 4 bytes of padding and struct mxfs_caw_lock_slot grew
  past its 512-byte on-disk size.  find_slot indexes its multi-slot probe
  read as an ARRAY OF THAT STRUCT, so every slot past the first in a window
  decoded from the wrong byte offset.  P94-SPAN-DISAGREE's byte dump named it
  outright: span16=d4ec3a45acfcd7e69407a00200000000 vs
  fresh16=4c44584d02000000d4ec3a45acfcd7e6 - the span image is the true slot
  SHIFTED BY EXACTLY 8 BYTES.  The probe then classified the shifted image as
  "truly empty" (terminating the chain, hiding live slots) and handed it to
  the claim CAS as the compare (which can never match) -> retry exhaustion ->
  -110 -> SHUTDOWN_CORRUPT_INCORE -> 10-32 nodes cascade.
- FIX: explicit pad4 before open_holders, reserved[352]; layout is 512 bytes
  again with the same field offsets as before 333.
- FIX: the size check is now an UNCONDITIONAL _Static_assert.  The kernel arm
  was a macro (MXFS_BUILD_CHECK_CAW_SLOT) that NOTHING EVER INVOKED - grep
  proved zero call sites - so kernel builds had no size assertion at all.
  That absent check is why the regression shipped silently.
- VERIFIED on 341: crash_consistency PASS 73s/90s (was a 32-node
  NO_TERMINAL_RECORD cascade), zero P94-SPAN-DISAGREE and zero
  P93-SLOT-GARBAGE events fleet-wide.

## 0.11.340 (sess40) — 2026-08-01

- caw_probe_span_enable default restored to 1 (measured: OFF costs
  dir_reuse_coherency a round — 7 vs the >=8 bar — while the 337 re-read
  guard already contains the observed harm and the full 32-node board is
  green with spanning ON; 0 remains the control arm and the safe fallback).
- P94-SPAN-DISAGREE now dumps the first 16 bytes of BOTH the span image and
  the fresh read.  mxfs_pal_alloc uses kzalloc at this size, so the
  disagreeing bytes are real device content (identical on all 32 nodes), not
  uninitialised memory: if the span bytes are a SHIFTED view of a valid slot
  the transfer is misaligned for the window tail, which names the mechanism
  outright.

## 0.11.339 (sess40) — 2026-08-01

- **D-CAW-SPAN-READ-SHORT**: the 16-slot probe read is proven to return data
  that disagrees with a per-slot read of the same LBA microseconds later —
  P94-SPAN-DISAGREE fired 41-91x per node per 32-way run, ALWAYS at
  span_base+1 and ALWAYS with the identical value 0x6fa01f04 on every one of
  32 independent machines, while read_slot at that index returned a valid
  LIVE/TOMBSTONE slot.  A constant across independent machines is not media
  content: the multi-sector read is not filling past its first sector.
  This is the layer UNDER the 337 claim-exhaustion fix.  337 stopped the
  cascading shutdowns by re-reading any unrecognised image, but that guard
  cannot fire for bad bytes that happen to decode as a valid magic.
  So the span optimisation now defaults OFF (mxfs.caw_probe_span_enable=0):
  probes issue per-slot reads, as every other slot consumer already does and
  as the code did before the span existed.  =1 retained as the A/B control.

## 0.11.338 (sess40) — 2026-08-01

- P94-SPAN-DISAGREE: names the layer under the 337 fix.  A slot image served
  from find_slot probe SPAN buffer whose magic is unrecognised, while a
  per-slot read of the SAME LBA returns a valid slot, is a disagreement
  between the multi-slot and single-sector read paths — measured 55-100
  times per node per 32-way run.  337 made classify/CAS robust to it; this
  probe tracks the disagreement itself so its own root can be pursued.

## 0.11.337 (sess40) — 2026-08-01

- **D-CAW-CLAIM-RETRY-EXHAUSTION-SHUTDOWN ROOT PROVEN AND FIXED** (RULE 4
  step 2b).  P92-CLAIMCAS caught it on three nodes independently:
  `cmp[magic=b4bc1b3d gen=4045629598] disk[magic=4d584357 gen=1]
  first_diff=0 fresh_read_skipped=1` — the CAS compare buffer held GARBAGE
  while the medium held a valid live slot.
  CHAIN: find_slot's probe may serve a slot image out of its SPAN buffer;
  `slot_appears_corrupt()` returns false for ANY non-LIVE magic, so an
  unrecognised image is never re-read; find_slot then classifies it as
  "truly empty", which (1) TERMINATES THE PROBE — making a resource whose
  live slot sits further down the chain invisible, so acquires see -ENOENT
  while a peer holds the lock — and (2) becomes the claim's CAS COMPARE
  image via the `last_read_idx != empty_idx` skip.  A compare that can never
  match spins the claim until the acquire gives up; mxfs_dlm_ilock_begin
  escalates that to SHUTDOWN_CORRUPT_INCORE and 10-32 nodes cascade.
  FIX A: the claim target is ALWAYS read fresh before the CAS (one extra
  sector read on the claim path; also feeds the daf50d34 live-magic
  re-probe guard with truth instead of a span artifact).
  FIX B: only a ZERO magic terminates the probe.  Any other unrecognised
  magic is re-read per-slot; if it resolves to a live entry for our resource
  the probe returns it (found), if it resolves to another resource the probe
  continues, and if it is still unrecognised it is recyclable but NEVER a
  chain terminator (P93-SLOT-GARBAGE).
  Retained from 336: the claim-race wall-clock deadline and the bounded
  P91-CLAIMEXH capture.

## 0.11.336 (sess40) — 2026-08-01

- D-CAW-CLAIM-RETRY-EXHAUSTION-SHUTDOWN increment 1 (RULE-4 measured, not
  guessed).  New P91-CLAIMEXH prints, at the moment the acquire gives up, the
  resource hash base, the insertion point we kept CASing, that slot's actual
  content, and a bounded re-probe for the resource.  Two captures at 32/caw:
  test5 empty_idx=50701 with the resource's LIVE slot AT 50701 (a peer won the
  claim for the SAME resource), test1 insertion point = a tombstone of our own
  resource with no live slot (same-resource recycle contention).  Both mean
  progress is possible and we are simply the losing racer — yet the bare
  MXFS_CAW_MAX_RETRIES=100 count returned -ETIMEDOUT and
  mxfs_dlm_ilock_begin escalated it to SHUTDOWN_CORRUPT_INCORE, cascading
  10-32 nodes.
  FIX: a claim-race-dominated inode acquire now retries to a wall-clock
  deadline (MXFS_CAW_UNLOCK_DEADLINE_MS) instead of a bare count — the exact
  pattern the unlock path already ships for the same reason (giving up is
  worse than retrying; we hold nothing that could double-grant).  The deadline
  arms only when a claim race is actually LOST, so a genuine dead-holder wait
  still exits on the count and keeps its own liveness extension.  The
  jittered per-node backoff (caw_inode_backoff) already applies between
  attempts.  P91's re-probe is bounded to 4096 slots — a full 65536-slot walk
  was ~20s of shared-LUN I/O on an already-fatal path.

## 0.11.335 (sess40) — 2026-08-01

- open-tracking hardening + A/B knob (mxfs.open_tracking, default 1):
  * PUBLISHED-FLAG GATE (i_mxfs_open_pub): the clear paths (evict,
    unlinked-inode inactivation exit) previously ran a full slot probe for
    EVERY inode, adding SCSI reads on the shared LUN proportional to
    eviction volume.  MEASURED: zero_silent_loss 440/644 -> 644/644 once
    only published inodes pay the clear.  Only what we set gets cleared.
  * open bit is published on the BAST-RELEASE CAS (the only moment a peer's
    destructive path can be imminent — it must BAST every holder off to take
    EX), not per open().  Per-open CASes were measured to starve real
    acquires at 32 nodes (ea_claim=100 -> -110 -> shutdown).
  * i_mxfs_open_n counts open file descriptions (xfs_file_open /
    xfs_file_release); protected activity = that count or mapping_mapped().
  * mxfs.open_tracking=0 restores pre-sess40 behaviour as a same-build
    control.  Used it to exonerate this work from
    D-CAW-CLAIM-RETRY-EXHAUSTION-SHUTDOWN (control arm reproduces).
  32/caw on this build: fio_perf, cache_coherency, strong_consistency,
  zero_silent_loss 644/644, scaling_curve, posix_multi, mmap_coherency,
  dlm_fairness, dlm_membership, dlm_scaling, dirent_durability (30r, loss=0),
  dirent_publish_integrity, fence_during_write, fault_netpartition, soak all
  PASS; openunlink_probe PASS.

## 0.11.334 (sess40) — 2026-08-01

- Open-tracking completion (increment 3 verified end to end):
  * open bit SET added to the two fresh-CLAIM constructions (single and
    batch) — the grant-CAS arm alone missed the first-touch claim, which is
    exactly the path a create+open takes, so the first probe still lost data.
  * lazy CLEAR moved from evict to the INACTIVATION EXIT for nlink==0 (past
    the last iput, pages truncated: no protected activity can remain).
    Waiting for reclaim left a peer's reap blocked behind a stale bit for
    minutes while the closer's zombie sat RECLAIMABLE.
  * deferred-reap entries carry the defer-time AUTHORITY SNAPSHOT
    (LOCAL_UNLINK intent + recorded bucket) and restore it after the
    generation match: a fresh iget in the worker has neither, so the B4
    no-authority guard was blocking the responsible freer's own reap forever.
  VERIFIED: tests/openunlink_probe.sh PASS (data intact through the held fd,
  peer_frees=0), then P87-OPEN-DEFER → P88-REAP-RETRY (open_holders 0x3→0x1
  as the closer's bit clears) → P145-FREE + P89-REAP-DONE within one 30s
  cycle of the last close.  Pre-fix arm: FAIL, 20 bytes of zeros.

## 0.11.333 (sess40) — 2026-08-01

- D-CROSSNODE-OPEN-UNLINK-DATA-LOSS increment 3 (GPT-reviewed design):
  distributed open tracking + deferred reap.  New slot field open_holders
  (bitmap; reserved-bytes area, slot stays 512B): SET inside every inode
  grant/claim CAS (zero added I/O); LAZY CLEAR at evict (one small CAS when
  the node truly has no protected activity — eviction is the VFS guarantee),
  at unlock_free (freer zeroes the field), at unmount release-all, and at
  fencing (dead nodes' bits stripped with holder bits).  Slots carrying open
  bits never tombstone (tombstones are recyclable by different resources —
  that would destroy a live opener's protection); the clear CAS tombstones
  when it empties the last state; same-resource tombstone claims inherit the
  field.  New B6 OPEN-DEFER guard at the head of destructive inactivation
  (before truncate!): peer bits ⇒ defer whole truncate+ifree, zombie stays
  durable on our bucket, per-mount deferred-reap list + 30s worker
  (iget+irele re-drives the guard; EX acquire BASTs cache-only holders into
  bit-clearing evictions — converges without any new message type).
  Probes: P87-OPEN-DEFER, P88-REAP-RETRY, P89-REAP-DONE/UNMOUNT-PENDING.
  P82-ADD now prints the real (recorded) bucket.

## 0.11.332 (sess40) — 2026-08-01

- D-AGI-UNLINKED F1 increment 2a: PER-SLOT AGI UNLINKED BUCKETS
  (mxfs.iunlink_slot_buckets, default 1, cluster-uniform only).  Multi-node
  inserts go to bucket[node_slot] instead of agino%64, so every bucket member
  is its inserter's own zombie: cross-node chain adjacency, peer-zombie
  reloads (P83-UNL-RELOAD), cross-node backref stitching, and the stale
  in-core self-view that produced the deterministic -117 shutdown
  (tests/agi_bucket_repro.sh) become structurally unreachable at runtime.
  Membership is recorded per-inode (i_unlinked_bucket, stamped at insert and
  by every recovery/reload walk); the remove path USES the record, never
  recomputes, so removals stay correct across a knob flip or foreign
  adoption (GPT sess40 review).  Mount-time xlog_recover_process_iunlinks is
  SCOPED in multi-node mode to this node's own bucket (P86 skip probe) —
  walking peers' buckets was the mount-time arm of the same defect; a
  single-node/first mount still sweeps all 64 (legacy drain).  Foreign cached
  zombies are excluded from quotacheck/bulkstat bucket reloads
  (P85-UNL-FOREIGN-RELOAD-SKIP).  Scrub's hash-membership assert scoped
  (compiled out in this config).  New probes: P84-UNL-BUCKET-UNSET.

## 0.11.331 (sess40) — 2026-08-01

- D-AGI-UNLINKED tombstone-semantics increment 1: "genuinely freed" at the two
  free-aware DLM release sites (xfs_inactive exit, mxfs_dlm_evict) is now
  MXFS_IF_FREE_COMMITTED — set only when THIS node's xfs_inactive_ifree
  commits — instead of VFS nlink==0, which is equally true for a cached or
  reloaded copy of a PEER's live open-unlinked inode.  Guard-skipped
  inactivations (INACT-SKIP-STALE / B2-B5 / IFREE-REVALIDATE-SKIP) now release
  plainly: no is_free epoch/last_ex_slot clear (P144) against a live peer's
  slot.  Deterministic evidence: tests/agi_bucket_repro.sh (2-node, ~40s).
  P128-INACT-EXREL now prints freed=.  GPT sess40: "inactivation skipped !=
  inode freed".

## 0.11.330 (sess39) — 2026-08-01

- D-INODE-WIRE-EX-ORPHAN-ON-EVICT fix (dlmtr-traced to the line): the sess44
  deferred-publish evict skip assumed unpublished => no on-disk slot, but every
  created file's type-1 wire slot EXISTS (gen=1 EX) while the inode still rides
  the unpublished list — the skip orphaned one wire-EX slot per created-then-
  evicted file (the 13.4K board population; the true mechanism behind the slots
  the 326 A/B could not exercise).  Fix mirrors 326: trust the WIRE — one
  hint-read at the skip; a live grant falls through to the real release
  (P-UNPUB-WIRE-DESYNC), a genuinely slotless inode keeps the cheap skip.
- lru_sweep default 0: the 329 sweep was built against a misdiagnosis
  (page-cache-held inodes are off-LRU by upstream design; drop_caches=3 evicts
  them normally).  Opt-in diagnostic only.  D-DWORK-RUNTIME-PIN: DISPROVED.

### 0.11.330 board (sess39 close) — FIFTH ALL-GREEN BOARD @32/caw, 7 OPEN

- Full 22-test board green on 330 (dir_reuse twice in-board, 8 rounds each).
- Session sess39 net: 9 -> 7 OPEN.  FIXED AND VERIFIED: evict-retention wire-EX
  (326), release-barrier (census), statfs drift (328 perag sums), wire-EX orphan
  on evict (330, the true mechanism behind the slot leak).  DISPROVED: dir_reuse
  run-over-run decay (host rig storage), dwork-runtime pin (upstream page-cache
  LRU design).  grace=10 default landed (327).
- Remaining OPEN: authority family x3 (AGI canary quiet all session), pace x2
  (re-baseline under the >=25min-idle rig rule), dirview non-convergence,
  matrix rig-blocked columns.

## 0.11.329 (sess39) — 2026-08-01

- D-CLEAN-UNREF-INODE-LRU-STRAND fix (was D-DWORK-RUNTIME-PIN; pin_census-proven:
  stranded inodes show i_count=0, clean, on_lru=0).  An inode dirty at its final
  iput skips the LRU add; when mxfs later cleans it outside fs-writeback
  (drain/AIL paths), inode_sync_complete's clean-and-unused LRU re-add never
  runs, and no VFS path revisits an already-clean inode — invisible to
  drop_caches forever, holding its cached wire-EX slot (200/200 per bulk-create
  batch measured).  Fix: 30s repatriation sweep walks s_inodes, __iget/iput on
  clean+unused+off-LRU inodes so iput_final performs the LRU add.  lru_sweep=0
  disables.

## 0.11.328 (sess39) — 2026-08-01

- D-STATFS-IFREE-NEGATIVE-RANK1 fix (GPT-reviewed design): statfs on multi-node
  mounts reports cluster-coherent per-AG sums (icount/ifree from pagi_*,
  physical fdblocks from pagf_freeblks) instead of the percpu lazy counters,
  which receive only local transaction deltas and drift monotonically under
  cross-node create/free asymmetry (rank1 measured used=-10851 inodes, +38MB
  phantom free).  Mount-time init of all AGF/AGI baselines the sums.  The
  percpu ADMISSION counters are untouched (no safe external adjustment;
  cross-node delalloc overcommit is a separate ledgered thread).
- pin_census diagnostic param: walks s_inodes printing refcount/DLM/work state
  of every cached mxfs inode — names the D-DWORK-RUNTIME-PIN holder.

## 0.11.327 (sess39) — 2026-08-01

- dir_ex_batch_grace_ms default 40 -> 10.  Three same-day 32/caw A/Bs: turn p50
  81 -> 50ms, dir_reuse 9 rounds fresh (vs 8 at 40); bash inter-op gap 1.2-1.3ms
  so 10ms still batches consecutive local ops into one tenure.  sess38 proved
  the same via sysfs and the setting silently reverted at the 325 module reload
  - defaults are the only durable knob state.

### 0.11.327 board (sess39) — FOURTH ALL-GREEN BOARD @32/caw

- All 22 functional tests green on grace=10 default; dir_reuse passed TWICE in-board
  (8 rounds then 9 rounds — first consecutive-run 9-rounder ever); cache_coherency
  29s (vs 38s at grace=40; the sess7 concern is dead on current machinery);
  sustained_load per_op 279 -> 168ms.
- D-DWORK-RUNTIME-PIN narrowed: pin breaks on unlink, survives peer dir BAST,
  no dwork/rearm activity for pinned inos -> silent i_count holder; next = s_inodes
  ref-census probe.

## 0.11.326 (sess39) — 2026-08-01

- EVICT-RETENTION WIRE-EX LEAK FIX (D-EVICT-RETENTION-WIRE-EX-LEAK, live-proven):
  the sess37 clean-PR evict retention decided on the IN-MEMORY mode; the wire
  can hold EX while memory says PR (bulk-create repro: P6R-RETAIN fired for
  inos whose on-disk CAW slot held granted EX gen=1; 13.4K orphan-EX slots
  (~435/node) accumulated from one board's rsync_paired files, evenly across
  all 32 nodes; every orphan blocks all other nodes on that ino until a
  demand-noino unlock that never comes for never-reaccessed files).
  Retention now requires wire-confirmed PR via mxfs_v5_dlm_inode_granted_mode
  (one hint-path sector read, paid only when all cheaper conditions already
  voted retain).  EX/PW or phantom (NL/no-slot, also live-observed) fall
  through to the normal unlock.

### 0.11.326 verification (sess39) — TWO DEFECTS CLOSED + one DISPROVED (12 -> 9 OPEN net)

- FULL BOARD ALL GREEN @32/caw on 326 (third all-green: 322, 325, 326), dir_reuse in-board 8 rounds.
- D-EVICT-RETENTION-WIRE-EX-LEAK: FIXED AND VERIFIED (bulk repro 190 orphans -> 0; board green).
- D-RELEASE-BARRIER-OPEN: FIXED AND VERIFIED (cluster census: ~130K unlocks, obligation=0 on all
  32 nodes across the full board; defer backstop engaged 2x and correctly withheld).
- D-DIR-REUSE-COHERENCY-32-FLAKY: DISPROVED as an MXFS defect — the run-over-run degradation
  (fresh 8-9 rounds PASS, consecutive-run plateau 7, ~25min idle recovery, reproduced 3 laps on
  schedule) is host-rig storage-path latency: pure-host 4K O_DSYNC probe degrades p90 26->95ms
  max 164->1806ms during plateau runs; nvme0n1 write await grows p50 1.19->4.29ms below the
  entire mxfs/SCST stack; CAW table byte-identical across fast/slow runs; guest CPU + all log/AIL
  counters flat. Rig: Samsung 990 EVO Plus 93% full + ambient user writers (myse 1.19TB/9h).
  RIG CONSTRAINT: pace results comparable only from fresh (>=25min idle) storage state.
- NEW D-DWORK-RUNTIME-PIN (found by the 326 A/B): bulk-created inodes pinned in memory across
  drop_caches (armed dwork igrab suspect); demand-release verified working; runtime sibling of
  the sess36-37 unmount dwork family.
- NEW D-STATFS-IFREE-NEGATIVE-RANK1: n1 in-memory ifree > icount by 10851 (df -i used=-10851);
  n16/n32 sane; platter consistent.

## 0.11.325 (sess38) — 2026-08-01

- Heartbeat-starvation mutex fix (D-RELABORT-ORPHAN-LOOP-HEARTBEAT-SELFFENCE
  RULE-4 step 2b — root CONFIRMED live by the 324 probes within an hour of
  deployment: test1 P-HB-SLOW lockwait_ms=26726 write_ms=0; peers
  P-HB-MONSLOW 5.4-6.5s).  Three disklock read loops held ctx->lock
  CONTINUOUSLY across full slot scans, starving the heartbeat writer that
  shares the mutex: mxfs_disklock_read_all (64 reads under one hold),
  mxfs_disklock_get_stale_slot_mask snapshot pass (63) and its repeated
  poll pass (63 x threshold/poll iterations) — the latter two run from
  RUNTIME v5_mount acquire/join paths.  At storm-saturated ~400ms/read one
  scan = ~25s continuous hold; at the 62s default lease a bad episode =
  the test21 self-fence.  Fix: per-slot lock/unlock (the hb monitor pass's
  own precedent) — hb-writer wait now bounded by ONE read.  Slot reads are
  512B device-atomic; no cross-slot mutual exclusion was ever needed.

### 0.11.325 full board @ 32/caw (sess38 true close)
ALL FUNCTIONAL TESTS GREEN (2nd all-green board; 1st was 322) — including
dir_reuse in-board (58/58, 110s).  dir_reuse x3 post-fix: PASS-8/FAIL-7/FAIL-6
rounds — bimodal pace unchanged (its tail = EX-rotation x release-drain
economics, distinct from the fixed hb starvation).  9 OPEN.

### 0.11.325 verification (sess38) — DEFECT CLOSED (10 -> 9 OPEN)
Same-saturation A/B: every post-fix hb event lockwait_ms=0 (was 26726);
residual write_ms<=2.5s = raw single-I/O bound, 25x margin vs the 62s lease.
10/10 verification tests PASS including crash_consistency (77s, clean
terminal records — its NO_TERMINAL_RECORD x32 pattern rode the same
starvation) and fence_during_write (32/32; failed 2 nodes on the incident
board).  D-RELABORT-ORPHAN-LOOP-HEARTBEAT-SELFFENCE = FIXED AND VERIFIED.

## 0.11.324 (sess38) — 2026-08-01

- P-HB-SLOW / P-HB-MONSLOW (D-RELABORT-ORPHAN-LOOP-HEARTBEAT-SELFFENCE
  RULE-4 step 1): unconditional disklock heartbeat cycle clocks — per-cycle
  write_ms + lockwait_ms (ctx->lock is shared with the 32-peer monitor scan)
  + age_since_last_ok_ms + monitor-pass duration; logs ONLY when a write is
  slow (>2s), the last-ok age exceeds 2 intervals, or the monitor pass
  exceeds 2 intervals.  A future self-fence names its own outage anatomy
  (device-queue stall vs mutex hold vs hard failure) instead of rotating out
  of the ring.  hb write failure log now carries age_since_last_ok_ms.

## 0.11.323 (sess38) — 2026-08-01

- D-AGI-UNLINKED-CROSSNODE-RECOVERY-SHUTDOWN instrumentation (RULE 4 step 2):
  - mxfs_inode_disk_unlinked() (xfs_mxfs_dlm.c): FUA dinode read returning
    on-disk di_next_unlinked (+nlink/mode).
  - P83-UNL-REMCHK (xfs_iunlink_remove_inode, instr-gated): in-core vs
    ON-DISK next_unlinked comparison at stitch time; STALE=1 = a peer
    rewired our cached unlinked inode's disk pointer and we are about to
    stitch the shared bucket with the stale in-core value.
  - P83-UNL-RELOAD (xfs_iunlink_reload_next, unconditional multi-node):
    stitch params + AG tenure gen + node slot at the rare reload canary.
  Repro vector: dir_ex_batch_grace_ms=10 + dirent_durability @32/caw
  (2/2 at sess38: mkdir_err=4 then droplink rc=-117 shutdown).

### 0.11.323 board @ 32/caw (sess38 close)
26/27 functional: all green EXCEPT dir_reuse_coherency (5-round lap this time —
the OPEN bimodal pace defect; it was green on the 322 board).  Two mid-board
incidents, both diagnosed:
- rsync_paired FAIL -> test21 SELF-FENCE: P15-REL-ABORT orph=1 livelock starved
  its disklock heartbeat past the lease; peers fenced correctly, slice replayed,
  31/32 unaffected; re-run after prep = PASS 20s.  NEW LEDGER ENTRY
  D-RELABORT-ORPHAN-LOOP-HEARTBEAT-SELFFENCE (10 OPEN now).  Evidence:
  tests/logs/sess38_t21_selffence/.
- crash_consistency NO_TERMINAL_RECORD x32 at its 90s box once (all nodes
  barrier-stuck at kill), re-run PASS 21s — transient, coord-timeout family.
seqW on aged fs measured 1071MiB/s vs 7721 fresh (fio_perf still PASS) — fs
aging effect on sequential allocation, worth a future look.

## sess38 addendum — grace A/B outcome + NEW DEFECT (no version; knob default unchanged)

- dir_ex_batch_grace_ms=10 A/B at 32/caw: cache_coherency 41->25s, crash 79->21s
  (big wait waste removed) BUT dirent_durability FAIL (mkdir_err=4) and on repro
  a FORCED SHUTDOWN on test1: runtime AGI unlinked-list reload
  (xfs_iunlink_reload_next, upstream lazy-unlinked design) fired mid-churn on a
  peer's in-flight unlinked inode; xfs_droplink rc=-117 (dir nlink already 0)
  inside vfs_rmdir -> dirty xfs_trans_cancel -> corruption(0x8) shutdown +
  voluntary withdrawal.  Default STAYS 40 (masks the race); ledgered as
  D-AGI-UNLINKED-CROSSNODE-RECOVERY-SHUTDOWN (9 OPEN).  Evidence preserved:
  tests/logs/sess38_shutdown_g10/.  Mechanism hypothesis for next loop: shared
  AGI bucket's IN-CORE linkage (i_prev_unlinked/i_next_unlinked, cached list
  views) survives across AG-DLM handoffs — a node stitches the bucket with
  stale views after a peer reshaped it.

## 0.11.322 (sess38) — 2026-08-01

- PR-batch admission storm fix (P139 census root, RULE 4 + GPT RULE-5).
  Census on 321: the round wall's tail = SIMULTANEOUS ~900ms PR admission
  storms — a streak-yield ticket names N readers (chosen on ~85% of loop
  reads) but each self-claims ONE CAS at a time (9 nodes x ~22 tries, each
  success invalidating the other 8's compare base; caw_miss=try-1), because
  the release-side P6H-PRBATCH arm requires the releaser to be the LAST
  holder of ANY class.  Plus 364 LOCKTOTAL >800ms whole-acquire events
  (retries=0, ea_*=0) = raw CAW/read service inflation under the same
  storm.  Two fixes:
  - BATCH-COMPLETION-ON-CLAIM (P6H-PRCLAIMBATCH): the first ticket member
    whose claim CAS wins admits EVERY still-registered shared-class sibling
    in the same write; grant mcast wakes them; adopt path is author-
    agnostic; per-reader recovery unchanged (abort-reconcile/lease purge).
  - Release-side batch guard relaxed from !slot_has_holders to no
    EXCLUSIVE-class holders (PR coexists with PR/CR) — the batch now fires
    while sibling shared holders remain.

### 0.11.322 board @ 32/caw (sess38, defaults: grace=40, create_intent_ex=0)
FIRST ALL-GREEN FUNCTIONAL BOARD: 27/27 tests PASS (open_defects gate red by
design, 8 OPEN).  dir_reuse_coherency PASSED IN-BOARD (58/58, 111s) — its 2nd
PASS ever at 32 and first on the batch-claim build; stability laps: PASS 106s,
FAIL 6-rounds/104s => 2/3, defect stays OPEN (zero margin, bimodal pace).
fio 32/32 seqW=7721MiB/s seqR=6487 randW=194k randR=314k iops.  Standalone
probe: idle sync=14-33ms => the 2.5s presync p50 is 32-way concurrent
log-force/flush congestion at the shared target, not a per-op bug.

## 0.11.321 (sess38) — 2026-08-01

- P139 tail census (RULE 4 discriminator for the dir_reuse round-wall root:
  ONE rotating multi-second grant-wait outlier per round — measured 4.70s
  create-EX wait on test28 r=6 while its lookup PR granted in 0.5ms and both
  files created in 10ms each).  Unconditional on ALL nodes, >800ms waits
  only: P139-TAILCENSUS (per wait_for_grant: bit_lost / chosen / foreign_yt
  / free_defer / doze250 / ytd / caw stats) + P139-LOCKTOTAL (whole-acquire
  clock across outer retries: retries + per-CAS-site -EAGAIN census) —
  discriminates queue-position-consumed-by-churn vs claim/adopt latency vs
  bounded-bypass violation vs lost-nudge 250ms dozing vs multi-retry
  re-registration.  GPT RULE-5 consult (full design in sess38 memory)
  prescribes persistent-enrollment + RR-cursor grant discipline; this census
  picks WHICH hole to close first.

## 0.11.320 (sess38) — 2026-08-01

- create_intent_ex default 1 -> 0 (RULE 4 same-build A/B, 32/caw dir_reuse on
  0.11.319: knob-on 6 rounds vs knob-off 7 in the 120s box).  With the sess38
  tag-survival fixes the mechanism is CORRECT (instrumented nodes: rc=-35
  create-path count 0, P-CI-A engaged 52/52, arm-entry cached grant 0/PR/EX =
  24/2/26) but NET-NEGATIVE at 32-node contention: it moves consumer-refresh
  evict + FUA re-read + dir_lookup inside the serialized dir-EX critical
  section (~19ms/create cluster-serialized vs ~15ms legacy), while the
  EDEADLK self-demote it kills is already drain-free (dir_pr_release_fast=1)
  and burst batching comes from dir_ex_tenure_floor + 40ms sliding grace
  either way (P12-DLMTR: burst rides one tenure, release 41.3ms after last
  op = grace expiry, correct).  Residual rc=-35 attribution (test1): root-dir
  mkdir pre-arm walk-PR poison + rm-rf readdir-PR->unlink-EX — rank1-only,
  once-per-round class, not the pace driver.
- tests/drc_straggler_report.sh: per-round per-node phase-span harvest from
  the unconditional DRCph ring markers; names the straggler node + phase
  behind every wrbar/barrier tail (wrbar = straggler wait: local sync
  measured 0.04-0.06s while wrbar ran 2.5-8.3s).

## 0.11.319 (sess38) — 2026-08-01

- CREATEINT tag-survival fix (RULE 4 + RULE 5 GPT design review). 0.11.318's
  instrumented lap showed partial engagement: waves batch, but ~one
  "EX denied EDEADLK rc=-35 -> drop -> drain -> fresh EX" survived per dir
  visit (test1 lap window: 8x ino=128 root + 7x ino=131 drc, all mode=5).
  Three in-window wire-PR leaks poisoned the armed EX, all the same species
  (the CREATEINT bit did not survive every lock_mode computation):
  - A: mxfs_dlm_dir_consumer_refresh's direct xfs_ilock(SHARED) (with
    dir_force_evict=1, on EVERY armed lookup) never consulted the registry.
    Now takes SHARED|CREATEINT when armed; one mode variable feeds both
    lock and unlock so begin/end holder counts mirror.
  - B: xfs_ilock_data_map_shared's need_iread branch overwrote lock_mode
    (SHARED|CREATEINT -> EXCL|PRIREAD), regressing every fresh-adopt
    create-intent lookup to wire PR.  Consult once, tag AFTER base mode.
  - C: mxfs_ilock_map_recheck rebuilt new_mode preserving only PRIREAD,
    dropping CREATEINT across its unlock/relock.  Preserves both bits.
  New exported gate mxfs_createint_dir_armed() is the single consult used
  by every in-window site.  Probes (instr=1): P-CI-A/B/C per-leak lines +
  P-CI-ARM cached_dlm_mode at arm entry (GPT discriminator: in-window PR
  vs pre-arm cached PR from plain path-walk lookups — the latter is NOT
  fixed by this patch and is the next candidate if rc=-35 persists).

## 0.11.318 (sess37) — 2026-08-01 [BUILT, NOT DEPLOYED, NOT TESTED]

- **CREATE-INTENT EX** (knob mxfs.create_intent_ex=1): when the VFS
  lookup carries create intent (LOOKUP_CREATE|LOOKUP_EXCL), the dir
  ILOCK inside xfs_dir_lookup is tagged XFS_ILOCK_MXFS_CREATEINT
  (bit 7, PRIREAD's mirror — upgrades the CLUSTER mode to EX while
  the local lock stays shared; wins over PRIREAD by ordering in both
  xfs_ilock and xfs_iunlock).  Carried by a FIX-26-style task
  registry in xfs_inode.c: xfs_lookup(+create_intent param) arms it
  around consumer_refresh + xfs_dir_lookup only;
  xfs_ilock_data_map_shared consults it once per dir lookup.
  Callers: xfs_vn_lookup/xfs_vn_ci_lookup pass the intent;
  xfs_export dotdot passes false.  Target: the proven per-create
  cycle (lookup-PR CAS storm -> reload -> EX upgrade -EDEADLK ->
  PR drop + drain -> fresh EX).  VERIFICATION PENDING (next
  session): instr window on the dir (expect rc=-35 count -> 0 in
  create windows, PR,PR,PR->EX per wave -> single EX), dir_reuse ×3
  (target >=9 rounds), then full 32-board.

## 0.11.317 (sess37) — 2026-08-01

- **xfs_can_free_eofblocks: local peek, no DLM** — the tail
  ILOCK_SHARED protects an in-core-only read (i_delayed_blks + loaded
  extent tree), but routed through xfs_ilock it paid a FULL DLM wire
  acquire per call — and the reclaim path calls it for EVERY evicted
  inode (mark_reclaimable -> needs_inactive -> here; RULE-4 stack
  capture).  Now takes the raw i_lock rwsem directly (both mxfs hooks
  skipped symmetrically).
- With 314-317 combined, dir_reuse's drop_caches phase (new
  dc-real-done marker): **6.3-8.8s -> 0.10-0.15s**.  Round wall now
  dominated by the create-rotation barrier tail (8-9s; 214 dir-EX
  transitions/round — batch grace not bridging create-loop gaps at
  32-node load), sync (2-3s), rm (3.4s).  dir_reuse still FAIL (7
  rounds vs floor 8) — next levers identified.
- **32-board on 317: 20/21** (dir_reuse the only FAIL — same as
  306/308/313).  cache_coherency 654/654, zero_silent_loss 644/644,
  crash_consistency 204/204, dirent_durability 30r/0 loss.  fio_perf
  improved: seqW 2152->5341 MiB/s, randW 167k->248k iops.

## 0.11.316 (sess37) — 2026-08-01

- **EVICT-RETAIN-PR** (knob mxfs.evict_retain_pr=1): a clean PR DLM
  grant is retained across inode eviction instead of CAS-cleared.
  RULE-4 stack capture (new DCSTK sampler in dir_reuse's dc wait
  loop): barrier-aligned drop_caches had all 32 nodes inside
  caw_slot <- unlock_gen <- v5_dlm_inode_unlock <- mxfs_dlm_evict
  simultaneously clearing PR bits on the SAME hot slots, each unlock
  walking retry backoff toward its 5s deadline — pure waste (verify
  re-acquires the same PR ~100ms later).  Demand-release via the
  proven no-inode BAST path (data durable by definition of clean);
  free boundary safe structurally (free requires EX, which excluded
  foreign PR bits first); unmount handled by release_all sweep; EX/PW
  never retained (orphan-EX class).  P6R-RETAIN print.

## 0.11.315 (sess37) — 2026-08-01

- **PR-CLASS BATCH GRANT** on the streak-yield arm (same
  caw_direct_handoff knob): the release CAS grants the entire PR
  class (holders_pr |= pr_w, waiters cleared, streak reset in-CAS)
  instead of ticketing it for one-by-one claims.  Measured need on
  314: 823 streak yields vs 310 EX handoffs; the class claimed its
  ticket serially (1639 miscompares).  P6H-PRBATCH print.
- **Same-build A/B, 32/caw grant-wait anatomy (8 files/node)**:
  handoff+batch ON = 75 contended grants, 11.1s total wait, max
  255ms; OFF (legacy ticket) = 171 grants, 95.8s, max 2657ms —
  **8.6x, no overlap between arms**.  Creates mean 109ms vs 235ms;
  the 1.4-2.2s PR-behind-unclaimed-ticket shelf is gone.

## 0.11.314 (sess37) — 2026-08-01

- **DIRECT GRANT HANDOFF** (knob mxfs.caw_direct_handoff=1,
  GPT-reviewed ownership-incarnation design): when the releaser is
  the last holder and fair-handoff picks EX waiter W, the release
  CAS itself transfers ownership — holders_ex |= W, W's waiter bits
  cleared, yield_to zeroed, dir_epoch/last_ex_slot/streak updated
  FOR W.  W's poll ADOPTS on sight (new adopt branch in
  caw_wait_for_grant: requires the registration generation floor
  reg_gen, waiter bit cleared, holder bit present; ad_handoff
  derived from slot dir_epoch vs cached grant-meta epoch).  Kills
  both measured costs: the ticket-guard window (86.6% of 81.9s
  total wait was grantable-but-unclaimed) and the winner's claim
  CAW storm (miscompares p95 27 -> 0 for handed-off grants).
  Nudge targets only the winner.
- **Abort reconcile** (caw_drop_own_waiter + giveup_mode): a
  give-up now also clears a grant that LANDED for the abandoned
  acquire (handoff raced the abort, or an ambiguous CAW reported
  miscompare but landed) in the same cleanup CAS — closes the
  sess34 SIGKILL orphan-wire-EX class (P6H-ABORT-RECONCILE).

## 0.11.313 (sess37) — 2026-08-01

- D-DWORK-TEARDOWN-LASTREF-LEAK **class fix** (FIXED AND VERIFIED; the
  310 P6G gate covered 1 of 25 per-inode arm sites).  New bast-arm
  gate: `m_mxfs_arm_lock` + `m_mxfs_arms_off` (xfs_mount.h); ALL 14
  dwork + 11 work per-inode arm sites now route through static
  wrappers `mxfs_bast_arm_queue{,_delayed}()` (xfs_mxfs_dlm.c) whose
  queued-false return means the caller drops the arm's igrab ref —
  the contract every site already implemented for queue collisions.
  put_super: close gate -> pr_sweep cancel + wq flush -> **s_inodes
  sweep**: igrab pin, cancel_work_sync + cancel_delayed_work_sync
  outside all spinlocks, xfs_irele per canceled arm (P204-style
  BADREF guard), iput pin, restart scan (terminates: closed gate
  means pending cannot return).  Breaks the last-ref circular the
  entry flush cannot see (timer-pending dwork -> ref is inode's last
  ref -> evict/P204-cancel unreachable -> timer outlives
  xfs_free_perag -> P142 leak).  Prints P6S-ARMSWEEP / P6S-ARM-
  REFUSED / P6S-SWEEP-BADREF.  Verified: teardown_leak_repro 2
  cycles @8 with real shutdowns — sweep engaged on every surviving
  node's umount (cancels=1 refs=1 ×7), zero P142-LASTREF/P202/BADREF;
  32-board 20/21 (only the pre-existing dir_reuse pace FAIL).
- GPT design review incorporated (mount-level gate lock over
  per-inode latch ordering; sync cancels outside locks; pinned
  traversal; sweep before DLM teardown).

## 0.11.312 (sess37) — 2026-08-01

- **xfs_io -x shutdown was a silent no-op on mxfs** — the whole xfs
  ioctl surface is stubbed (xfs_stubs.c returns ENOTTY), so xfs_io's
  FSGEOMETRY probe fails before it ever sends the shutdown.  Every
  prior scripted "shutdown -f" against mxfs (incl. the sess36
  teardown repro cycles) did nothing.  XFS_IOC_GOINGDOWN is now
  implemented in the xfs_file_ioctl stub (capable + get_user +
  xfs_fs_goingdown; everything else stays ENOTTY by design — MXFS
  ships its own tools).  NEW tests/mxfs_shutdown.sh issues the raw
  ioctl (0x8004587d, flags 2 = -f); teardown_leak_repro.sh switched
  to it.
- Verified live: GOINGDOWN -> "User initiated shutdown received" ->
  P-WITHDRAW voluntary death (peers fence, replay, purge).  Note:
  post-withdraw the device is fenced, so post-shutdown bast drains
  fail imapf/EIO and abort before the release eval — the natural
  P6G teardown strand is a narrow race (shutdown set, unmounting not
  yet, withdraw incomplete), consistent with the single sess36
  capture.

## 0.11.311 (sess37) — 2026-08-01

- TEST-ONLY knob mxfs.rel_stale_inject (default 0): forces the
  stranded (-ESTALE) verdict on inode DLM releases while
  shutdown/unmounting is set, to drive the P6G teardown-era arm
  decision on demand.  (In practice the drain-abort precedes the
  release eval on a fenced device — kept for future strand-path
  work.)

## 0.11.310 (sess36) — 2026-07-31 [boarded via 313's 20/21]

- D-DWORK-TEARDOWN-LASTREF-LEAK fix (knob mxfs.teardown_arm_gate=1,
  0=legacy for A/B): the P6G-REL-STALE stranded-release deferral no
  longer arms the bast dwork when the fs is unmounting, shut down, or
  the DLM ctx is gone (P6G-REL-STALE-TEARDOWN print, no igrab) — the
  arm's ref used to become the inode's LAST ref, so eviction never
  ran, the P204 cancel never engaged, the 4ms timer outlived
  xfs_free_perag and the P142 last-ref guard leaked the inode at
  unload (sess36 live capture, ino 31457413).  put_super's entry
  flush cannot see a timer-pending delayed work; the arm itself must
  not happen in that window.  v5_shutdown's release_all sweep owns
  the on-disk slot regardless.
- NEW tests/teardown_leak_repro.sh: churn + mid-churn xfs_io
  shutdown on half the nodes + teardown + P142/P202/P6G census.
  VERIFICATION PENDING (next session): cycles with gate=0 seeking the
  captured signature, then gate=1 showing TEARDOWN lines and zero
  leaks; then a 32-board regression on 310.

## 0.11.309 (sess36) — 2026-07-31

- PROBE-A transient guard: the AG-META-WRITE-NOT-HELD gate is racy by
  design; a 4/caw soak FAIL traced to the once-per-boot dump_stack
  firing on a SELF-REFUTING sample (gate saw !held mid-transition of
  an AG re-acquire; the print's own payload showed cached=1).  The
  probe now re-reads authority immediately before emitting: a
  transient logs P-A-TRANSIENT (no stack); only a persistently
  unauthorized write earns the crash-shaped artifact.  Soak's kernel
  -log scan is untouched (RULE 6: fix the noise source, not the test).
- MATRIX: caw column fully re-measured this session on 308/309 —
  1/2/4/8/16 all green (16/caw was 1-FAIL on the sess27 0.11.237
  baseline), 32 = 20/21 (dir_reuse pace only).
  dirent_publish_integrity, RED at every multi-node count on 237, is
  GREEN at every count now.

## 0.11.308 (sess36) — 2026-07-31

- TEST-ONLY injector mxfs.bast_qfalse_inject: bast_work_fn self-requeues
  at entry with its own donated ref, holding WORK_STRUCT_PENDING so
  every bast_notify dispatch hits its queue_work-false branch
  deterministically — the GPT-required branch-coverage proof for the
  307 fix.  Measured: 126 forced collisions through the fixed branch
  in one storm, ZERO queue-false leaks (the single residual leak that
  cycle was the distinct P142-DWORK-STALE teardown arm on an
  infra-aborted cycle — split to its own ledger entry).  NEVER ship on.

## 0.11.307 (sess36) — 2026-07-31

- D-UNMOUNT-BUSY-INODES ROOT FIX (kernel-side kprobe ref-trace proven):
  mxfs_dlm_bast_notify's FOUR dispatch sites (immediate,
  none-held-idle, orphan-release, phantom-reconcile) returned WITHOUT
  xfs_irele when queue_work() came back false — but the already-
  pending instance owns only the FIRST donor's ref and ireles once, so
  every collision leaked exactly one inode ref.  Captured live
  (ino 8391890, test10): failed EX acquire (rc=-EDEADLK) honored a
  deferred BAST synchronously -> bast_notify iget -> queue_work
  collided with the already-queued work (P70-BP starts 10us later on a
  kworker) -> P76-QW-FALSE site=immediate -> ref stranded; survives
  unmount with icount=1, dentry_count=0, nothing pending — the exact
  historical signature (varying bastq_src/stale_src across captures
  was last-writer noise; the arms audits were clean because the arms
  ARE clean).  Fix: xfs_irele on the queue-false branch at all four
  sites, mirroring the ilock-end arm's correct pattern; the P76 prints
  now read "extra ref dropped (P226)".  GPT design review passed.
  Tools built for this hunt (RULE 3): tests/refleak_trace.sh (tracefs
  kprobes on igrab/ihold/__iget/iput with BTF offsets, per-node
  streaming), tests/refleak_analyze.py (per-inode running-count
  reconstruction + per-task net balance), tests/census_p.sh.

## 0.11.306 (sess36) — 2026-07-31

- D-RELEASE-BARRIER-OPEN — FIX-A completed: removed the i_dlm_stale
  exemption from the terminal obligation gate (GPT-reviewed; verdict:
  "no legitimate class where the handoff is correct merely because
  dstale is set; safe default for an unexplained open obligation is
  retain-the-grant").  The 305 dss census proved the exemption was
  self-defeating: 459/459 leaked tenure-ends were dss=5 — the release
  pipeline's OWN next-tenure cache-invalidate mark (bast_process,
  xfs_mxfs_dlm.c:14275) — so the gate never fired (P244=0 from birth).
  True nothing-to-land classes remain exempt (ISTALE, dead_incarn_gen,
  dirs, shutdown).  Safety valves verified: defer-retry reload cannot
  consume stale disk state over an open obligation (P184
  reload_oblig_keep guard); strikeout downshifts to 1s and HOLDS the
  tenure — never force-releases past the gate.
- VERIFIED on dir_reuse+crash_consistency @32/caw: P244 defers = 306,
  P241 blind discharges = 0, P220 terminal-store crossings = 0 (all
  realns-window-filtered to the 306 run; the residual counts in raw
  dmesg are 303-305 stale-ring events).  crash_consistency 32/32 PASS
  82s/90s — the added defer latency did not damage the budget.
  dir_reuse_coherency remains pace-FAIL only (D-DIR-REUSE-32-FLAKY).

## 0.11.305 (sess36) — 2026-07-31

- P220 dss= field (i_dlm_stale_src at the ledger-open print) + codes
  for the two unlabeled stale setters (26=reload_identical_keepfork
  xfs_mxfs_dlm.c, 27=file_rw_bail pal/linux/xfs_file.c) + header
  decode for 24/25.  Census result: 459/459 dir_reuse leak events at
  the terminal store carried dss=5 (bast_process_rel) — see 306.

## 0.11.304 (sess35) — 2026-07-31

- P220-EPOCH-LEDGER-OPEN diagnosis fields: dstale= (i_dlm_stale) and
  dinc= (i_mxfs_dead_incarn_gen != 0) — the FIX-A exemption classes.
  First census (dir_reuse 32/caw): EVERY leaked tenure-end at the
  terminal store (epsrc=14925) carries dstale=1 dinc=0 istale=0
  nlink=1 pend>dur (e.g. ino=39846017..19, pend=9/10 dur=2/6/5,
  comm=kworker) — the i_dlm_stale exemption in the FIX-A gate is the
  remaining leak; "dlm_stale has nothing of ours to land" is
  contradicted for at least one stale class.  Next: stale_src census.

## 0.11.303 (sess35) — 2026-07-31

- FIX-A shipped (D-RELEASE-BARRIER-OPEN TOCTOU, Gemini priority-2):
  P244-REL-TERMINAL-DEFER — a LAST obligation gate at the release
  path's terminal store (immediately before i_dlm_mode=NL).  If
  pend != dur there: keep the tenure, set CACHED+bast_pending, re-arm
  the 25ms dwork, wake waiters, return — identical discipline to the
  P236 obligation arm.  Exemptions: dirs (post-NL fence tails),
  ISTALE, dead-incarnation, i_dlm_stale, shutdown.
- Board chunk on 303: cache_coherency, zero_silent_loss,
  crash_consistency (88s/90s) all 32/32 PASS; dir_reuse_coherency
  FAIL (pace only, 7 rounds vs >=8).  P244 fired 0 times while P220
  fired 695x — the leak is NOT the non-dir terminal-store race FIX-A
  covers; epsrc census pinned the bumps at the terminal store with
  the dstale exemption taken (see 304).

## 0.11.302 (sess35) — 2026-07-31

- P138-BAST su split: sw= (drain-end -> unlock entry) and sx= (the wire
  unlock call proper).  First measurement: sx = 12.7-54ms on CLEAN file
  releases during the dir_reuse rm storm — the ENTIRE su tail is inside
  mxfs_v5_dlm_inode_unlock_gen, i.e. shared-target queue time for the
  unlock's read+CAW under aggregate load (TRAP-1 ceiling, documented at
  mxfs_dlm_caw_unlock_gen), not drain work.  Per-handoff floor under
  storm ≈ one release+grant disk round-trip pair at queue depth; the
  remaining reduction is protocol-IO count (ledger next_step:
  reader-state/writer-gate redesign).

## 0.11.301 (sess35) — 2026-07-31

- NUDGE v2 companion — HOPELESS-DEFER (MXFS_CAW_DEFER_POLL_MS=250): a
  waiter whose slot read proves no grant can land until another node's
  release (fair-handoff ticket naming another node, or a foreign EX
  holder) now sleeps 250ms between verification reads instead of the
  2/1..25ms cadence, relying on the targeted v2 nudge for its instant
  wake.  The 2ms-fastpoll/25ms-backoff herd was measured as >1100
  serialized FUA reads/s at the single SCSI target from ~28 excluded
  waiters — the reads THEMSELVES were the 21.6ms/handoff cost.  Stale
  -ticket (5s) and PR-patience clocks tick at the new cadence; a lost
  UDP nudge costs at most 250ms on one handoff.
- RESULT: crash_consistency 32/32 PASS at 71s (budget 90s) after two
  consecutive 90s-budget FAILs; dw+md5 create phases 63-70s -> 47-53s.
  dir_reuse_coherency improved 6 -> 7 rounds vs the >=8 bar (still
  FAIL; residual is the per-release wire-unlock cost, see 302).

## 0.11.300 (sess35) — 2026-07-31

- GRANT NUDGE v2 (Gemini-reviewed design): the UDP nudge now carries
  wake_mask — the node bits that can act on the slot change (fair-
  handoff ticket / PR class / all waiters).  Receivers record the last
  32 nudges in a per-ctx ring (nudge_lock); a blocked acquirer scans
  the ring on wake and skips its FUA slot re-read when every new nudge
  is for another resource or targets other nodes.  Sequence-continuity
  fallback (fell off the ring -> conservative read), v1-sender
  compat (version<2 -> wake-all), EX-promote nudges suppressed
  entirely (nobody grantable), PR-promote nudges target the PR class.
  Poll backstop unchanged (lossless).  On its own this did NOT move
  the convoy (the herd was poll-cadence-driven, not wake-driven) —
  it is the enabler for 301's hopeless-defer.

## 0.11.299 (sess35) — 2026-07-31

- D-CRASH-COLDREAD-STALE-SPLIT / D-INODE-CLUSTER-PUBLISH family —
  FIX-B3 + FIX-C shipped together (Gemini priority-1 verdict):
  - FIX-B3 (merge-mask staging-tenure protection): the cluster merge
    now protects a slot whose LIVE staged image was produced under the
    CURRENT EX tenure (i_mxfs_pub_stage_epoch == i_dlm_epoch, stage
    mode EX, flush != durable) even when the item's dirty_seq predates
    the tenure — verified per-slot against the coherent disk read
    (same di_gen AND platter changecount <= staged changecount).
    P243-CURSTAGE-KEEP traces each engagement.
  - FIX-C (honest ledger on condemnation): the P238 rollback now ALSO
    engages outside RELFLUSH for a same-incarnation condemnation of our
    own strictly-newer state (mode EX, gen == platter gen, iversion >
    platter changecount, not ISTALE) — cls=samegen-own.  Blind
    discharge of that class (P241 CLEAN DETACH capture, ino 58729920)
    left in-core state as the sole copy of acknowledged data.
    Livelock-safe vs the 293 engine: the 293 class had revoked
    authority (gen mismatch) — excluded; and B3 protects the re-staged
    image next push so condemn/rollback cannot recur on the same state.
  - Verification status: 1 board lap zero P239/P241/P238 events (no
    condemnable overlap arose); engagement proof still requires the
    fix26/27 injection laps per the Gemini A/B plan.

## 0.11.298 (sess35) — 2026-07-31

- Classifier round 2 instrumentation (RULE 4) for the P239 population:
  - P239 grew gen=/pgen= (in-core vs platter incarnation — the
    dead-shell discriminator), ds=/gs= (dirty_seq vs ex_grant_seq at
    condemnation), fields= (re-log state deciding self-heal vs
    exposure).
  - P241-BLIND-DISCHARGE: MXFS_IF_CLMERGE_HIT armed at every overlay
    of a slot with an in-flight claim; the buffer-wide iodone
    discharge over a merged-away image now traces, labeled re-logged
    (self-healing) vs CLEAN DETACH (in-core state sole copy).
  - P242-EPOCH-CHURN at all six ex_grant_seq bump sites: fires when a
    bump strands open obligations (flush != durable or dirty item).
- DECISIVE capture, first lap (test21 ino 58729920, 74ms):
  P242 (upgrade site, ds=gs=311, pend=9 > flush=7 — TWO transactions
  committed while NOT holding EX, i.e. post-release ioend conversions
  via the FIX-25 admit) -> P239 (ds=311 gs=312, gen==pgen — same
  incarnation, mask condemned the freshly-staged flush 7->9 image) ->
  P241 blind discharge dur 7->9, CLEAN DETACH.  Companion P220 capture
  same lap: pend=9 dur=5 AT the terminal store 0.4ms after
  iomap_write_unwritten commits under dlm_state=BAST — the P236 gate
  evaluates before the drain-generated conversions land and nothing
  re-checks at the store: the release-pipeline TOCTOU is the leak
  source (FIX-A, Gemini priority-2, queued: in-flight-ioend counter +
  terminal re-check).  This lap self-healed (workload kept writing;
  release drain landed cc=4) — the archived COLDREAD incident is the
  quiescent variant of the same chain.

## 0.11.294 (sess34) — 2026-07-31

- FIX-1 REFINEMENT (RULE 4 — 293's unconditional form was a proven
  livelock engine, caught on its first board): the P238 cluster-merge
  ledger rollback + PUB_SKIPPED re-arm now engages ONLY inside the
  sanctioned-release window (MXFS_IF_DLM_RELFLUSH).  293's first cut
  fired for copy-in-gate/merge-mask authority-gap slots (copy-in allowed,
  mask condemns — revoked provenance/pipe-relog forms), where the overlay
  is the DESIGNED correction: test32 ino 62914705 looped copy-in(6->7) ->
  overlay -> rollback(7->6) -> re-arm -> re-push (50 capped P238, 1926
  P187 in minutes), the immortal dirty item wedged the no-inode release
  fence (P-NOINO-RELFENCE-WEDGE ino=8388746) -> node shutdown -> chunk-6
  cascade (dir_reuse 0/32, integrity pre-asserts, ag_strand 5-node FAIL).
  Void-change slots keep the pre-existing complete-clean resolution.
- 294 full 32/caw knob=0 board green at healthy walls (crash 71s,
  dir_reuse 105s, cache 29s, zsl 31s, dd 65s, fio seqW 10.8GB/s) EXCEPT
  ag_strand_repair 27/32 — ROOTED SAME SESSION as RIG DRIFT, not a
  filesystem defect: test19-23 booted without log_buf_len=16M (256KB
  ring wraps in ~40s → the test's window marker ejected → empty scan →
  strands=0 honest FAIL; same cause as the 292-era 3-of-5 history).
  Grub-fixed + rebooted the 5 nodes; ag_strand_repair now 32/32 PASS
  (strands=1 repaired=1 on the ex-failing nodes) → **294 board FULLY
  GREEN**.  Also: ag_strand rounds now scale with node count (16→T at
  T>16).  Ring-drift blast radius (any dmesg-window scan on 19-23
  silently under-reported; atomic counters unaffected) recorded in
  ccmemory rig-test19-23-log-ring-drift-fixed.

## 0.11.297 (sess34) — 2026-07-31

- P239 classifier fields pcc= (platter slot changecount, from the
  merge's own coherent read) + icc= (in-core iversion): decides per
  event whether an overlay-condemnation protected a peer's newer image
  (true staleness) or reverted our own newer state with no peer writer
  (provenance false-positive from in-core epoch churn — the wire grant
  never left).  Gemini consult #3 ruling: post-P236-gate, mid-tenure
  provenance mismatch should be IMPOSSIBLE absent bugs → the endgame is
  a fatal tripwire, NOT fail-closed copy-in (which would pin the log
  tail); classification must precede enforcement because live authority-
  gap P239s exist (6 on 296-era logs) and a fatal tripwire on a false-
  positive class would shut down healthy nodes.
- Full 32/caw board 24/24 green.  dir_reuse pace-FAIL (7/8 rounds,
  content clean) + dlm_fairness budget-FAIL both PROVEN external host
  load (Wow.exe+worldserver ~7.7 cores); clean PASSes at load <20.
  Injected laps (fix27=25) 2/3 PASS + 1 budget overrun, non-binding;
  no orphan signatures.

## 0.11.296 (sess34) — 2026-07-31

- `mxfs.pub_obligation_enforce` DEFAULT 1 (Gemini consult #2 ruling 2b):
  the release drain's P146V re-log-under-current-tenure arm is the
  principled convergence mechanism for committed changes whose copy-in
  the merge mask condemned — provenance re-stamped through the journal,
  crash-consistent; partners the P236 pre-NL gate (defer) so deferred
  releases land.  Full 32/caw board green (24 criteria, crash 80s,
  dir_reuse 110s).  P176 engagement 0 so far (rare interleave; armed).

## 0.11.295 (sess34) — 2026-07-31

- Instrumentation build (no behavior change; Gemini RULE-5 consult #2
  drove the design):
  P239-OVERLAY-ID: unconditional identity trace at every cluster-merge
    overlay of a slot with an in-flight copy-in claim (flush!=durable) —
    bp pointer, RELFLUSH, dlm_mode, ledger seqs.
  P240-COPYIN-ID: RELFLUSH-gated copy-in identity (ino, bp, seqs) — the
    chain-of-custody pair for P239.
  P-ACQ-STUCK grew myslot= (our claimed disklock slot — slots are
    claimed, not rank-ordered; the sess34 orphan capture could not name
    slot 16's owner).  New P-ACQ-SELF-ORPHAN detector: sole wire holder
    is this node while our own waiter starves (grant with no in-core
    consumer).
- Full 32/caw board green (dlm_fairness 2 budget-FAILs PROVEN external
  host load — Wow.exe+worldserver ~7 cores; PASS 15s/30s at load 17).
- Amplified crash laps (fix27_delay_ms=25, non-binding): 2/2 PASS;
  FIRST P239 capture: ino 8390564 overlay-condemned at flush=7 dur=5
  while EX-held relflush=0 (the authority-gap class), and P240 shows
  THREE different buffer instances for one inode's cluster in 40s —
  instance replacement is routine; the merge/ledger design must not
  assume buffer identity stability.  Gemini ruling for the next
  behavioral increment: fail-closed copy-in (one authority predicate,
  the mask's) + pub_obligation_enforce=1 (re-log under current tenure)
  as the convergence mechanism.

## 0.11.293 (sess34) — 2026-07-31

- D-CRASH-COLDREAD-STALE-SPLIT root chain REVISED from the archived
  incident (P170 slot-cc progression + ledger prints): the overlap/
  out-of-order-landing hypothesis is REFUTED (39 submissions, cc=6 image
  NEVER submitted; zero sema-poisoning hits).  Proven chain: dd's O_SYNC
  append committed via the sub-EX writeback path during the release
  abort/re-entry window (P26PRE, holders census blind to it); the re-
  entered pipeline's durable pass copy-in staged cc=6 (flush 6->11), the
  cluster-merge overlay RESTORED the platter's cc=4 over the staged slot
  (P-CLMERGE restored) withOUT rolling the flush watermark back; the
  next completion discharged durable=flush=11 — ledger BLIND-CLOSED for
  bytes never on the wire; close_or_defer read pend==dur and the wire
  unlock proceeded; 50s later a reload adopted the stale platter (P177
  silent — ledger read closed) destroying the only cc=6 copy.
- Three-part fix (Gemini RULE-5 review: flush-before-demote must be
  structural; dirty-at-NL unrepresentable; evict of an obligated fork is
  the loss finalizer):
  FIX-1 P238-CLMERGE-LEDGER-ROLLBACK: merge overlay of a staged slot
    rolls i_mxfs_pub_flush_seq back + re-arms (P187) so a completion
    cannot discharge merged-away bytes.  (Narrowed in 294.)
  FIX-2 P236-REL-OBLIGATION-DEFER (mxfs.rel_obligation_gate=1): pre-NL
    obligation gate at the bast_process commit point — a non-dir inode
    with pend!=durable defers the release via the existing abort
    machinery (CACHED+bast_pending+25ms dwork re-arm, bastq_src=21),
    keeping tenure/authority for the re-fired drain.  Exempt: dirs
    (their post-NL fence + tails), ISTALE, dead-incarnation, dlm_stale,
    shutdown, entry-NL cleanup flavors.  gate_defer counter in P220
    dump.
  FIX-3 P237-EVICT-OBLIGATION (mxfs.evict_obligation_shutdown=1):
    evict-side tripwire — open ledger at eviction attempts a last-chance
    publish if still EX, else pr_err + force_shutdown rather than silent
    cluster-wide loss of acknowledged data.
- sess34 capture: dir_reuse 0/32 NO_TERMINAL_RECORD wedge = ORPHANED
  WIRE EX (test17 slot 16, ino 34081568, 350s+): the budget SIGKILL
  killed mkdir between winning the wire EX CAS and in-core consume;
  nothing in-core references the grant so no reaper arms (P36-MHT only
  covers in-core state; the abandoned-grant reap P15-TCP-ORPH-PROCEED
  is TCP-only).  Heartbeat keeps stamping the slot (gen climbs, yt/ysm
  frozen) => permanent starvation; local nudge impossible (any access
  queues behind it).  Evidence: tests/logs/sess34_dirreuse_orphan_ex_*.
  This is the sharp mechanism for (at least part of) the dir_reuse-32
  flake / conv-wedge family — CAW needs the abandoned-grant reap.

## 0.11.292 (sess33) — 2026-07-31

- D-CAW-YIELD-STARVATION idle-holder root PROVEN by live intervention and
  FIXED: P36-STRIKEOUT stopped re-arming with bast_pending set, but an
  IDLE holder has no local refire and CAW cannot push a BAST — 4 idle PR
  holders (all post-strikeout, parked 20s+ busy by collision injection)
  starved an EX waiter 23.7 minutes (P-WAIT-EXTEND "holders alive"
  forever); a manual `ls` on one holder granted it in seconds
  (P34-ACQ-SLOW dur_ms=1420998 rc=0). Fix: strikeout DOWNSHIFTS to a 1s
  keep-alive (2500..~4300 strikes ≈ 30min hard cap, P36-STRIKEOUT-SLOW;
  evict still cancels both arms). Same-provocation A/B on 292: 16
  downshifts engaged, contention episodes progressed (gen 141→223), full
  self-recovery after disarm with no manual touch.
- Injection triage: the readdir undercount (117/128 with lookups OK,
  every node) is ICLUSTER-knob=1-ONLY (2/2 vs 0/2 at knob=0 under
  identical injection) — Phase-B campaign blocker, not shipped-product.
- NEW OPEN CRITICAL D-CRASH-COLDREAD-STALE-SPLIT: one crash_consistency
  lap (knob=0, load 35) had observers rank2-6 read IDENTICAL stale
  content for two peer-written files while 27 ranks read fresh; fresh
  mkfs excludes prior-lap content; primary candidate cold-iget of a
  lagging home dinode. 3 immediate repro laps PASS incl. at load 31-36.
  Evidence preserved (tests/logs/sess33_crash_md5_mismatch). Ledgered
  with capture protocol; every future crash lap is a repro attempt.
- 292 knob=0 shipped-config board otherwise green at healthy walls
  (strong 4s, posix 7s, mmap 6s, membership 5s, fairness 15s, fence 20s,
  zsl 21s, cache 27s, dd 66s, dir_reuse 101-112s ×2, crash 27-29s ×3
  after the incident lap).

## 0.11.291 (sess33) — 2026-07-31

- ICLUSTER Phase A (campaign for the D-INODE-CLUSTER-PUBLISH write-unit
  ownership repair, per GPT closure ruling): first knob=1 boards in 274
  builds. GREEN: fairness (ghost-dirent residual GONE), strong, posix,
  cache, mmap, membership, zsl, fence, crash, dir_reuse 106s, dd 65s.
  ONE wedge on 290-knob1 (conv worker + bast worker D in
  folio_wait_writeback inside bast_process; call chain not captured) →
  291 extends the P152 trans-free punt to ioend/writepages contexts
  (why=ioend-ctx, bastq_src=17) — armed, ZERO engagements since, so the
  wedge root is NOT yet attributed; full-stack capture protocol recorded
  for recurrence. One dd 240s-at-box outlier under load 15-19 with zero
  hung-task warns (distributed slowness, watching). icluster_dlm remains
  default 0; campaign continues.

## 0.11.287-290 (sess33) — 2026-07-31

- P234-LOG-NOEX source counter (GPT closure criterion 3, "dirty-at-NL"
  generalized): at the pend++ stamp in xfs_trans_log_inode, count every
  publication obligation created without cluster authority; buckets
  lognoex_nl / lognoex_pr in the P220 dump. .287 first data: pr=0, nl only
  from the pipeline's own P146V/P182 re-log arms → .288 gates those via
  i_mxfs_pipe_relog → STRICT ZERO on dd+zsl. .289's full board then fired
  it 2-24/node — attributed (RULE 4) to the FIX-25/26/27 nested ioend/
  writeback admissions, which legitimately mutate while drain site 2 has
  already cleared i_dlm_mode to NL but the on-disk mirror grant is still
  ours (their ex_holders census pins the wire grant; P15 aborts + re-arms
  the release, so every such commit drains before handoff). .290 fixes the
  SENSOR: authorized = mode EX || i_dlm_ex_holders>0 || pipe_relog —
  STRICT ZERO across posix+mmap+strong+zsl+crash+dd. True bypasses
  (atomic ilock_try, ILOCK-nowait) inc neither and stay caught.
- INODEGC/ORPHAN AUTHORITY CLASS: VERIFIED covered, no new machinery
  needed. Audit: multinode inactivation is SYNCHRONOUS at final iput (P25
  path, adopted v0.3.59 for the AGI-recycle race) → xfs_inactive →
  xfs_ilock(EXCL) → full DLM admission = GPT's reacquire-before-dirty,
  structurally; the deferred worker survives only the nested-AGI case and
  re-admits identically; ISTALE inodes cannot create core obligations
  (asserted in trans_log_inode). Measurement: the P234 tripwire above.
- EX-SIDE EPOCH GATE (.289, GPT condition 4, knob mxfs.stale_stage_skip_ex
  DEFAULT ON): holding EX now is not authority for bytes staged under a
  dead tenure — the reacquire reconciled the in-core inode, not the frozen
  pre-yield cluster-buffer image; publishing it can revert a peer's
  inter-tenure commit, and skipping is always safe at EX (equal bytes →
  no-op restage; differing → corruption prevented). PUB_SKIPPED set
  UNCONDITIONALLY (the P187 iodone re-arm restages current state under the
  live grant — retry succeeds at EX, unlike NL); ISTALE/ifree slots
  EXCLUDED (class-X: the freed-state write keeps publishing under the live
  ifree tenure); rf/dem submit contexts counted (stale_ex) never skipped;
  unlanded skips roll the flush watermark back (P56 treatment). New
  counters stale_ex / sskip_ex / sskip_ex_unl in the P219 dump. Validated:
  full 11-criterion board green at unchanged walls (dd 65-66s, dir_reuse
  112s, cache 28s, crash 72-73s); numerator ~1/node/board, skips fired
  exactly where eligible, sskip_ex_unl=0 (all skips were landed
  byte-redundant images). Pre-289 builds are the de-facto publish control.

## 0.11.286 (sess33) — 2026-07-31

- WRITER-QUIESCENCE admission barrier (the convergent close the .282/.283
  attempts aimed at): new atomic_t i_mxfs_ilk_wr_held census of outstanding
  ILOCK_EXCL holds — inc open-coded post-acquisition in xfs_ilock +
  xfs_ilock_nowait ONLY (the raw forensic note_lock callers stay uncounted:
  their releases bypass note_unlock, counting them would leak the census up
  and permanently disable the barrier), dec in mxfs_ilk_note_unlock (both
  callers release xfs_ilock-taken locks), demote adjusts, WARN_ON_ONCE on
  underflow/double-hold. mxfs_relbar_close_or_defer waits (one shared ~40ms
  budget, conditional before EACH durable pass — GPT-reviewed design) for
  census 0 instead of trylocking the rwsem: readers never waited on, never
  blocked (no .282 convoy possible by construction); pend++ is stamped under
  local ILOCK_EXCL and CIL insert completes before the holder's fully-ordered
  dec, so census 0 = everything finished is log_force-capturable — including
  the DLM-uncounted mutator classes the P15 ex_holders gate cannot see.
  Census 0 is an observation, not a stable state (down_write-queued writers
  have not inc'd); defer/requeue stays the safety backstop. Knob
  mxfs.relbar_wrq (1=census wait default, 0=legacy .283 trylock arm).
- Validated: full 11-criterion board + 2 extra aged-mount hot-dir rotations,
  all PASS at healthy walls (dd 64-66s, dir_reuse 110-112s, cache 22-28s,
  crash 71s, zsl 30s); WARN=0 on 8 sampled nodes; obligation=0 at all ~232k
  fleet unlocks; deferred=0 the whole batch (vs 6-119 on .276-283 batches)
  while epoch_obligation grew 30→93-115/node — mid-tenure opens keep
  happening and now all close by unlock time. Enforce engaged once:
  wrq_ok=1, closed in place, wrq_tmo=0. Exposure caveat recorded: the
  unlock-time-open regime (10-41/lap, intermittent) did not recur in 6 laps,
  so the convergence win is 1/1 not N/N; a legacy-arm control lap under zero
  engagement is byte-identical by construction and was skipped. .285's
  pending dd validation also cleared this session (PASS 65s quiet-host).

## 0.11.284-285 (sess32) — 2026-07-31

- P229/P230 probes: mxfs_dlm_ilock_try's preempt_count()>0 arm bypasses the
  DLM entirely (no DEMOTING gate, no holder count — and ilock_end's
  unconditional decrement would eat a concurrent holder's count for an EX
  bypass). MEASURED ZERO firings on the 32-node producer. .285 refuses EX in
  that arm anyway (nowait callers fall back to blocking xfs_ilock = full DLM
  path); PR keeps the bypass + a log-under-bypass tripwire
  (i_mxfs_atomic_bypass_ns, cleared at ilock_end).
- .285 dd validation pending: first lap failed 5/32 NO_TERMINAL_RECORD=27
  under external host load (game server at 350%+ CPU on clyde; P229=0 on
  that board proves the change never ran; cache_coherency passed 27s in the
  same window). Re-validate on a quiet host.

## 0.11.282-283 (sess32) — 2026-07-31

- Admission barrier in mxfs_relbar_close_or_defer: .282's unconditional
  down_write(&i_lock) CONVOYED behind readdir's long ILOCK_SHARED holds
  (dirent_durability 240s/240s, 4x wall — RULE 0 fail) and was replaced in
  .283 by a <=40ms down_write_trylock loop (timeout = safe pre-barrier defer
  behavior). Measured: the trylock rarely wins on a hot dir (closed=7 vs
  deferred=119 over 227k unlocks) — defers stay safe/bounded at healthy
  walls, but the convergent close still needs the full admission interlock
  (ilock_begin-side gate), queued.
- INCIDENT (recorded in ledger, unattributed): one aged-mount batch on .283
  failed dir_reuse 0/32 + cache_coherency 652/654 (its first check failure);
  3 identical aging sequences + fresh pair all green after. 1/4 rate.

## 0.11.281 (sess32) — 2026-07-31

- relbar enforcement extended to BOTH wire-unlock arms: the inline anchored
  block refactored into mxfs_relbar_close_or_defer(ip, arm) and wired into
  the noanchor unconditional-unlock path too (defers via its existing
  stranded re-arm). P228 print now carries arm=.

## 0.11.280 (sess32) — 2026-07-31

- mxfs.relbar_enforce DEFAULT ON. Same-build A/B: enforce=0 leaked 10-12
  open-ledger wire unlocks per lap (typed: shared parent dirs re-committed
  in the durable-flush->unlock window); enforce=1 leaked ZERO across 3
  dirent_durability laps + the guard board (cache 28s, crash 69s, dir_reuse
  101s, dd 64-66s — no pace cost), with 6/26551 (0.02%) bounded deferrals
  (P228, all in-window recommits of two base dirs; requeue landed them).
  First enforcement increment of released=>landed; anchored arm only.

## 0.11.275-279 (sess32) — 2026-07-31

- D-RELEASE-BARRIER-OPEN: the LEDGER predicate (pending!=durable) added to
  both release-tail checks and every tenure-end site — fires 10-41/lap where
  the old IFLUSHING predicate reads 0 (blindness proven). Typed via new
  identity fields: epoch-site events are transient child dirs (closed by the
  later pipeline flush); the WIRE-UNLOCK events (10-12/8234 unlocks) are
  shared parent dirs whose durable flush RAN and that were re-committed in
  the flush->unlock window (the admission-not-closed case). P176 fired 0
  (bypassed); P56/P187 rollbacks uncorrelated (refuted); restamp-at-attach
  refuted by source (ifree binvals the buffer; stamps are honest).
- NEW ENFORCEMENT (mxfs.relbar_enforce, default 0 pending A/B): at the
  anchored wire unlock, an open ledger triggers up to 2 in-place durable
  passes (dir/non-dir variants); if it still will not close the wire unlock
  is DEFERRED via the proven -ESTALE requeue (P228-RELBAR-DEFER) instead of
  handing the grant away with the obligation open. Counters closed/deferred
  in P220-RELEASE-BARRIER-TOTAL.
- P222 print now carries stage_mode/ili fields/pending/durable (root-fix
  forensics); P224 unlanded fail-closed shipped in .273.

## 0.11.274 (sess32) — 2026-07-31

- Mount-time arm of D-FOREIGN-REPLAY-UNGATED-IMAGES: a PASS-2 (fresh)
  disklock claim now marks the inherited log slice ADOPTED
  (disklock ctx -> v5 -> mp -> XLOG_MXFS_ADOPTED_SLICE), and mount recovery
  suppresses untagged buf/dquot/quotaoff/icreate images AND the dead
  incarnation's intents (P223 with src=adopted, P226-UNTRUSTED-INTENT-SKIP)
  while inode records use the di_changecount gate
  (xlog_is_mxfs_untrusted_replay). PASS-1 own-stamp reclaim keeps full
  recovery (own-crash path: grants still quarantined, replay required).
  Knob mxfs.adopted_slice_full_replay=1 restores legacy full replay for A/B.
  Closes the rejoin/claim hole where a returning or joining node re-applied
  an already-recovered slice's images against survivor-updated blocks via
  the meaningless cross-slice LSN compare.

## 0.11.273 (sess32) — 2026-07-31

- NEW CRITICAL DEFECT RECORDED + CONTAINED: D-FOREIGN-REPLAY-UNGATED-IMAGES.
  Foreign/adopted slice replay applied buf/dquot/quotaoff/icreate image
  records gated only by cross-slice XFS_LSN_CMP, which is meaningless
  (per-node slices number LSNs independently — the sb-LSN check already
  admits this). Containment (GPT-ruled stop-ship): live foreign replay now
  SKIPS untagged non-inode image records (P223-FR-UNTAGGED-SKIP, counted);
  inode records keep their node-independent di_changecount gate. Knob
  mxfs.foreign_replay_untagged_apply=1 restores legacy apply for A/B only.
  Full fix (authority tokens + durable held-set manifest + IMAGE_REPLAY_DONE
  marker) queued; mount-time adopted-slice suppression next.
- P222 unlanded arm now FAILS CLOSED (GPT condition-1): a committed change
  unlanded under a dead tenure at NL triggers P224-UNLANDED-STALE-FATAL +
  xfs_force_shutdown (-> lease loss -> peer fence -> journal recovery), never
  a silent publish/drop/livelock. Never observed (sskip_unlanded=0 ever).
  mxfs.stale_stage_unlanded_shutdown=0 restores count-and-skip for A/B.

## 0.11.272 (sess32) — 2026-07-31

- mxfs.stale_stage_skip DEFAULT ON. Paired laps on one 0.11.271 module load:
  skip=0 baseline put 2 dead-tenure NL images on the wire; every skip=1 lap
  masked 100% of detections (cumulative sskip_landed=36, sskip_unlanded=0,
  wire writes of the class = 0) with the guard board green at healthy walls
  (cache_coherency 26s, dir_reuse 110s, crash_consistency 24s,
  dirent_publish_integrity PASS unlanded_at_unlock=0, dirent_durability
  64-66s x4). Authority-merge check: 0 passenger writes, 0 in-window P219,
  582 passenger slots dropped by the shipped sess29 fix. 0=pre-fix control.

## 0.11.271 (sess31) — 2026-07-31

- D-RELEASE-BARRIER-OPEN containment (DEFAULT OFF, mxfs.stale_stage_skip):
  P222-STALE-STAGE-SKIP masks dead-tenure staged inode images out of home
  writes in the cluster masking loop (P56-mirroring bookkeeping: landed
  images skip losslessly; unlanded roll the watermark back and count LOUDLY,
  re-arm only via the existing pub_skip_rearm lever). First cut of the
  GPT-ruled program; A/B pending next session (deploy + skip=0/1 laps,
  acceptance stale_nl-writes -> 0 with green board + authority-merge
  divergence=0).

## 0.11.270 (sess31) — 2026-07-31

- P219 sharpening: torn-stamp fix (epoch double-read around the mode read in
  xfs_iflush), stale_nl counter (stale && submit-at-NL = the corruption-capable
  class), bflags= in the P219 print. Findings: class X = ORPHAN inode images
  really written at NL (no XBF_STALE); class Z = shared-parent dir submitted
  mid-EX with multi-epoch-old bytes (drain-covered for now). Fix design queued.

## 0.11.268-269 (sess31, ccloop c7ee71c6) — 2026-07-31

- D-CAW-YIELD-STARVATION-SHUTDOWN (NEW critical, ROOT PROVEN, FIX SHIPPED):
  compatible-yield fresh INODE acquires never registered in slot->waiters, so
  release tickets (yield_to = waiters) never named them; under sustained
  shared-dir handoff they burned all 100 CAW retries (P-CAWEXH yield_bo=100),
  got -ETIMEDOUT, and mxfs_dlm_ilock_begin force-shut-down the FS — 10 of 32
  nodes died within 1.8s in dirent_durability@ 32/caw. Fix (GPT-reviewed):
  mxfs.caw_fresh_register=1 (register-on-first-deferral; claim CAS clears
  waiter bits + recomputes waiter_mode atomically, also draining ghost bits)
  + mxfs.caw_fresh_yield_bound=16 (bounded courtesy, P221-YIELD-BOUND).
  P-CAWEXH now prints yreg=/ybypass= (doubles as a 269+ line marker).
- P219-LOGGED-NO-AUTHORITY print: fixed %s-vs-integer format bug (missing
  stage_ns=%llu) that made EVERY fire dereference a timestamp as char* and
  PANIC the node from xfsaild context — the mechanism behind several
  "no visible error" node deaths (serial logs are root-only; sudo required).
  First 13 surviving captures recorded: all stale=1 epsrc=14516, including
  freed-inode images written at NL (see OPEN_DEFECTS D-RELEASE-BARRIER-OPEN).
- New harnesses: tests/ysr_dd_ab.sh (per-arm dirent_durability lap with scoped
  exhaustion harvest), tests/yield_starvation_repro.sh (synthetic PR/EX storm).

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

## 0.11.374-376 (sess47, 2026-08-02)
- 374: RULE-4 probes naming every exit of xfs_iunlink_remove_inode
  (P-UNLREM-INCOMPLETE/-NOPREV/-LOGSELF/-BACKREF); deterministic repro
  tests/reap_midlist_repro.sh REPRODUCED D-REAP-IFREE-EFSCORRUPTED-SHUTDOWN-372
  first run (40s): reap-after-reclaim mid-list remove with prev=0 ->
  silent -EFSCORRUPTED -> ifree -117 -> shutdown.
- 375: FIX (GPT-hardened design): mxfs_ifree_unlinked_preflight — pre-ifree
  slot-bucket walk rebuilding chain state + NONBLOCKING predecessor pin
  (igrab live / iget-recycle reclaimable / -EAGAIN mid-evict = clean skip,
  zombie durable, reap retries).  Pin released after AG DLM drop.  Verified:
  repro 374=REPRODUCED -> 375=CLEAN both scenarios (fresh-iget + igrab pin
  arms), openunlink_matrix 9/9 x2, 2 clean aged lap->matrix cycles.
  D-REAP-IFREE-...-372 FIXED AND VERIFIED.
- 376: rsync-rename producer NEW SIGNATURE decoded (aged cycle 3): fossil
  di_next_unlinked (P53-IUNLINK-MISMATCH old_ptr=chain fossil, dip_gen
  current) -> 0x8 shutdown at iunlink precommit; 2 sibling events absorbed
  by P53-IDEMPOTENT (sess53 masking warning confirmed).  P143 agmeta
  time-travel fence gap: xfs_inode_buf_ops unfenced.  Report-only probes:
  pag_mxfs_inocl_wr_epoch stamp + P-INOCL-COLDREAD (cold cluster read
  inside unflushed write window).  Ring banked:
  test2:/root/transcommit_incore_1785706689.dmesg.
