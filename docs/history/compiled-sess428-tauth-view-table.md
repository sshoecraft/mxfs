<!-- sess428: D-0351 free-publish regression root+fix (0.38.1-0.38.3), D-0349 GPT ruling to durable view-table+barrier, 4-pass RULE-5 review to GO on step… -->
# sess428: tauth view-table/barrier design + D-0351/D-0349 build chain

Single session (2026-08-28), two interleaved threads: (1) the D-0351
free-publish foreign-misclassification regression found and fixed through
0.38.1→0.38.3, and (2) the D-0349 durable-authority redesign — GPT-ruled
down to a VIEW TABLE + 2-phase barrier — spec'd through four RULE-5 passes
to a GO on build step 1.

## Thread 1: D-0351 build chain (0.37.0 → 0.38.3)

- 12:56:39Z — s430 chain DONE: 32/caw board on 0.37.0 all-pass (25 PASS, 3
  FLAKY-but-pass, node_death_replay shared/single PASS 309/470s).
  `docs/history/docs/history/docs/history/compiled-sess428-tauth-view-table.md`
- w038 (0.38.1 = D-0351 fix + D-0348 step2) needed two more compile fixes
  (forward decl of static `mxfs_p87_read_home_dinode`; new
  `read_random_bytes()` helper in `tools/mkfs_mxfs.c` for the tauth seed
  draw). Out-of-tree build clean (sv 40ACA9DE), ported to tree ~12:59Z.
  Code review confirmed: FREE entry always created on `xfs_iunlink_remove`
  success; `pag_dlm_lock` is a mutex so sleeping inside
  `mxfs_ag_handoff_commit` is legal; every post-pubwrite-gate exit in
  `xfs_iflush` goes through `flush_out`; only `return -EAGAIN` is the
  DENIED path before the gate.
  `docs/history/docs/history/docs/history/compiled-sess428-tauth-view-table.md`
- `tests/sess427_chain.sh s431` launched (setsid, ~5600s budget) to verify
  D-0351 via dre stages (P55C-FREE-FLUSH / P-FREEOB-PUBLISHED present,
  freeob_bad=0, shutdowns=0).
  `docs/history/docs/history/docs/history/compiled-sess428-tauth-view-table.md`
- **0.38.1 board regression, root proven**: s431 board collapsed
  (cache_coherency 0/32, BUDGET_EXHAUSTED; mmap_coherency FAIL; 14
  blocked). Root: two defects in the D-0351 code.
  1. `i_generation` is random at allocation (`xfs_inode.c:2227`,
     `xfs_icache.c:2224`) and only incremented at free
     (`xfs_inode_util.c:1495`). A short-lived incarnation whose live
     image never reached the platter leaves `mode=0` at the
     *pre-allocation* gen, so the classifier's `mode==0 && gen==ogen`
     "home" test fails and misclassifies it FOREIGN
     (`P55C-FREE-FOREIGN`, 51 hits, all `disk_mode=00`). Correct rule:
     `mode==0` at ANY gen = published. Fixed at 3 sites (xfs_iflush
     P55C, audit FREE branch, recovery worker).
  2. The FOREIGN branch stamps `i_mxfs_dead_incarn_gen` on the freed
     shell, but `xfs_iget_recycle` never clears it — a legitimate local
     re-allocation on that shell inherits the write-poison and
     `P32D-DEADINCARN-SKIP` refuses every flush of the new file. Fix:
     clear the stamp on the recycle-create path once the platter verdict
     is known.
  `docs/history/docs/history/docs/history/compiled-sess428-tauth-view-table.md`
- 13:50Z — 0.38.2 in tree (unbuilt): added
  `mxfs_tauth_ledger_prepare_unowned` (UNOWNED→PREPARED(target) in one
  CAW write, used by the bootstrap node's FREEZE_REQ handler) and
  `handoff_parked` stat. The eager per-page activation pass (built this
  session for D-0349, see Thread 2) was measured harmful — w038 tauth3/4
  showed formation_test 2 then 9 fails; isolation run with eager off = all
  PASS — and was refuted and removed. s431 dre1/dre2 (0.38.1, before the
  regression fix) showed P55C-FREE-FLUSH 39/70, freeob_bad=0, shutdowns=0,
  zero P-CR62/CR3-CANCEL/ESTALE: first evidence the D-0351 mechanism
  engages and the peer shutdown does not recur. The dre rc=1 traced to a
  harness bug (shutdown check ran before the dmesg pull) plus legitimate
  `rm -rf`/`mkdir` races between peers — both fixed in
  `tests/dir_recreate_estale.sh` (also now asserts zero FREE-PUBLISH
  violation lines per node).
  `docs/history/docs/history/docs/history/compiled-sess428-tauth-view-table.md`
- 14:00Z — 0.38.3 in tree (unbuilt; w038 sv 51B907995EABF9B113024F1 clean):
  the two 0.38.1-board-regression fixes above (mode-0 classification at 3
  sites + recycle dead-stamp clear). `docs/free-publish.md` updated.
  `tests/sess428_chain.sh <label> [waitlog]` added: waits (≤1800s) for
  `^DONE` in the s431 log, then build+proof → tauth → prep caw → dre×2
  (fixed harness) → board → sweeps with verdict counters. Launched as
  `s432` (`tests/evidence/sess428_s432.log`).
  `docs/history/docs/history/docs/history/compiled-sess428-tauth-view-table.md`
- ~14:20Z checkpoint — s431 confirmed DONE 13:29Z; s432 built 0.38.3 in
  tree (same sv), proof OK, tauth usermode all PASS, prep/dre/board in
  progress. PASS bar for the D-0351 second lap: sweep
  `foreign_mode0=0, deadskip=0, shutdowns=0, freeob_bad=0`; board all-pass
  with `cache_coherency 32/32` (0.38.1 had 0/32).
  `docs/history/docs/history/docs/history/compiled-sess428-tauth-view-table.md`

## Thread 2: D-0349 redesign (durable authority under format-v2 geometry)

Motivating facts given to GPT: v2 ledger = 67,651 pages (31 rec/page), a
per-page durable authority header; any per-page handoff on a view change is
O(pages) writes; lazy first-touch costs ≥100ms × ~5000 pages for the
workload; requirement is ≤6s (2× native) for the 4-node small-file
workload; eager per-page activation was motivated by 1092
`P-TAUTH-REMASTER-PARKED` hits on 1083 distinct pages in the s430 token
sweep (first-touch parking at 100ms retry cadence).

- **GPT ruling — eager page activation**
  (`docs/rulings/d0349-eager-page-activation.md`):
  - Formation flood: option (c) accepted — the exclusively-fenced
    bootstrap node does `UNOWNED → PREPARED(target, target_inc)` in ONE
    durable CAW transition comparing the complete expected UNOWNED image
    incl. seq; D-0347 fencing guarantee retained; stale bootstrap op
    harmless after a generation change. Option (b) (each node claims its
    own UNOWNED pages) REFUSED — under false death the wrongly-surviving
    node could win the race first. Lowering per-tick alone does not fix
    the serialization bottleneck; the real fix (bootstrap-side bounded
    deduplicated queue keyed by (page, generation), accepted/pending
    reply, rate from completed durable I/O, demand prioritized over
    eager, durable ops outside the TCP handler/tick) is NOT yet landed
    (stage B, owed). Until then: 2/tick/node temporary safeguard, not 16.
  - Concurrency: one shared per-page acquisition object (not a distinct
    durable eager state); eager and request callers join the same
    in-flight op instead of each sending FREEZE_REQ; the tick only
    enqueues, never blocks on acquire.
  - Keep the settle gate; every acquisition generation-bound, obsolete
    completions never satisfy current waiters.
  - Track `eager_required_gen` / `eager_completed_gen` (not a bool) to
    avoid a lost wakeup vs a mid-pass membership change; publish
    completed=G only under a full set of preconditions; per-generation
    scan cursor.
  - What landed (stage A, in w038→tree, 0.38.2): `prepare_unowned`, eager
    pass with required/completed gen + cursor, knob
    `mxfs.tauth_eager_per_tick` (default 2), stats in
    `P-TAUTH-DLM-STATS` + `P-TAUTH-EAGER` line per productive pass.

- **GPT ruling — view-table barrier design**
  (`docs/rulings/d0349-view-table-barrier-design.md`):
  four options evaluated (A page-group authority, B durable view table +
  barrier, C claim-on-first-grant, D wake-on-FROZEN). **B is the target**:
  a durable VIEW TABLE (range→owner incarnation per table generation),
  double-buffered slots + CAW-switched ROOT pointer, with a 2-phase
  barrier on membership change — PREPARE(Gnew,Gold,digest,moved_ranges,
  memb_digest,coord_term) → each node verifies Gold current, freezes new
  requests on moved ranges, cancels/finishes old-routed queued requests,
  blocks new old-gen commits, waits admitted old-gen commits
  durable/failed, persists the promise, ACKs exact digest → coordinator
  CAW-commits root → nodes validate, new owners open admission, requesters
  reroute. A missing ACK is NEVER converted by timeout — the node must
  return or be removed+storage-fenced+ranges recovered. Coordinator death:
  successor reads root and either aborts/unfreezes (Gold) or finishes
  dissemination without rollback (Gnew), or stops on ambiguity. A (page-
  group authority) is a legitimate bounded interim ONLY as real group
  authority, not the endpoint. C (claim-on-first-grant) does not hold
  under false death unless claim+first-grant is one CAW vs an exact fresh
  UNOWNED image and takeover of foreign ACTIVE needs ordered handoff or
  confirmed storage fence — not selected. D fixes a polling artifact only.

- **RULE-5 spec review chain** on `docs/tauth-view-table.md` (the write-up
  of design B above), four passes to GO:
  - **v1 review**
    (`docs/history/docs/history/docs/history/compiled-sess428-tauth-view-table.md`):
    2 outright refusals — (1) removed members can't ACK because they're
    fenced/dead (fix: ACK from surviving+admitted+reachable-voluntary
    members, DURABLE FENCE-AND-RECOVERY CERTIFICATE substitutes for
    unreachable removed incarnations); (2) stale/concurrent coordinators
    can both CAW-write the same inactive slot before either commits the
    root (fix: single storage writer before any slot write — fence the
    previous coordinator, exclusive coordinator PR/token, durable ROOT
    BALLOT `{coord_node,inc,term}` by full-block CAW before any slot
    write). Plus 18 more findings covering: root-bound monotonic
    coord_term; page ownership = `{node,inc}` tuple; immutable recovery
    manifest/certificate bound into the committed view; SHA-256/BLAKE2s
    (not fnv1a-64) for proposal identity; proposal identity keyed on
    `{prev_gen,prev_digest,proposed_gen,proposed_digest,ballot}`; full
    drain-linearization discipline; `imported_gen` kept separate from
    on-disk `config_epoch`; certified membership epoch+digest bound into
    proposals; slot-then-root write ordering with full-block root CAW;
    storage-fencing on coordinator takeover; root always wins on
    COMMITTED/ABORT/conflict; first-view cutover is one atomic migration
    (v3 = reformat, destroys legacy grants); worst-case ownership-churn
    measurement flagged (rendezvous hashing if drain/import burst >6s).
  - **v2 review** — NO-GO for build step 1
    (`docs/history/docs/history/docs/history/compiled-sess428-tauth-view-table.md`):
    blocking items were manifest publication/lifetime (unresolved), root
    nonce + ambiguous-CAW re-read rule (unresolved — after ANY ambiguous
    CAW, re-read and validate the root, never retry with the old expected
    image), and the byte-level format not yet frozen (unresolved).
    Non-blocking for step 1 but must close before their consuming steps:
    membership-vs-commit race, ballot-reuse rejection, PR-takeover
    in-flight I/O termination, HRW identity on a stable placement id (not
    incarnation).
  - **v3 (pass 3)** — accepted R1 (embedded certs), R2 (lock-held
    membership revalidation pre-CAW), R4 (FENCED+verified reservation+
    drained I/O before token transfer), root-without-separate-manifest-
    binding
    (`docs/history/docs/history/docs/history/compiled-sess428-tauth-view-table.md`).
    Froze into `docs/tauth-view-table.md`: R5 (ambiguous-CAW retry uses
    the unchanged old root as compare image, never reuses a failed
    proposed image/nonce, §12); R3 (PREPARE/ABORT only at the validated
    root's exact `{coord_node,coord_inc,ballot}`, ballot = root.ballot+1
    by CAW, UINT64_MAX fails validation, §5); R6 (exact magics, SHA
    domain tag "MXFS-TAUTH-VIEW1", CRC32C Castagnoli params, root payload
    exactly 512B with pad_end@504, real test vectors w/ digests, §13.1-2);
    R7 (exact SplitMix64 HRW finalizer with check values, §3.1).
  - **v3 checkpoint** — full freeze recorded
    (`docs/history/docs/history/docs/history/compiled-sess428-tauth-view-table.md`): §11
    manifest binding = embedded certificate essentials (no rman slot
    pinning), §12 128-bit nonce `{writer_inc,seq}` + ambiguous-CAW re-read
    rule, §13 frozen little-endian layouts for `mxfs_tauth_view` (4096B:
    members@176, removed[32]@1200, SHA-256@4024, crc32c@4088) and
    `mxfs_tauth_root` (512B: slot/gen/digest/ballot/nonce, crc@500),
    validation rules, §3.1 HRW over heartbeat slot, §5 root-monotonic
    ballots + PREEMPT-AND-ABORT/FENCED precondition, §7 pre-commit
    membership revalidation.
  - **Pass 5 — GO for build step 1**
    (`docs/history/docs/history/docs/history/compiled-sess428-tauth-view-table.md`): cleared
    after R3 (allocator refuses at `root.ballot >= UINT64_MAX-1`, never
    CAWs UINT64_MAX, on-media UINT64_MAX = validation failure) and R6
    (half-open CRC ranges `[0,4088)`/`[0,500)`, stored CRC outside its own
    range, reserved/pad bytes zero-validated, root pad_end `[504,512)` and
    4Kn tail `[512,4096)` protected by zero validation only). Step-1
    scope: `MXFS_TAUTH_CTRL_PAGES=3` region v3 (PROTO_GEN 10), the two
    structs exactly per §13(+13.1), SHA-256 in the PAL (kernel
    `crypto/sha2.h`; usermode `dlm/sha256.c`), mkfs writes root
    `{gen 0, slot 0xffff, ballot 0, nonce {0,1}}` + zero slots, chk
    decodes/validates root+slots, `tests/tauth/view_format_test.c`
    against `tests/tauth/vectors/{view_v1,root_v1}.bin`. Step-1 tests
    must additionally assert the UINT64_MAX-1 refusal performs no
    CAW/media modification, and the UINT64_MAX rejection uses an
    otherwise integrity-valid image. Steps 2-5 (barrier protocol itself)
    still need their own reviews at step 3.

## State at session end

Tree at 0.38.3 (unbuilt at write time of the earliest checkpoints, built
and running by s432). D-0351 second-lap verification (s432) in progress
against the `foreign_mode0=0, deadskip=0, shutdowns=0, freeob_bad=0` +
`cache_coherency 32/32` bar. D-0349 ledger holds the s431 token
measurement; design frozen at v3/GO for build step 1 of the durable
view-table/barrier redesign; steps 2-5 (the barrier protocol) not yet
implemented or reviewed. D-0352 (formation flake) untouched this session.
