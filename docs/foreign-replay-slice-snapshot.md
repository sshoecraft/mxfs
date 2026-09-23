# Foreign-replay slice snapshot & stabilization (D-527, 0.27.0)

## Defect this exists for

`D-FOREIGN-REPLAY-UNSTABLE-SLICE-READ-FALSE-TORN-527` (sess409 slot 12,
sess410/411 slot 29): a survivor elected to replay a fenced victim's log
slice started reading it ~22 ms after fence certification.  A
fenced-but-recently-live victim's writes that were admitted before the
PREEMPT AND ABORT can land on the backing store AFTER certification
(target task-abort does not cancel already-submitted backing aio;
SCSI simple tasks give no cross-command ordering), so a single live read
pass can see record-aligned holes.  Because mkfs does not durably zero
the 2 GB of log slices and the rig re-runs identical workloads, those
holes contain CRC-valid cycle-1 near-twin records from a PREVIOUS fs
life.  Recovery's ophdr walk silently skips unknown-tid regions
("slack space" tolerance), so a stale record inside a multi-record
transaction span drops items with no error; the next current record's
regions then land in the wrong `ri_buf` slots → `ldip->di_magic`
mismatch → -EFSCORRUPTED(-117) → a FALSE terminal TORN verdict and a
permanent FSWIDE quarantine of a slice that was actually replayable
(the platter decoded 100 % clean minutes later — proven with
`tools/mxfs_logslice.py`).  Worst case is silent: a mis-assembly that
happens to parse could APPLY wrong images.

Full evidence chain: `docs/history/replay-117-root-cause-live-slice-read-race.md`;
design-consult ruling:
`docs/rulings/unstable-slice-read-snapshot-replay.md`.

## Mechanism (0.27.0)

`mxfs_xlog_recover_foreign_slice()` (xfs_log.c) now calls
`mxfs_xlog_slice_snapshot()` (xfs_log_recover.c) after the enforcement
preflight and BEFORE consuming the one-shot fault-injection knob and
before any recovery read:

1. Read the whole slice sequentially into a kvzalloc'd buffer
   (`l_mxfs_slice_snap`, slice-sized, ~64 MB at 32 slices).
2. Stabilization loop: sleep `fr_stab_interval_ms` (default 2000),
   re-read the slice in 4 MB chunks, compare.  Any differing chunk is
   folded into the snapshot (it converges on the latest platter state),
   logs `P-FRSTAB-UNSTABLE pass=N diff_chunks=K first_bb=X`, and resets
   the stability counter.  Instability observed here is the in-vivo
   proof of post-certification landings.
3. Accept only after `fr_stab_passes` (default 2) consecutive zero-diff
   passes → `P-FRSTAB-STABLE` → recovery starts.
4. Deadline `fr_stab_deadline_ms` (default 45000) exceeded →
   `P-FRSTAB-NOT-QUIESCED`, return -EBUSY: the attempt aborts with
   verdict reason NONE (slice stays dirty, later election retries).
   NEVER a terminal verdict from an unproven image.  Allocation failure
   (-ENOMEM) and snapshot read errors abort the same retryable way —
   there is deliberately no fallback to live reads.

While `l_mxfs_slice_snap` is set, `xlog_do_io()` serves every recovery
READ from the snapshot and mirrors every WRITE into it before writing
through to disk, so the head/tail scan and both recovery passes operate
on ONE immutable image (no TOCTOU between validation and replay — the
design-consult ruling explicitly forbids the read/validate/re-read shape).
The snapshot is freed in `xlog_dealloc_log()`, covering every exit path.

Knobs (module params, 0644): `fr_stab_interval_ms`, `fr_stab_passes`,
`fr_stab_deadline_ms`.

## What this does NOT fix (open follow-ups on D-527)

- Phase 3 (fence contract): certification still does not prove the
  target has drained the victim's backing I/O.  The stabilization loop
  tolerates the landings; it does not prevent them.
- Phase 4 (provenance): no per-record mount-incarnation stamp yet, so a
  GENUINE crash victim's slice with previous-life twin records beyond
  its true head still relies on cycle/CRC/head heuristics.  The ruling's
  deep fix (versioned, CRC-covered record incarnation; never bridge a
  txn across an incarnation mismatch) is a separate landing.
- Adopted-slice mount-time replay (`XLOG_MXFS_ADOPTED_SLICE`) does not
  snapshot yet — same exposure class, lower risk (mount-time claims are
  older), wire `mxfs_xlog_slice_snapshot()` in when touched.
- Terminal TORN after a STABLE snapshot is still possible without
  incarnation proof; accepted residual until Phase 4.

## Forensic tooling

`tools/mxfs_logslice.py IMAGE --slice N [--records|--all|--ino I|--lsn HEX]`
— envelope-aware, O_DIRECT, upstream-faithful decoder of one slice; use
it on the SCST backing image (`/home/steve/disk.img`) to compare what a
kernel replay saw against what the platter holds.  `--cluster DADDR`
dumps dinode magics of an inode cluster.

## sess412 postmortem: the 0.27.0 verification storm (D-528)

The first live run of the snapshot (fln5_hb_churn, 0.27.0) never logged a
P-FRSTAB line: the `<6.16` compat aliased `bio_add_vmalloc_chunk` to a
`bio_add_vmalloc` shim whose return contract was inverted (0-on-success
vs upstream's bytes-added), so `xfs_rw_bdev`'s chain loop treated every
successful whole-chunk add as "bio full" and submitted an unbounded
chain of real 4 MB reads marching from the slice base past
end-of-device (~31k bios/s), starving the replayer's own heartbeat.
The snapshot's 66.8 MB kvzalloc buffer was the tree's first
guaranteed-vmalloc `xfs_rw_bdev` caller, which is why nothing before
0.27.0 tripped it.  Fixed in 0.27.1 by mirroring upstream
`block/bio.c` semantics exactly (see xfs/xfs_platform.h and ledger
D-BIO-VMALLOC-CHUNK-COMPAT-INVERTED-RUNAWAY-528).  Lesson for every
future compat shim: copy the upstream return contract verbatim, and
grep upstream callers for how the value is consumed before aliasing
anything.

## Prefetch ring (0.53.0, sess445)

The sess444 prefetch (option A of the pipelining ruling) proved the NEXT
victim's snapshot on a worker while the current slice replayed.  Chain 36
on 0.52.0 measured it as never engaging: the mount-cohort barrier arms slot
k+1 before it replays slot k, and the single in-flight entry was dropped when
the next one was armed, so 30 of 31 proofs ran inline (4.7 s each, 143 s of a
298 s restart).  The prefetch is now a ring of up to `MXFS_SNAP_PF_MAX` (8)
in-flight proofs; `mxfs.fr_stab_prefetch` is the pipeline DEPTH (default 3,
each entry ~68 MiB: 64 MiB snapshot + 4 MiB bounce; 0 = inline only).  The
barrier arms the next `depth` todo victims on every iteration
(`mxfs_xlog_snap_prefetch` is idempotent per (mount, slot) and arms nothing
when the ring is full); `mxfs_xlog_slice_snapshot` takes exactly its own
entry (mount, slot, logBBstart, bytes, target all equal) after the worker
completes, and falls back to the inline proof on any mismatch or worker
error.  `xfs_log_unmount` drops every entry of the mount.  Each proof keeps
its own pass 0 + `fr_stab_passes` sleep-separated compares and its own
deadline, exactly as inline — only their sleeps overlap.
`P-FRSTAB-PREFETCH slot= inflight= depth=` and `P-FRSTAB-STABLE ...
prefetched=1 age_ms= waited_ms=` are the evidence lines.
