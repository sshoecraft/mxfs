<!-- sess145-151: clyde loop0/workqueue-swallow host-jam diagnosis, abandoned-surgery decision, rig re-established, pivot found+fixed P248 lreq-retire lea… -->
# clyde host-jam (loop0/workqueue swallow) diagnosis, abandonment, and the pivot to P248

Seven-session arc (sess145-151, ccloop c7ee71c6) covering a clyde host-local
D-state pileup caused by the sess136 fence-path GPF, the forensic chain that
traced it to a kernel workqueue "swallow," the decision to abandon in-place
kernel surgery in favor of a user reboot, and the immediate payoff once the
session pivoted back to the the zero-defect bar ledger: a teardown census that found and
fixed D-RELEASEALL-LREQ-RETIRE-MISSING (P248).

## The jam chain (sess145-147)

Root: a GPF-killed task from the sess136 fence-stage-ii GPF left two leaked
locks on `/dev/loop0` (backing `/var/lib/mxfs-fence/fio-backing.img`, a local
fence-test artifact, NOT the clustered rig) — this is the origin of
`docs/history/docs/history/docs/history/compiled-clyde-host-jam-loop0-swallow-and-p248-pivot.md`.
Cascade proven purely via `/proc` stack reads (bare `ps`/`pgrep` themselves
wedge on this host — see ccmemory `never-pgrep-f-on-clyde-mmap-lock-wedge`): a parked
loop kworker leaked `i_dio_count`; a stranded `flush_rq` blocked jbd2's
superblock PREFLUSH; a THP fault in an unrelated `ffmpeg` (spawned by the
user's own `mmrun` cron) got stuck holding `mmap_lock` while migrating a
locked jbd2 buffer; `khugepaged` queued behind it; every `/proc/<pid>/cmdline`
reader (266 `pgrep` + 246 `ps`) piled up behind THAT — loadavg 521, host-wide,
zero CPU cost (all D-state).

sess145 built `scripts/inode_dio_release/` (the source-tree rule) to replay the dead
task's missing `inode_dio_end`, gated by identity interlocks and a GPT
the design-consult rule conditional GO, but did not insert it (needed to confirm the iomap
`dio->ref` init/tail-drop pattern in `/src/linux` source first — NOT
`~/src/linux`, a path correction that recurs in
`docs/history/docs/history/docs/history/compiled-clyde-host-jam-loop0-swallow-and-p248-pivot.md`).

sess146 executed the plan and found the leak was actually two leaks on the
same dead task: the `i_dio_count` token (released via `act=1` cmpxchg once
the correct 6.8 wake primitive — `wake_up_bit(&i_state, __I_DIO_WAKEUP)`,
not `wake_up_var`, a kernel-version-dependent trap — was identified) and a
leaked SHARED `i_rwsem` reader from an unwritten-extent shared→exclusive
upgrade (released via one `up_read_non_owner`, GPT the design-consult rule conditional GO,
guarded by an exact-count re-read immediately before the single decrement).
Both releases worked: the kworker and a stuck `dd` freed. One `flush_rq`
(tag 31, PREFLUSH/FLUSH_SEQ) stayed `in_flight` with no kworker anywhere
holding loop frames — `/sys/block/loop0/inflight` reads 0 0 and cannot be
trusted for flush-seq requests.

`docs/history/docs/history/docs/history/compiled-clyde-host-jam-loop0-swallow-and-p248-pivot.md` built a
read-only forensic toolchain (`pahole` off `/sys/kernel/btf/vmlinux`
for exact 6.8 struct layouts since drgn had no DWARF; `bpftrace` to capture
live pointers; a custom `/proc/kcore` walker) and PROVED the missing piece:
the dead worker was still on its pool's `busy_hash`, and a `rootcg_work`
item queued after it died landed on the dead worker's own `->scheduled`
list — permanently unreachable ("swallowed"). The `rootcg_cmd_list` head was
separately corrupted (pointing at a stale completed cmd from the Aug 4
force-completion churn), and the stranded `flush_rq`'s `loop_cmd` was
self-linked on no list at all, reachable only from the block layer, not the
workqueue. A full surgery plan (unswallow the worker, reinit the corrupted
list, force-complete the flush) was designed with exact offsets but NOT
executed — the design-consult rule GPT consult on the surgery itself was still outstanding,
and journalctl showed the same force-complete-without-fixing-the-swallow
approach had already re-stranded the flush 3 times on Aug 4.

## The decision: abandon surgery, work the ledger (sess148)

`docs/history/docs/history/docs/history/compiled-clyde-host-jam-loop0-swallow-and-p248-pivot.md`
reversed course after seven sessions sunk into the jam. Evidence-based
reasoning: the jam does not block the mission (all 32 rig VMs healthy,
load 0.00, mounts fine — `loop0` is a local fence artifact, not the
clustered FS); the jam is contained and stable for 3+ days (521 D-state
tasks consuming zero CPU, not trending toward OOM); the host is fragile
enough that even a bare `ps -eo stat,comm` hangs in the herd, so hand-writing
live kernel workqueue memory on the one host running the rig, SCST target,
and Claude itself is a bad risk/reward trade; and a user-scheduled reboot
is strictly better than surgery — same end state, none of the catastrophic
downside, and explicitly the user's call under the never-reboot-clyde rule. `loop0` was left
quarantined (attached, not `losetup -d`, which would hang on the stranded
flush). The user's `mmrun` cron stays paused (`#PAUSED-mxfs-sess145`) until
after the reboot, since re-running it would re-seed the ffmpeg linchpin.
The two real fixes from sess146 (the `i_dio_count` and `i_rwsem` leak
releases) were kept as genuine fence-path defect knowledge, independent of
the abandoned jam-clearing surgery.

The same session then proved the actual rig was fine on the current build:
`docs/history/docs/history/docs/history/compiled-clyde-host-jam-loop0-swallow-and-p248-pivot.md`
found 0.11.453 (srcversion F20024E38213A9E64DB6718) still deployed,
`prep_cluster` completing in 71s across 32/caw, and a fresh board
(cache_coherency, node_responsive, kernel_health) PASS 32/32 with the host
jam present throughout — confirming the jam is host-cosmetic to the
mission. Also recorded here: the `MXFS_EXTRA_MODARGS="cluster_passenger_skip=N"`
knob mechanism, the manifest's `max_nodes=30` cap that excludes several P2
coherency tests at 32 nodes, and that `dir_reuse_coherency` at 32/caw is a
~75-minute job (not foreground-runnable).

## The pivot pays off: P248 found and fixed (sess149-151)

`docs/history/docs/history/docs/history/compiled-clyde-host-jam-loop0-swallow-and-p248-pivot.md`
found the D-FOREIGN-REPLAY-UNGATED-IMAGES ledger `next` field was stale
(pointed at sess98 state; the real frontier had advanced through sess135's
lifecycle landings on 0.11.452). More important: `stop()` had never
actually executed on the deployed 0.11.453 build — the sess148 prep's
teardown ran under the previously-loaded 0.11.440 module. This made a
teardown census the correct next measurement, ahead of any further code
work.

`docs/history/docs/history/docs/history/compiled-clyde-host-jam-loop0-swallow-and-p248-pivot.md`
ran it: lifecycle teardown PASSED fleet-wide (clean heartbeat-slot release
on all 32, zero P253/P255/P258-P262 probe hits) but a NEW defect appeared —
P248-LREQ-LEAK fired with exactly 6 leaked entries on every node, 1:1 with
`P109-CLR-RELEASE-ALL` count. Root cause, code-confirmed: `caw_release_all_body`
(`dlm_caw.c`) did `untrack_held` on CAS-confirmed clear but never called
`lreq_release_all` — the retire step the single-resource unlock path
performs — so entries with live tenure survived to the destroy-time leak
report. Ledgered as D-RELEASEALL-LREQ-RETIRE-MISSING. A the design-consult rule GPT consult
fixed the design: sample `pub_seq` exactly once per resource identity,
before the first CAS, never re-sampled on retry (re-sampling could eat a
publication landing between a CAS failure and the next sample); on identity
churn across retries (memcmp mismatch) decline the retire entirely
(fail-closed — A→B→A needs history this shape doesn't have); `pub_seq==0`
is a safe "no entry" anchor since the only increment site guarantees
published entries read ≥1; do not retire the not-cleared-but-owed case.
A second defect, the stuck-notify chain (`mxfs_v5_dlm_set_dlm_stuck_notify`
registered with no caller, so a ruled force-shutdown request never reached
XFS), was designed alongside it in the same consult: wire via
`SHUTDOWN_META_IO_ERROR`, teardown order v5-destroy-first (stop() joins the
owed worker, the only emitter) then `cancel_work_sync` then free.

`docs/history/docs/history/docs/history/compiled-clyde-host-jam-loop0-swallow-and-p248-pivot.md`
landed both changes exactly per the ruling — the per-slot `pub_seq0` sample
plus a P248 identity dump in the destroy loop (Change A), and the XFS-side
`mxfs_dlm_stuck_work_fn`/`mxfs_dlm_stuck_notify` plus the matching
`cancel_work_sync` at both mount-teardown sites (Change B) — as 0.11.454
(srcversion 80380189DB5175E6A8CF74E), deployed to 32/caw. Verification
(a second `prep_cluster` run whose teardown actually exercises the new
build, checked for zero P248 delta) was left pending for the next session;
that verification and the fix's disposition to FIXED AND VERIFIED are
carried forward in the later `docs/history/docs/history/compiled-p248-owed-registry-leak-campaign.md`
article (sess152-160).

## Recurring lessons

- Bare `ps`/`pgrep` on clyde is not just risky in general (see
  ccmemory `never-pgrep-f-on-clyde-mmap-lock-wedge`) — under an active D-state herd
  it will itself hang the diagnosing session, as it did to sess143/144
  before sess145 worked out the `/proc`-stack-sweep alternative.
- `/sys/block/<dev>/inflight` does not count flush-sequence requests;
  reading 0 0 while a `flush_rq` is `in_flight` is not a contradiction.
- Kernel version-specific primitives are a trap even within "the same"
  6.8 kernel: `inode_dio_end`'s wake call (`wake_up_bit` vs `wake_up_var`)
  differs from what later/adjacent kernel source (7.1-rc7, consulted for
  the `dio->ref` proof) uses — verify against the actual running kernel,
  not whatever tree is easiest to grep.
- Seven sessions on a host-local jam that never touched the clustered rig
  is the concrete case for the never-reboot-clyde rule's "host recovery is the user's call":
  the safe fix (user reboot) was available the entire time and was
  strictly dominant over live kernel-memory surgery on the one host
  running everything.
- A stale ledger `next` field is itself a hazard — sess149's mapping work
  (pure reconstruction, no code) was necessary before any further P248/lreq
  work could safely resume, and directly surfaced the teardown-census gap
  that found P248.
