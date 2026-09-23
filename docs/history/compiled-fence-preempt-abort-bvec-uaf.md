<!-- D-PR-FENCE-PREEMPT-WITHOUT-ABORT sess134-142: stage(i)/(ii) A/B harness, SCST fileio bvec UAF root cause+fix+deploy, leaked i_dio_count blocker. -->
# D-PR-FENCE-PREEMPT-WITHOUT-ABORT stage (i)/(ii) A/B campaign, sess134-142

Closure requires an A/B discriminator proving PREEMPT AND ABORT (0x05) linearizes
against in-flight I/O where plain PREEMPT (0x04) does not, run on BOTH SCST
handlers the fleet uses (blockio for method validation, fileio for the shipped
32-node LUN), plus (C3) proof the real MXFS survivor doesn't replay before fence
completion is consumed. The campaign found and fixed three independent bugs
before the fileio arm could even run once: two harness-scorer defects (fixed
`docs/history/docs/history/docs/history/compiled-fence-preempt-abort-bvec-uaf.md`,
`docs/history/docs/history/docs/history/compiled-fence-preempt-abort-bvec-uaf.md`) and a real
SCST kernel use-after-free that the ruled stage-(ii) rig turned out to be the
sharpest possible reproducer for
(`docs/history/scst-fileio-async-bvec-uaf-root-caused.md` through
`docs/history/docs/history/docs/history/compiled-fence-preempt-abort-bvec-uaf.md`).

## Stage (i) — blockio A/B, method validation (sess134-135)

`tests/fence_inflight/{inflight_ab.sh,verdict.py}` scores an arm on whether a
PROUT's completion (the "boundary") precedes or follows the victim's write
actually landing at the device ("t_land"). Three scorer bugs surfaced and were
fixed before the method was trustworthy:

1. `EH_MARKERS` included the string "reservation conflict", which property (C)
   deliberately provokes once — replaced with an exact-count check
   (`4b_conflicts_all_accounted`) plus `4c_held_write_admitted`.
2. `6_target_observed_sa` grepped dmesg (trace-level dependent); replaced with
   ftrace on `scst_pr_do_preempt`/`scst_pr_abort_reg`, direct from SCST source:
   0x04 calls only `do_preempt`, 0x05 calls `do_preempt`+`abort_reg`.
3. `7_common_timeline` wrongly required `t_land` to exist — a write that never
   reaches the medium is a BETTER outcome, not a broken measurement.
4. The 0x05 completion boundary must be the LAST `scst_cmd_done_pr_preempt`
   call, not the first — that hook fires once per pending PR_ABORT_ALL mgmt cmd
   plus once for the PROUT's own exec-done; only the call that drains
   `pr_abort_pending_cnt` to 0 is the real completion. Using `first()` would
   have failed the safety arm spuriously (confirmed against the sess135 trace).

With TAS off, SAM requires an aborted command be dropped with no notification —
SCST does exactly that, so under 0x05 a fenced node's in-flight I/O never
completes and never errors, it just hangs; the initiator's `eh_cmd_timed_out`
keeps returning BLK_EH_RESET_TIMER indefinitely. This is a real design
consequence for MXFS, not just a harness nuisance: whatever ships must not
assume the victim ever learns anything. `inflight_ab.sh` was restructured so
the entire measurement window runs BEFORE reaping the held write, with a bounded
(10s) reap and `stack.sh relogin` fallback recorded in `arm.env`.

sess135 ran the ruled order 0x04→0x05→0x04 end to end: all three arms scored
VALID, 0x04 bracketing 0x05 on both sides rules out drift/contamination, and the
0x05 margin (+90µs, boundary caused by landing per `<-scst_tm_thread` in the raw
ftrace) is CAUSAL, not luck — don't "improve" it by widening the delay window.

A fourth harness defect was found and fixed the same session: `DMESG_MARK=$(dmesg
| wc -l)` + `tail -n +N` is unsound because the printk ring buffer is bounded in
bytes, not lines — a burst of long trace lines can evict enough short old lines
that the total count falls, and `tail -n +N` yields nothing. This let an empty
dmesg capture make `4_no_eh_reset_timeout` pass **vacuously** — the single most
dangerous failure mode this harness has, reporting clean because it captured
nothing. Fixed with a unique token stamped into `/dev/kmsg` at arm start, sliced
with `sed -n "/$TOKEN/,\$p"`, plus a new validity item `4d_dmesg_window_captured`
that scores INVALID (not silently passing) if the token was evicted. Also:
printk's clock is NOT CLOCK_MONOTONIC (~1.3s offset measured at 110000s uptime)
— never place a dmesg timestamp on the ftrace/userspace timeline.

Also found (not yet fixed as of sess135): `dlm/mount.c` has three 2-argument
calls to `mxfs_scsipr_preempt()` that look like a live 0x04 path but are dead —
the file isn't in the Kbuild dlm object list and doesn't compile into mxfs.ko.
The only built caller (`dlm/scsipr.c:465`) passes `abort=true` (0x05). Worth
removing but not a live bug.

## Stage (ii) blocker #1 — the fileio LUN wouldn't even come up (sess136)

The production 32-node LUN is `vdisk_fileio` (`async=1 o_direct=1`, AIO), not
`vdisk_blockio` — all sess134-135 arms ran on blockio, so stage (ii) (required
by the original ruling: "code agreement is not a measurement") was still fully
outstanding. `tests/fence_inflight/stack.sh` gained `MXFS_FENCE_MODE=fileio`,
building loop0→dm-delay→ext4→disk.img→vdisk_fileio to mirror production exactly
(SCST rejects `o_direct` without `async` — `vdisk_attach: using o_direct without
setting async is not supported`). `prprobe fiemap` was added to translate a LUN
byte offset to a physical one via `FS_IOC_FIEMAP`, required because the ruling
forbids parsing filefrag text.

The fileio LUN wedged immediately: every command hung with `DID_TRANSPORT_DISRUPTED`
after 146s, `iscsiadm logout` deadlocked (`sd_shutdown`→`sd_sync_cache` blocked on
a target trying to close a connection that's `msleep`ing for commands to drain).
Every layer below the handler measured healthy (~11ms aligned O_DIRECT reads at
every layer), pointing at the fileio handler itself, not the loop/dm/ext4 stack
(`docs/history/docs/history/docs/history/compiled-fence-preempt-abort-bvec-uaf.md`). This
diagnosis was the launching point for sess137.

## Stage (ii) blocker #2 — the real bug: SCST fileio bvec use-after-free (sess137-140)

Root cause, fully measured via `/sys/kernel/debug/block/loop0/hctx0/busy` plus
dmesg: `fileio_exec_async()` in `scst/src/dev_handlers/scst_vdisk.c` unconditionally
`kfree()`s the heap-allocated bvec array after submitting I/O, including on the
`-EIOCBQUEUED` (async/deferred) path — but the kernel bio contract
(`bio_iov_bvec_set()`, `block/bio.c:1177`) ALIASES that array into the bio rather
than copying it. On plain ext4-on-nvme this race is masked because
`blk_finish_plug`/`nvme_queue_rqs` maps the SG list before `-EIOCBQUEUED` returns;
inserting dm-delay+loop defers the real submission to a workqueue, so the free
happens first, the slab gets recycled, and DMA mapping reads garbage — this is
what GPF'd `dma_direct_map_sg` and killed the loop0 worker mid-submission in
sess136, stranding its in-flight requests (blk-mq can't recover them because
loop's `blk_mq_ops` has no `.timeout`).

**Production runs the identical vulnerable path** (`async=1 o_direct=1`,
`vdisk_fileio`, same code) — GPT design-consult ruling: treat all prior unexplained
production timing/error-rate anomalies as contaminated evidence; a clean run
does not establish absence, since a freed slab often still holds its old
contents; rebaseline after patching
(`docs/history/scst-fileio-async-bvec-uaf-root-caused.md`).

sess138 proved this from live memory, not code reading: `scripts/loop_unwedge/`
(new kernel module) walked the four leaked loop0 requests' bvec arrays in situ —
3 of 3 kmalloc'd (>4-segment) arrays were corrupted (one clobbered `bv_page`
pointer each in two cases, a fully garbage first bio_vec in the third), while the
1 of 1 inline `small_bvec` (≤4 segments, never freed) array was intact. The
corrupted `bv[0].bv_len` in one case made `bvec_iter_advance()`'s consuming loop
unsafe to run normally, so `loop_unwedge` was designed to detach `rq->bio` and
end each bio by hand (`bi_status` set, `bio_endio()`) rather than force a normal
completion — verified safe against `bio_release_pages`, `bio_free`, and
`fileio_async_complete`'s error branches
(`docs/history/docs/history/docs/history/compiled-fence-preempt-abort-bvec-uaf.md`). Gotcha for anyone
validating a `struct page*` from a kernel module: `virt_addr_valid()` is always
false for vmemmap pages — use `pfn_valid(page_to_pfn(pg))`.

`scripts/loop_unwedge/` also unwedged the rig with no host reboot (5 D-state
tasks → 0, 6 stale sessions → 0), and all of GPT's required audits for the fix
were discharged by direct grep/read: `do_verify`'s early return never touches
`p->async.bvec`; a completion that never fires only leaks the array (never
double-frees); nothing else reads or frees it
(`docs/history/docs/history/docs/history/compiled-fence-preempt-abort-bvec-uaf.md`).

The patch (sess139, `+caw-abort-reclaim.2`, builds clean, not yet deployed):
free the bvec array at the TOP of `fileio_async_complete()` instead of after
submit in `fileio_exec_async()`, reset to `small_bvec` for idempotency (fixes a
second UAF too — the queued route could free `p` before the submitter's own
kfree ran); move `iov_iter_bvec()`+kiocb init INSIDE the `-EAGAIN`/`-EOPNOTSUPP`
retry loop (previously outside, so a retry reused an advanced iter/`ki_pos`);
replace the hand-built zeroed kiocb literal with `init_sync_kiocb()` (the literal
silently dropped IOCB_DSYNC/SYNC/APPEND/ioprio); add `kiocb_start_write()`/
`kiocb_end_write()` freeze protection around writes to regular files (GPT-required,
mirrors `fs/aio.c`) — note 6.8's `kiocb_end_write()` does NOT self-guard on
IOCB_WRITE, the caller must track pairing, contra one of GPT's own claims.
Confirmed the bvec count itself was never wrong on this kernel (≥5.1 emits
exactly one bvec per SG entry) — the bug is purely the free timing
(`docs/history/docs/history/docs/history/compiled-fence-preempt-abort-bvec-uaf.md`).

sess140 deployed `+caw-abort-reclaim.2` to the live 32-node target (full
teardown/rebuild recipe recorded: unmount+rmmod fleet-wide, delete SCST
target/devices, `pkill iscsi-scstd` before `rmmod` — it holds a refcount — then
rebuild via `scst_setup.sh`+`rig.sh mpath`). Gotcha: `scst.ko`'s srcversion is
identical across `.1`/`.2` since modpost only hashes listed `.c` files — use the
`version:` sysfs field, not srcversion, to distinguish. Also fixed here: the
fence harness's `stack.sh devmap` was called via `sudo bash` which drops env, so
`MXFS_FENCE_MODE=fileio` never reached it and a live fileio stack silently
reported blockio device names — could have silently scored the wrong handler.
Stack now persists its mode to a file. Separately re-confirmed: never run
`stack.sh up` twice on an already-up stack — it reinstates iSCSI sessions with
the same ISID, leaving 6 sessions on a 2-initiator target and wedging session
teardown for ~5 minutes per stuck `SYNCHRONIZE CACHE`
(`docs/history/docs/history/docs/history/compiled-fence-preempt-abort-bvec-uaf.md`).

## Stage (ii) blocker #3 — leaked `i_dio_count` on the harness's own backing file (sess141)

Even after the SCST fix deployed, stage (ii) still couldn't run: fileio writes
to the loop backing file hung. Root cause, measured via new
`scripts/inode_dio_probe/`: the sess136/137 GPF killed the loop worker inside
`__iomap_dio_rw()` on the harness's `fio-backing.img` inode, and
`make_task_dead()` never ran the matching `inode_dio_end()` — so `i_dio_count`
was permanently stuck at 1 even though nothing was in flight anywhere
(`nvme0n1 inflight = 0 0`). `ext4_dio_write_checks()`'s exclusive path calls
`inode_dio_wait()` (`wait_var_event(&inode->i_dio_count,...)`), which then never
returns. Diagnostic signature: O_DIRECT reads of the loop device kept working
(shared i_rwsem path never waits on the count) while writes and flushes hung —
and flushes hung only as a side effect of `loop_process_work()` draining its
per-worker `cmd_list` serially behind the one permanently-stuck write.
`tests/fence_inflight/stack.sh down` deliberately preserved the backing image
across runs, so every fileio `up` since sess136 re-attached the same poisoned
inode — five sessions of the blocker being invisible because nobody suspected
the file itself. Two hypotheses were tested and refuted along the way: a
poisoned `lo->rootcg_work` (refuted — a fresh backing file flushed fine); root
ext4/nvme sickness (refuted — clean). Do not free the poisoned inode or its loop
device; the parked kworker sleeps in `wait_var_event` against it forever, and
deleting it would UAF that wait
(`docs/history/fence-stage-ii-blocker-root-caused-leaked-i-dio-count.md`).

## Resolution — generational images + two more latent harness bugs (sess142)

design-consult ruling on how to route around the poisoned inode: use a fresh inode per
"generation" on the SAME ruled stack (file→loop→dm-delay→ext4→disk.img→
vdisk_fileio) — do NOT swap in a `brd` RAM device to delete the loop layer
entirely. Plan A (fresh inode) is closure-grade; Plan B (brd) is supplemental
only, because brd generally completes bios synchronously in the submitter's
context and could collapse exactly the race window (SCST abort/reclaim vs. a
still-outstanding lower-layer I/O) that stage (ii) exists to test. A Plan-B pass
after a Plan-A wedge would only prove the upper half works, not clear stage
(ii). Also ruled: new images must use `O_CREAT|O_EXCL`, never recycle a name; an
admission-probe timeout must quarantine that whole generation and stop, never
accumulate parked probes; the fact that stage (ii) now necessarily runs on a
post-GPF, kernel-tainted host with the poisoned stack quarantined must be
recorded as a stated test-environment exception (the never-reboot-clyde rule forbids clearing it by
rebooting clyde).

`stack.sh` was made generational: gen 0 (the original poisoned names) is
permanently quarantined and untouchable by `down`/`purge`; gen N≥1 owns
uniquely-suffixed names; `up` gained two admission gates — an `inode_dio_probe`
read on the image BEFORE attaching anything, and a bounded (5s) 4KiB
write+flush test after attach, using a reserved scratch region outside the
dm-delay mapping so the gate is non-destructive and can run on every `up`.
Either gate failing quarantines the generation rather than proceeding.

Empirical isolation (`blocklayer_selftest.sh`, new) confirmed the quarantined
loop0 doesn't constrain the rest of the block layer — loop attach/dio/flush,
dm create/suspend/reload, mkfs/mount all healthy on fresh devices; poisoning is
per-inode, not per-workqueue.

Two more latent fileio-arm bugs were found and fixed before ever running an arm
against the LUN for real:
1. `inflight_ab.sh`'s in-flight-write check hardcoded the stage-(i) blockio
   target name (`...:inflight` vs. fileio's `...:inflightf`) — every fileio arm
   would have aborted "write never observed in flight" regardless of actual
   handler behavior.
2. The observation offset used the LUN's logical offset directly against the
   loop device — correct only for blockio identity mapping. For fileio the real
   physical offset must come from `stack.sh fiemap` against `disk.img`; fixed to
   resolve and record `PHYS`/`PHYS_C` before and after every arm, with an
   `EXTENT_STABLE` flag if the file's extent map moved mid-run
   (`docs/history/docs/history/docs/history/compiled-fence-preempt-abort-bvec-uaf.md`).

## State at end of campaign

Stage (i) done and scored (all arms VALID). Stage (ii) is unblocked by design
but had not yet run a scored arm against the fileio handler as of sess142.
(C3) — proving the real MXFS survivor doesn't replay before fence completion is
consumed — remained outstanding throughout. Production stayed on 64 sessions,
healthy, throughout the entire campaign; every wedge and recovery was confined
to the disposable fence-test stack.
