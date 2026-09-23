# Host safety — why clyde wedged twice (and panicked once), and what now prevents it

clyde was wedged unrecoverably twice inside 24 hours (2026-08-20 and
2026-08-21), each time needing a manual reset.  Neither was an MXFS
filesystem bug.  Both were the host being driven into a state it could not
return from, and both had a cheap, observable precondition that nothing was
checking.

This document is the root cause of each, and the guardrails that now stand
between the rig and a third one.

---

## The structural fact underneath both

    /sys/kernel/scst_tgt/devices/mxfs/filename = /home/steve/disk.img
    guest root disks                           = /home/steve/vms/qemu/testN/testN
    persistent journal                         = /var/log/journal
    all three                                  = /dev/nvme0n1p2, ext4, 1.8T

The shared LUN under test, all 32 guests' root images, and clyde's own journal
are files on **one ext4 filesystem** with **one jbd2 journal**.  Anything that
makes that journal stall, stalls the entire rig — and the rig is what the host
is for.  On 2026-08-20 it was 92% full.

No threshold removes this coupling; only separate devices do, and on this host
that is not possible (see "Decisions taken" below).  `scripts/clyde_preflight.sh`
therefore prints it as a `NOTE` and compensates with tight headroom limits.

---

## Both wedges are the SAME root cause

This was not obvious at first and the first pass of this document got it
wrong.  The 2026-08-20 boot left **no** `BUG:`/`Oops` in the journal, so it
read as a pure jbd2 deadlock.  It is not: journald could no longer write once
the root ext4 was wedged, so nothing after 19:24:43 reached the journal.  The
faults are in pstore/ERST instead, and that boot reached **Oops #9**.

The surviving record (`/var/lib/systemd/pstore/7675903811256320028`) holds
oops #3:

```
BUG: kernel NULL pointer dereference, address: 000000000000000c
Oops: 0002 [#3] ... Comm: CPU 0/KVM  Tainted: G      D W  OE
RIP: 0010:jbd2_journal_grab_journal_head+0x29/0x80
RDX: 66786d2d39717473
  jbd2_journal_try_to_free_buffers <- ext4_release_folio <- filemap_release_folio
  <- shrink_folio_list <- evict_folios <- ... <- do_huge_pmd_anonymous_page
  <- __get_user_pages <- hva_to_pfn [kvm] <- kvm_tdp_page_fault [kvm]
```

From the instruction bytes at that RIP, `RDX` is `bh->b_state`.  Decoded
little-endian it is the ASCII **`"stq9-mxf"`** — an iSCSI TransportID
fragment, the same payload family as wedge B's corrupted PTEs
(`"st16-mxf"`, `"s-node,i"`).  The rest follows exactly:

- `b_state` happens to have bit 16 (`BH_JBD`) set, so `buffer_jbd(bh)` returns
  true;
- the code then loads `b_private` at `+0x40`, which is NULL;
- and writes `jh->b_jcount` at `NULL + 0x0c` — **the precise faulting address
  in the oops.**

So the overflow described under "Wedge B" below also ran on 2026-08-20; it
simply landed on a `struct buffer_head` instead of a page-table page.  That is
why jbd2 "deadlocked" with the device idle: the journal was not slow, its
buffer state was corrupt.

**One defect, two different victims.**  The `+caw-abort-reclaim.4` fix
addresses both.  The trace flood below is a genuine and serious aggravator —
it blinded journald, it filled the ERST crash buffer with 716 KB of per-IO
trace so the oops context was mostly lost, and it drove the ext4 pressure that
put reclaim on the corrupted buffer in the first place — but it is not the
root cause.

---

## Wedge A's aggravator — 2026-08-20: a debug trace left on

**Chain**

1. SCST is built in debug mode (`CONFIG_SCST_DEBUG` + `EXTRACHECKS` +
   `TRACING` — the tree's default `make` with an empty `BUILD_MODE`), so the
   per-IO `TRACE_BLOCKING` prints in `scst_check_scsi_atomicity()` are compiled
   in and one sysfs write turns them on.
2. They are *not* in `SCST_DEFAULT_LOG_FLAGS`.  A previous debug session
   enabled them via `/sys/kernel/scst_tgt/trace_level` and did not turn them
   off.  (The same had already happened with `pr` tracing, deliberately "left
   on to capture the next real fence".)
3. MXFS uses SCSI COMPARE AND WRITE as its DLM transport, so at 32 nodes every
   lock operation crosses that trace point.  Measured over that boot:
   **1,074,700 kernel lines in 98 minutes — ~182/s, 92% of them from this one
   trace point.**
4. journald persisted all of them to the root ext4 — the same filesystem as
   the LUN and the guest images.
5. jbd2 wedged.  **875 D-state threads** (813 qemu workers, 47
   `iscsi_conn_cleanup`), loadavg 870, MemAvailable 39 GB, Dirty 920 kB, and
   the **nvme 1.6% busy at 270 KB/s**.  Idle device + free memory + hundreds
   of blocked tasks is never slowness — and per the section above, it was not
   even a lock dependency: the journal's buffer state had been corrupted.
   `virsh destroy` timed out on every domain.

**Three distinct harms from the flood, all real:**

- it drove the memory and journal pressure that put reclaim onto the
  corrupted buffer_head;
- it stopped journald persisting anything once the filesystem wedged, which is
  why nine oopses left no trace in the journal and the first analysis of this
  incident was wrong;
- it filled the ERST crash buffer with 716 KB of per-IO trace, so the crash
  record that *did* survive is mostly `scst_check_scsi_atomicity` lines with
  the oops context pushed out.  **Debug tracing left on destroyed the evidence
  for the bug it was left on to find.**

**Fixes**

- `scripts/scst_setup.sh` now resets the trace mask to the build default on
  **every** rig build.  The mask is rig state owned by setup, not something a
  session leaves behind.  Enable tracing deliberately for an investigation;
  a rig rebuild always takes it back off.
- `scripts/clyde_preflight.sh` refuses to start a run when a per-IO trace flag
  is set (`MXFS_PREFLIGHT_ALLOW_TRACE=1` for a deliberate, time-boxed debug
  run), or when the kernel log is already running hot.
- `tools/clyde_kmsg_guard.sh` halts the rig if the kernel log sustains
  >60 lines/s for 60 consecutive seconds of hot 5 s windows (until sess410:
  two consecutive hot windows).  Baseline for comparison: a full 32-node
  campaign produces ~1 line/s on clyde.
- `/etc/systemd/journald.conf.d/50-mxfs-rig.conf` caps size and message rate.
  Defence in depth — the fix is not producing the flood.
- **2026-08-22 (sess398): the rig default is the build default minus
  `mgmt_dbg`.**  The guard halted twice that day (16:53:42Z, 18:58:36Z;
  `.evidence/guard_20260822_{165342,185836}_106480`) on the same deterministic
  burst: at a 32-node re-prep (iSCSI re-login + PR re-register of every node,
  which every `tests/d385_publication_verify.sh` arm switch and every
  `prep_cluster` after a fenced node performs) SCST printed ~4,400 kernel lines
  in ~30 s at up to 224 lines/s — `Queuing new UA (6:2a:3)`, `Setting pending
  UA`, `task_mgmt_fn_done`, session negotiation, `Clearing UA`, command-thread
  start/finish — all `TRACE_MGMT_DEBUG`.  The first time the halt was cleared
  without fixing the source and it came straight back.  The guard's trip is not
  widened (the host-guard rule); the source is removed: `scst_setup.sh::reset_trace`
  (`reset-trace` subcommand) now does `default` then `del mgmt_dbg` on the core,
  every handler and every target mask, and `clyde_preflight.sh` treats
  `mgmt_dbg` on any of those masks as a hot flag.  Investigations that need
  per-UA / task-management tracing enable it deliberately and turn it off.
- **2026-08-23 (sess410): the residual prep burst and the sustain rule.**  With
  `mgmt_dbg` off, a 32-node prep power-cycle still logs ~2,270 host kernel
  lines in ~40 s (peak 228 lines/s over 5 s): 64 iSCSI sessions (two paths per
  node) each printing 8 `scst_cmd_thread ... finished` + 8 `... started` lines
  plus 8 session-negotiation lines — all `PRINT_INFO`, not trace-mask
  controlled, so `reset_trace` cannot remove them.  The shape is deterministic
  (identical tallies at 13:52Z, 16:14Z, 16:20Z that day; measurement in
  `.evidence/guard_20260823_162103_5326` and the sess410 transcript) but the
  two-window rule tripped on only one of the three — the trip depended on where
  line arrivals cut the windows.  The halt at 16:21:03Z was that burst: 397 of
  the 400 snapshot lines are session lifecycle, 3 are reservation conflicts, no
  corruption or precursor line, taint unchanged.  The guard's RATE is unchanged;
  its duration requirement is now `FLOOD_SUSTAIN_S=60` seconds of consecutive
  hot windows, which a 40 s bounded burst cannot meet and a wedge-class flood
  (182 lines/s for 98 min) meets within a minute having logged ~11k lines —
  ~1% of the 1.07M that wedged the host.  Reducing the burst itself would mean
  fewer SCST threads per session (`threads_num`, a throughput knob) or a
  patched SCST; neither was done.

---

## Wedge B — 2026-08-21: a kernel buffer overflow in the SCSI target

**Root cause, proven by code and reproduced deterministically:** a
signed/unsigned comparison in `scst_pr_read_full_status()`
(`/src/scst/scst/src/scst_pres.c`).

```c
int offset, size, size_max;                /* signed   */
const uint32_t rec_len = 24 + ts;          /* UNSIGNED */

if (size_max - size > rec_len) {           /* promoted to an UNSIGNED compare */
        memcpy(&buffer[offset + 24], reg->transport_id, ts);
        offset += rec_len;
}
size += rec_len;                           /* counts skipped registrants too */
```

`size` accumulates **every** registrant, including ones skipped for not
fitting.  The moment one does not fit, `size` passes `size_max`,
`size_max - size` goes negative, and because the other operand is `uint32_t`
the comparison is performed unsigned: the negative int promotes to ~4e9, the
test passes, and **every remaining registrant is memcpy'd past the end of the
command's data buffer.**

`scst_pr_read_keys()` right above it does the same thing correctly — its
`rec_len` equivalent is a plain `8`, so that comparison stays signed.

**Reachability is structural, not exotic.**  MXFS probes READ FULL STATUS with
a 4096-byte buffer and resizes on the reported ADDITIONAL LENGTH
(`pal/linux/kern.c::mxfs_pal_scsi_pr_read_full_status`) — a correct, standard
pattern.  Any initiator whose probe buffer is smaller than the full response
arms the bug.  That happens at roughly 53 iSCSI registrants; the 32-node rig
runs 64 (32 nodes × 2 multipath paths).  **The rig crossed the threshold when
it scaled to 32 nodes.**

**Chain**

1. `08:25:22` `scst: ***ERROR***: Too big response data len 4496 (max 4096)`
2. `08:52:58` … `4848 (max 4096)`
3. `09:03:00` … `5024 (max 4096)` — growing with the registrant list; each
   with a stack naming `scst_pr_read_full_status`.  SCST's own comment at that
   print says *"It's a bug in the lower level code"*.
4. `09:05:24` `BUG: Bad page map in process CPU 1/KVM  pte:66786d2d36317473`
   and `pte:692c65646f6e2d73`.  Those PTE values are little-endian ASCII —
   `"st16-mxf"` and `"s-node,i"`, consecutive 8-byte chunks of
   `…test16-mxfs-node,i,0x…`, an iSCSI TransportID.  A register in the
   following oops held the ASCII `"3d0200"` (ISID hex).  **A live QEMU
   page-table page was full of the exact payload of that `memcpy`.**
5. Oops in `vm_normal_folio` via `change_prot_numa` → the vCPU thread died
   *with irqs disabled and preempt_count 1* → `migration/49` stuck >387 s in
   `multi_cpu_stop` (stop_machine never completed) → RCU stalls → 23 threads
   in `synchronize_rcu` → jbd2 blocked in `__wait_on_buffer` with the nvme
   idle → journald unkillable after SIGKILL.  Host dead.

**Fixes**

- `scst_pres.c` — the bound is now taken against `offset` (bytes actually
  written) with signed types, and clamped to `min(buffer_size, cmd->bufflen)`;
  the walk stops at the first descriptor that does not fit while ADDITIONAL
  LENGTH still reports the **full** length so the initiator can resize.
  Two sibling guards on wire-supplied 32-bit lengths (`ext_size + 28`,
  `tid_buffer_size + 24`) were hardened against wrap in the same pass.
  Shipped as **`+caw-abort-reclaim.4`**.
- `tests/scst_pr_fullstatus_bounds.c` + `tests/scst_pr_bounds_check.sh` —
  runs both loop variants against a `PROT_NONE` guard page in a forked child.
  The old loop dies of SIGSEGV; the new one stays in bounds and still reports
  the full length.  The script also asserts the **installed** `scst.ko` is
  `.4` or newer and that `iscsi-scst.ko` was built against the same core
  (SCST refuses to register a target template whose interface version
  differs, so a stale one silently prevents the target coming up).
- `scripts/clyde_preflight.sh` blocks any run on an SCST older than `.4`.
- `tools/clyde_kmsg_guard.sh` treats `Too big response data len` as a
  precursor: on 2026-08-21 that gave **38 minutes** of warning before the kill,
  and the last one gave 2m24s.

**Do not try to reproduce this on an unpatched module.**  The "before" arm is
the historical evidence above; deliberately re-running the overflow corrupts
host memory.  The guard-page harness is the safe reproduction.

---

## Crash C — 2026-08-23: SCST PREEMPT AND ABORT vs. session teardown

The third host incident was a **panic**, not a wedge: `panic_on_oops=1` (the
2026-08-21 decision) did its job, clyde rebooted itself in ~90 s and
`mxfs-crash-latch.service` halted the rig with the pstore record archived to
`.evidence/crash_20260823_102547/`.  Ledger:
`D-HOST-SCST-PR-ABORT-SESSION-SHUTDOWN-PANIC-408`.

**What happened.**  The 0.26.3 rman matrix arm `mutate2` killed test3 and
test4 (10:22:59Z / 10:23:04Z).  ~65 s later their iSCSI sessions hit the
target's 30 s response timer and tore down (`NEXUS_LOSS_SESS` ->
`session_free` -> `scst_unregister_session`).  At that instant a survivor
(test29) executed the fence for the dead key — PERSISTENT RESERVE OUT /
PREEMPT AND ABORT — and SCST's `scst_pr_abort_reg()` queued an abort-all TM
on the *registrant's* session, which was already past `shut_phase READY`:

    scst_post_rx_mgmt_cmd: ***CRITICAL ERROR***: New mgmt cmd while shutting
      down the session 00000000c9ed2ee1 shut_phase 2
    kernel BUG at /src/scst/scst/src/scst_targ.c:6794!
    Comm: mxfs29_6 ... scst_rx_mgmt_fn <- scst_pr_abort_reg <- scst_pr_do_preempt
      <- scst_pr_preempt_and_abort <- scst_persistent_reserve_out_local
    Kernel panic - not syncing: Fatal exception

**Why it is a race in SCST's core, not in MXFS.**  A registrant's
`reg->tgt_dev` keeps pointing at its session from `scst_unregister_session()`
(shut_phase=SHUTDOWN, refcount killed) until `scst_free_session()` ->
`scst_pr_clear_tgt_dev()` clears it under `dev_pr_mutex` — on the management
kthread, after the refcount reaches zero.  In that window a PREEMPT AND ABORT
from any other initiator naming that key calls `scst_rx_mgmt_fn_lun()` on the
dying session: `percpu_ref_get` on a killed (possibly zero) ref, then the
READY `sBUG()`.  The core's own PR path violates `scst_rx_mgmt_fn`'s documented
"not concurrent with `scst_unregister_session`" contract; nothing orders them.
On this rig the window opens on **every** kill-fence whose P&A lands ~60 s after
the kill (iSCSI nop-in 30 s + response timeout 30 s), which is the normal fence
timing; hundreds of kill laps missed the few-ms window before this one hit it.

**The fix — `+caw-abort-reclaim.5`** (`/src/scst`, design-consult reviewed):

- `scst_pr_abort_reg()` pins the registrant's session with
  `percpu_ref_tryget()` (not `_live`: it must succeed on a killed ref while
  references remain).  Zero means every command of that session has already
  completed and been released, so there is nothing to abort and the PR ABORT
  guarantee already holds: log `PR ABORT: registrant ... session ... is already
  released ... skipping` and move on.
- `scst_post_rx_mgmt_cmd()` exempts a core-originated `SCST_PR_ABORT_ALL` from
  the READY assertion (it never calls the registrant's target driver; its own
  ref keeps the session and its tgt_devs alive; a SHUTDOWN-phase session with
  commands still draining is a legitimate target) and logs `PR ABORT ALL
  admitted on session ... in shut_phase N`.  Target-driver TMs keep the sBUG.
- `scst_rx_mgmt_fn()` rolls the two PR abort counters back on a failed post
  (previously the PR command would wait forever — latent upstream bug).
- Test-only module parameter `scst.pr_abort_shutdown_delay_ms` holds a session
  in both halves of the window on purpose; `scripts/clyde_preflight.sh` refuses
  a rig run while it is non-zero and blocks any SCST older than `.5`.
- `tests/scst_pr_abort_shutdown_race.sh` drives both halves deterministically
  from two unmounted nodes (window A: admitted during SHUTDOWN; window B:
  tryget fails at refcount zero) and a no-knob stress loop; asserts both log
  lines, both P&As rc=0, keys gone, no BUG/Oops/CRITICAL on the host.

**Do not try to reproduce this on an unpatched module either** — the "before"
arm is the pstore record; the host panics.

---

## Crash D — 2026-09-01 08:45: GPU PCIe P2P (not MXFS)

> **CORRECTED 2026-09-02.**  The original version of this section covered
> *both* 2026-09-01 crashes under one GPU-P2P disposition and stated that
> "both traces are preceded within seconds by `NVRM: nv_dma_map_peer`".
> **That is false for the 07:15 crash**, whose pstore record contains no
> `NVRM` line of any kind.  The 07:15 crash was disposed on evidence
> belonging to the 08:45 crash.  It is now Crash D-bis below, reopened.
> The disposition for 08:45 stands on its own evidence and is unchanged.

Ledger (DISPROVED): `D-HOST-CLYDE-DOUBLE-CRASH-GPU-PCIE-P2P-NOT-MXFS-0901`,
scope now narrowed to this crash only.

**08:45 CDT** — the boot that began 07:17 died at uptime 5378 s: `BUG: NULL
pointer dereference 0x8` in `kfree_rcu_monitor` — `list_del` on a bulk page
whose `list_head` was `{next=NULL, prev=NULL}` — then `panic_on_oops`.
Record `.evidence/crash_20260901_134858/`.

**Why it is the GPU and not the rig.**  That boot logs 12 `NVRM:
nv_dma_map_peer` peer-to-peer mappings (60 more inside the pstore record
itself) and 8 Xid lines — `Xid 43, pid=44463, name=train.py` and `Xid 13
Graphics SM Warp Exception: Out Of Range Address` on two GPUs at 08:18:58,
27 minutes before the die.  SCST had been unloaded at 07:17:56 and is absent
from `Modules linked in`; every test VM was off; the crash latch had halted
the rig at 07:17:51; nothing ran `run.sh`.  The user confirmed at the time:
*"there was a crash this morning NOT due to mxfs … was playing with pci2
p2p."*

**Operational note.**  The same hardware runs the fleet, so a GPU P2P
experiment concurrent with a board run would take the 32 VMs, the LUN and the
journal down with it — schedule them apart.

---

## Crash D-bis — 2026-09-01 07:15: corrupted folio order, source UNPROVEN

Ledger: `D-HOST-CLYDE-CRASH-XAS-SPLIT-ALLOC-FOLIO-ORDER-CORRUPT-0901A`
(critical, **OPEN**).  Record `.evidence/crash_20260901_121751/`.

A 9.07-day boot died at uptime 784227 s with **seven** `WARNING: at
lib/xarray.c:1010 xas_split_alloc+0x12e/0x180` across two unrelated processes
in the same millisecond — `systemd-journal` (PID 936, CPU 31) and `train.py`
(PID 1839647, CPU 30) — each through
`filemap_fault → __filemap_get_folio → filemap_add_folio → __filemap_add_folio`,
then a fatal exception at `xas_load+0x3c/0x60` and `Kernel panic`.

**What the registers prove.**  `RCX=0xc` = `2 * XA_CHUNK_SHIFT`, so the failing
test is `WARN_ON(xas->xa_shift + 2 * XA_CHUNK_SHIFT < order)`.  The `order`
operand reads **0xbd (189)** in one instance and **0xdf (223)** in another, and
`entry` (RSI) is `0xc1d8c166c1c7c1d1` / `0xc21dc0d8c0fcc209` — neither a valid
kernel pointer.  `R13` holds a vmemmap address.  A folio order of 189 is
impossible: this is a **corrupted `struct page`/folio fed into the page
cache**, hitting two unrelated processes milliseconds apart, so the corruption
is broad rather than one bad folio.

**Ruled out — GPU PCIe P2P.**  `grep -c nv_dma_map_peer` over every file of
this record returns **0**, and `grep NVRM` returns **nothing at all**, against
120 hits in the 08:45 record.  `journalctl -b -3 -k` logged zero
`nv_dma_map_peer`; its only 19 NVRM lines are all from boot (static BAR1
mapping and an `nvidia-persistenced` API-version mismatch).

**Not supported either — an MXFS rig or Claude-session cause.**  Zero files in
`/src/mxfs` were modified between 2026-08-30 00:00 and the crash; no Claude
transcript under `~/.claude/projects/-src-mxfs` was touched after 2026-08-31;
`ccloop` logged no session that day; `journalctl -b -3 -k --since '05:45'`
returns `-- No entries --` (**no kernel line at all in the last 90 minutes**);
and the last rig line of that boot is `Aug 29 13:23:03 … Reservation conflict
(dev mxfs … test20)`, 2.7 days earlier.  SCST *was* loaded — it appears in
`Modules linked in` — but completely idle.

**The correlation worth testing, which is not a cause.**  In the three minutes
before the panic: `gemma-4-31B-it-INT8.service` (a vLLM server that had
consumed **1 d 9 h 45 min** of CPU) was stopped by hand at 07:12:42, an
interactive ssh login landed at 07:15:37, and `train.py`'s PID (1839647) is
*higher* than that sshd's (1839082).  A large model server torn down and a
training job started is exactly the reclaim and page-cache churn under which a
latent `struct page` corruption surfaces.

**Do not re-dispose this without new evidence.**  "Probably the GPU" is what
produced the bad filing in the first place.  Progress is gated on the same
instrumentation as Crash E below.

**Process lesson.**  A disposition covering two incidents must carry
*per-incident* evidence.  "Both traces show X" must be checked against **both**
records before it is written down.

---

## Crash E — 2026-09-02: a silent reset that left NO fault record at all

Ledger: `D-HOST-CLYDE-SILENT-RESET-NO-FAULT-RECORD-RIG-LIVE-0902` (critical,
**OPEN** — no attribution is available and none is asserted).

This one is different from every incident above and must not be filed with
them.  clyde died at **06:10:27 CDT** (up 21 h 22 m) and was back at 06:13:44.
It left **nothing**: `/sys/fs/pstore` empty at the next boot, `systemd-pstore`
skipped on `ConditionDirectoryNotEmpty`, `mxfs-crash-latch` logged *"no new
crash records"* at 06:13:54, no `.rig_halt`, and not one `BUG:`/`Oops`/
`WARNING`/panic line in the journal.  The last journal entry is a service that
**completed normally** (`aitrader-cycle-ledger` … `Finished`, 06:10:27).  An
instantaneous total stop — not a wedge, not a progressive failure.

ERST is not broken: this boot logs `ERST … support is initialized` and
`pstore: Registered erst as persistent store backend`, and it captured nine
oopses on 08-20 and seven on 09-01.  **The kernel never reached its own oops
path.**  That means a triple fault or a hardware-initiated reset.

**What the evidence rules out**

| Candidate | Ruled out by |
|---|---|
| the three known SCST memory-safety defects | all fixed in the installed `+caw-abort-reclaim.5` (`scst.ko` sv `49601BF23C0AF27910B7E2C`); `scst_pres.c:2634-2665` carries the `.4` signed/`offset` bound. Every one of them produced a loud oops with an SCST frame; this produced none |
| the PR READ FULL STATUS overflow specifically | its precursor `Too big response data len` never appeared, and the kmsg guard ran the full 21 h boot with no halt, precursor or flood trip |
| the GPU PCIe P2P cause of Crash D | boot -1 has **zero** `nv_dma_map_peer` lines and **zero** Xid errors (the boot that died of it had 12 and 8) |
| OOM / allocation failure | none in boot -1 |
| the headroom wedge | `/` 85 % used, 273 G free — inside the preflight floor |
| a log flood | peak 1303 kernel lines/**minute**, vs the 182 lines/**second** wedge class |
| a host-wide stall | userspace was healthy throughout — cron ran at 06:00:01, `aitrader-snapshot` wrote id=7335 at 06:00:24 |

The rig *was* live (unlike Crash D): libvirt was power-cycling test2 on a
~2.5 min loop, all 32 initiators hit the 30 s `conn_rsp_timer` at 05:59:31-41
and reconnected at 06:03, and 865 `Reservation conflict (dev mxfs)` lines ran
up to 06:09:03.  That is context, not attribution.

**Why it cannot be root-caused yet — the real finding.**  clyde has no
evidence channel that survives a fault which never reaches the oops path:

- **no BMC.**  `ipmi_si` is not loaded and SMBIOS type 38 (IPMI Device
  Information) is **absent** — the ASMB card is not present or not enabled in
  BIOS.  There is no SEL to read, and installing `ipmitool` would not create
  one.
- **no netconsole** (not loaded, no `modprobe.d` config) — the one channel that
  survives a hard lockup or triple fault.
- **no kdump.**  No `crashkernel=` on `/proc/cmdline`, `kdump-tools` inactive,
  `/var/crash` empty.
- **no metrics.**  `sysstat` is installed and its cron fires every 10 minutes,
  but `/etc/default/sysstat` has `ENABLED="false"` and `/var/log/sysstat` is
  empty — no CPU/memory/IO history across the event.
- `kernel.hardlockup_panic=0`, `kernel.softlockup_panic=0` — a lockup prints
  instead of producing a recorded panic.
- **the IOMMU is off** (`iommu=off intel_iommu=off intremap=off`) on a host
  running 3-4 CUDA GPUs, out-of-tree `vmmon`/`vmnet`/`vboxdrv`, an out-of-tree
  SCSI target and 32 KVM guests.  Any device can DMA anywhere in physical
  memory, with no protection *and no fault report naming the offender*.  That
  is also why this whole family of incidents surfaces in unrelated subsystems
  (page-cache xarray, jbd2 `buffer_head`, `kfree_rcu` lists, QEMU page tables).

**`mxfs-crash-latch` cannot latch this failure mode** — it keys on a pstore
record, and there was none, so the rig was free to restart into the same
conditions.  That gap is part of the defect.

Ordered actions are in the ledger record.  [a] enable sysstat and
[b] configure netconsole need no reboot.  [c] `crashkernel=` and any change to
`iommu=off` are kernel-cmdline changes and therefore need a reboot, which under
the never-reboot-the-host rule only the user may perform — and `iommu=off` is presumed deliberate (GPU
P2P / passthrough), so it is a decision with a real trade-off, not a defect to
be silently "fixed".

---

## The guardrails

| Layer | What it does | Fails how |
|---|---|---|
| `scripts/scst_setup.sh` | resets the SCST trace mask on every rig build | n/a — it is a reset |
| `scripts/clyde_preflight.sh` | gate: halt flag, kernel taint, D-state count, SCST version, trace mask, kernel-log rate, filesystem headroom, journald caps | exit 1; `run.sh` aborts with exit 3 |
| `tools/clyde_kmsg_guard.sh` (systemd `mxfs-clyde-guard.service`) | tails `/dev/kmsg`; halts the rig on corruption, precursor, or flood | writes `.rig_halt`, snapshots evidence to `/src` (NFS, not the root ext4), bound-pauses guests on corruption only |
| `tests/scst_pr_bounds_check.sh` | proves the PR overflow is fixed and the installed modules match | exit 1 |
| `tests/scst_pr_abort_shutdown_race.sh` | proves the PREEMPT-AND-ABORT / session-teardown race is handled on the installed `.5` (both windows, knob-driven) | exit 1 |
| journald drop-in | bounds what a flood costs on disk | n/a |

**What the guard deliberately does not do** (the never-reboot-the-host rule / the unkillable-wedge rule): it never
reboots or sysrqs clyde, never `virsh destroy` (measured 2026-08-20: every one
timed out), never `rmmod`s SCST, never touches `dmsetup`, and never issues a
global `sync`.  Each of those joins the queue behind the stuck resource rather
than relieving it.  It reads only `/proc/<pid>/stat`, `comm` and `stack` —
never `cmdline` or `maps`.

Clearing a halt is deliberate:

    tools/clyde_kmsg_guard.sh status
    tools/clyde_kmsg_guard.sh clear

---

## Decisions taken 2026-08-21

1. **The LUN and guest images stay on the root filesystem.**  The operator is
   not local to clyde and cannot add a device, so the coupling is an accepted
   constraint, not an action item.  Headroom is therefore the only remaining
   lever and is set tight: the preflight fails a **local** filesystem above
   **88% used** or below **120 G free** (the 2026-08-20 wedge was at 92% with
   ~145 G free — a 60 G floor would not have caught it, the 88% ceiling
   would).  Network filesystems get a plain "not actually full" check instead;
   a 12 TB NFS server at 89% is not a jbd2 hazard, and blocking runs over it
   is the kind of noise that gets a gate switched off.
   The preflight prints the coupling as a `NOTE`, not a warning, for the same
   reason.

2. **`kernel.panic_on_oops=1` is enabled**, in `/etc/sysctl.d/99-mxfs-host-safety.conf`,
   together with **`kernel.panic=30`**.  The timeout is not optional: the
   default `kernel.panic=0` makes a panic hang forever, which for an operator
   who is not physically at the machine is strictly worse than the status quo
   — a guaranteed dead box instead of one that might still answer sysrq.
   Supporting pieces:
   - `kernel.sysrq` raised 176 → **184** (adds bit 8, debugging dumps).  The
     reboot bit was already set but `echo w > /proc/sysrq-trigger` was refused,
     and a blocked-task dump is exactly the evidence both wedges needed.  The
     watchdog must **not** fire sysrq dumps automatically — on a host wedged by
     log volume, a task dump makes it worse.
   - `mxfs-crash-latch.service` (`tools/clyde_crash_latch.sh`) runs after
     `systemd-pstore` on every boot.  A pstore record it has not seen means
     this host crashed: it archives the record to `.evidence/crash_*` and halts
     the rig, so an automatic panic-reboot cannot loop back into the same crash
     with no evidence kept.  Seen records are tracked in `.crash_seen`.
   - Deliberately **not** enabled: `panic_on_warn` (far too broad with
     development code), `hung_task_panic` (D-state hangs are routine here —
     2026-08-20 reached 875 — it would reboot constantly), `softlockup_panic`
     (downstream of the oops `panic_on_oops` already catches), and
     `panic_on_rcu_stall` (attractive for a remote operator, but it can reboot
     through a state worth capturing — discuss before enabling).

3. **The stale host-side MXFS driver is gone.**  `/etc/modules-load.d/mxfs.conf`
   loaded DKMS `mxfs/0.9.25` into clyde's kernel at every boot — a three-month-
   old build of the filesystem under memory-safety investigation, resident in
   the host that runs the entire rig.  Removed: the modules-load entry, the
   loaded module (`rmmod`, refcount 0), and the DKMS instance.  The source at
   `/usr/src/mxfs-0.9.25` is renamed `.REMOVED-20260821` so DKMS cannot see it;
   delete it whenever convenient.
   `packaging/dkms.conf` in this repo is untouched — it is for building release
   packages, not for clyde.

## Still open

- **Upstream the SCST fix.**  The overflow is in SCST's own PR handler and is
  reachable by any initiator that probes READ FULL STATUS with a short buffer
  against a target with many registrants.  Not specific to this fork or to
  MXFS.
- **The other historical crashes.**  pstore holds records from 2026-08-07 and
  earlier that nobody has read.  Under the zero-defect bar a host-kernel oops is a
  first-class defect; these have never been dispositioned.

---

## Evidence locations (after the 2026-08-21 journal vacuum)

The journal was vacuumed 2.8 G -> 415 M, which discarded most of the
2026-08-20 boot.  Everything load-bearing was archived first:

| What | Where |
|---|---|
| wedge B boot journal, complete | `.evidence/wedges_202608/wedgeB_boot_20260821_full.klog.gz` |
| wedge A boot journal, flood removed (80,785 of 1,075,008 lines kept) | `.evidence/wedges_202608/wedgeA_boot_20260820_deflooded.klog.gz` |
| the actual oopses for both wedges | `/var/lib/systemd/pstore/*` (1.1 M, untouched — do not delete) |

A fourth harm of the trace flood turned up while doing this: journald's active
journal at the moment wedge A killed it survived as a 40 MB corrupted file
(`...journal~`).  It was unreadable to `journalctl`, and a raw scan found
**zero** fault markers in it — 42,000 lines of `scst_check_scsi_atomicity` and
nothing else.  Even the fragment that captured the exact moment of the wedge
had been filled with trace noise instead of the nine oopses.  It was deleted
after that check, which also cleared the "truncated, ignoring file" warning
`journalctl` printed on every invocation.

## A guest panic that nobody was listening for

Every test node is configured at boot to send its kernel log to the dev host
over netconsole:

```
netpoll: netconsole: remote IPv4 address 192.168.120.1
netpoll: netconsole: remote port 6666
```

Nothing listened on that port until 2026-09-10, so every datagram any guest
ever sent while dying was discarded by the host.

That matters because on this rig the netconsole stream is the **only** channel
that can carry a guest panic:

- A node that panics reboots, and its `dmesg` then starts at the new boot.
- `journalctl --list-boots` on these guests does not retain the boot that
  crashed — test1's list held two boots from ten weeks earlier and the
  post-crash boot, and nothing in between.
- `/sys/fs/pstore` and `/var/lib/systemd/pstore` are both empty on these
  guests, so systemd-pstore drains nothing at boot. An empty `/sys/fs/pstore`
  is not evidence that no crash occurred; on a guest whose machine type
  provides no pstore region it can never hold anything.
- `/var/log/libvirt/qemu/<node>.log` records a hypervisor-initiated
  destroy/start. A guest that resets **itself** — a panic with `panic=N`, a
  triple fault — leaves no entry there at all. So an absent libvirt event
  proves the reboot came from inside the guest; it does not tell you why.

With all four silent, a guest panic and a guest that "just rebooted" are
indistinguishable, and the second reading is the one a session reaches for.

`tools/netconsole_listen.sh start` runs the listener; `status` says whether the
port is being captured or discarded, and `tail` reads the log. It must be
running whenever the rig is doing anything that could kill a node. The guests'
`console_loglevel` is 1, so ordinary probe output does not reach netconsole and
the log cannot flood — but a panic prints at `KERN_EMERG` and does.

Verify it end to end rather than assuming it works, because a listener that is
running and receiving nothing looks exactly like a healthy rig:

```
tools/netconsole_listen.sh start
tools/mxfs_sshpass.sh test2 "echo '<0>PROBE' > /dev/kmsg"
tools/netconsole_listen.sh tail 5
```
