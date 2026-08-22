# Host safety — why clyde wedged twice, and what now prevents it

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
  >60 lines/s for two consecutive 5 s windows.  Baseline for comparison: a
  full 32-node campaign produces ~1 line/s on clyde.
- `/etc/systemd/journald.conf.d/50-mxfs-rig.conf` caps size and message rate.
  Defence in depth — the fix is not producing the flood.

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

## The guardrails

| Layer | What it does | Fails how |
|---|---|---|
| `scripts/scst_setup.sh` | resets the SCST trace mask on every rig build | n/a — it is a reset |
| `scripts/clyde_preflight.sh` | gate: halt flag, kernel taint, D-state count, SCST version, trace mask, kernel-log rate, filesystem headroom, journald caps | exit 1; `run.sh` aborts with exit 3 |
| `tools/clyde_kmsg_guard.sh` (systemd `mxfs-clyde-guard.service`) | tails `/dev/kmsg`; halts the rig on corruption, precursor, or flood | writes `.rig_halt`, snapshots evidence to `/src` (NFS, not the root ext4), bound-pauses guests on corruption only |
| `tests/scst_pr_bounds_check.sh` | proves the PR overflow is fixed and the installed modules match | exit 1 |
| journald drop-in | bounds what a flood costs on disk | n/a |

**What the guard deliberately does not do** (RULE 2 / RULE 2c): it never
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
  earlier that nobody has read.  Under RULE 6 a host-kernel oops is a
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
