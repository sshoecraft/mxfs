---
name: compiled-scst-iscsi-infra-wedge-recovery
description: SCST/iSCSI CAW-READ atomic wedge: root cause, no-reboot scst_unwedge recovery, stale-PR-blocks-mkfs, and storage topology.
metadata:
  type: project
tags: [compiled, scst, iscsi, infra, caw-wedge, recovery, storage-topology]
---

# SCST/iSCSI target wedge — diagnosis, no-reboot recovery, and storage topology

Central topic: the recurring **SCST CAW↔READ scsi-atomic deadlock** that wedges the
clyde iSCSI target during multi-node MXFS runs, the **stale-PR-blocks-mkfs** symptom it
produces, the **`scst_unwedge.ko` no-reboot recovery** procedure, and the storage-stack
topology (SCST iSCSI vs the later LIO/tcm_loop pivot) these all run on. RULE 2 governs
everything here: **never reboot clyde** — host reset is the user's call only.

---

## Root cause of the wedge (converged across sessions)

The canonical trigger: a **COMPARE AND WRITE (op 0x89, CAW)** and one or more overlapping
**READ (op 0x28 / 0x10, sometimes labelled 0x88)** on the SAME lba on shared vdisk
`disk1` each register the other as its `scsi_atomic` blocker → an **A↔B deadlock cycle**.
The CAW typically also blocks dozens more readers (`blocked_cnt` = 48–88). SCST's
`scst_suspend_activity` / `scst_unblock_aborted_cmds` only walks the blocked/deferred
lists and leaks the atomic-blocked cmds, so the cycle never breaks.

Original sess14 framing ([[sess14-scst-wedge-host-reboot]], 2026-06-10, build `9C2D4FA6`):
SCST runs CAW / WRITE SAME as **strictly-serialized** cmds (block device, drain, exec,
unblock). A serialized cmd that exceeds the initiator 60s timeout → guest EH `ABORT_TASK`
→ abort can't complete ("deferring ABORT", cmd stuck in `EXEC_CHECK_BLOCKING`) →
escalation to `LUN_RESET` → `NEXUS_LOSS` → conn drop. Each conn drop spawns an
`iscsi_conn_cleanup` kthread stuck forever in `close_conn` msleep — these accumulate,
pin per-device command refcounts, so the device outstanding-count NEVER drains again.
Afterwards **every** strictly-serialized cmd (including mkfs's WRITE SAME slot-table zero,
any CAW) blocks forever even on a quiet LUN. `mkfs_mxfs` was the canonical
victim/trigger: it zeroed the 65600-block CAW slot table as one `BLKZEROOUT`→WRITE SAME(16).

**Detection recipe:** on clyde, `ps -eo stat,comm | awk '$1 ~ /^D/'` — any
`iscsi_conn_cleanup` in D-state = wedged; `dmesg | grep EXEC_CHECK_BLOCKING`;
portal 3260 not listening; `/sys/kernel/scst_tgt/suspend=1`; backing sd devs
`transport-offline` with `inflight=0` (**not** a block-layer hang — pure SCST cmd-state
deadlock).

**Why it hits all nodes:** historically all 16 VMs shared ONE host iSCSI session
(host-device passthrough), so one guest's EH escalation and PR registrations (per-I_T-nexus)
were shared across all nodes ([[sess14-scst-wedge-host-reboot]]).

---

## The stale-PR-blocks-mkfs symptom

After FS shutdowns, `disk1` is left with a stale **"Write Exclusive, registrants only"**
(WE-RO, PR type 5) reservation held by a DEAD key + ~11–16 ghost registrants (same IQN,
different ISIDs). `fresh_cluster_mount`'s `sg_persist --clear` / `--register-ignore`
**fails to stick**: PR generation increments but our key never appears in `--read-keys`,
so preempt no-ops. Manual mkfs then fails: `pwrite at offset 4096 failed: Invalid exchange`
(EBADE = SCSI reservation conflict); `sg_persist --in --read-reservation` shows the dead
holder ([[sess47-scst-wedge-pr-recovery-procedure]], [[sess51-scst-caw-read-wedge-full-recovery-proven]]).

Key insight: **registration won't stick because the CAW↔READ atomic wedge is blocking it.**
The PR cannot be cleared until the wedge is cleared first. What does NOT work:
`echo ... > pr_state` (rc=1, needs device suspended); `echo path > pr_file_name`
("Device or resource busy" while any initiator is connected).

---

## The no-reboot recovery — `scst_unwedge.ko` (REUSABLE, PROVEN)

Built in [[sess43-scst-unwedge-and-p136]], refined [[sess47-scst-wedge-pr-recovery-procedure]],
fully executed+proven [[sess51-scst-caw-read-wedge-full-recovery-proven]], re-proven after
a 5-session false "reboot-only" conclusion in [[sess69-scst-wedge-cleared-NO-REBOOT-via-unwedge]].
Lives in tree: `scripts/scst_atomic_wedge_diag.py` + `scripts/scst_unwedge/`.

**Critical correction (sess69):** sessions 14/15/67/68 repeatedly (and wrongly) concluded
"unrecoverable, only a host reboot fixes it" and sat blocked ~5 sessions. **That was WRONG
— the sess43/47 unwedge clears THIS exact wedge in seconds.** Always run the unwedge
procedure before ever concluding "needs reboot".

Steps:

1. **Diagnose (read-only, /proc/kcore).** `disk1` is mid-unregister so it is OFF
   `scst_dev_list` — you MUST walk **`vdev_list`**, which needs `scst_vdisk.ko` symbols at
   the REAL path `/lib/modules/$(uname -r)/extra/dev_handlers/scst_vdisk.ko` (NOT
   `.../extra/scst_vdisk.ko`). Section addrs from
   `sudo cat /sys/module/scst{,_vdisk}/sections/.{text,data,bss,rodata}` — run the `cat`
   AS ROOT; `$(cat ...)` inline in the gdb line runs unprivileged → "Permission denied".
   Then `gdb -batch` with `add-symbol-file` for both `scst.ko` and `scst_vdisk.ko`,
   `core-file /proc/kcore`, `-x scripts/scst_atomic_wedge_diag.py`. It prints each disk1
   cmd's `scsi_atomic_blockers`/`blocked_cnt`.
2. **Identify the cycle:** the CAW (op 0x89, `blocked_cnt`=N large) and the ONE READ whose
   `blocked_cnt`=1 (it holds the back-edge). Verify A↔B: READ.blocked_arr==[CAW] and
   CAW.blocked_arr[0]==READ. (sess47 saw TWO CAWs sharing one READ — break each cycle.)
3. **Break ONE edge:** `cd scripts/scst_unwedge; sudo insmod scst_unwedge.ko
   blocker=0x<READ> blocked=0x<CAW>; sudo rmmod scst_unwedge`. `blocker` = the READ holding
   the edge; `blocked` = the CAW to requeue. The module self-verifies A↔B topology under
   `dev_lock` (–EBUSY no-op if wrong), frees blocker's array, zeros CAW blockers, requeues
   the CAW on the active list. Offsets verified identical vs running scst.ko first.
   dmesg: `scst_susp_wait ... returned 0` + `__scst_resume_activity suspend_count 0 left`.
   **Instantly: D-state 92→0, iscsi_conn_cleanup 90→0, suspend→0, modprobe/scstd complete.**
   Addresses are per-wedge (e.g. sess69 CAW=`0xffff8a681dd7e5c0`, READ=`0xffff8a5ea461a680`)
   — re-diagnose each time.
4. **Restart userspace target** (scstd died in `do_exit`, scst_vdisk may have unloaded):
   `sudo systemctl restart scst` → portal LISTENS on 3260, targets back.
5. **Re-login host iSCSI** (clyde IS the initiator; VMs use by-path passthrough): loop
   `iscsiadm -m node -T iqn.2026-05.local.mxfs:$t -p 127.0.0.1:3260 --login` for
   disk1, disk1n2..disk1n16 → all 17 sd devs go `running`. Shared LUN `disk1` = /dev/sdd
   (sess69) or /dev/sda (older) on clyde.

**DO NOT just `del_device disk1`** ([[sess51-scst-caw-read-wedge-full-recovery-proven]] —
tried it, made it worse): `del_device` → `scst_acg_del_lun` → `scst_wait_for_tgt_devs` is
an UNBOUNDED `while(cmds>0) msleep`. With cmds wedged, `scst_uid` (single SCST sysfs work
thread) goes D-state → ALL SCST mgmt blocked (can't even add disk1b targets), and the
device stays on `vdev_list` mid-`vdisk_del_device`. If you already deleted it, recreate:
`echo 'add_device disk1 filename=/home/steve/disk-1.img;async=1;o_direct=1' >
/sys/kernel/scst_tgt/handlers/vdisk_fileio/mgmt` (PR now generation=0 CLEAN), remap LUN0
on all 16 targets, re-login host iSCSI.

**PR clear after unwedge (registration now sticks):** `RK=0xabcd1234;
sg_persist --out --register-ignore --param-sark=$RK /dev/sda` (verify $RK in `--read-keys`);
`sg_persist --out --preempt-abort --param-rk=$RK --param-sark=<deadholder> --prout-type=5`;
`sg_persist --out --clear --param-rk=$RK` → "NO reservation held". Then
`tools/mkfs_mxfs /dev/sda` → rc=0; `tests/reset4.sh 16` → RESET_OK
([[sess47-scst-wedge-pr-recovery-procedure]]).

---

## The upstream SCST fix — `caw-abort-reclaim` ([[sess78-scst-caw-abort-reclaim-fix-and-p78-torn-format-barrier]])

Root-caused + fixed by a SEPARATE Claude session in a SEPARATE repo `/src/scst` (NOT the
MXFS tree). Fork github.com/sshoecraft/scst, branch `caw-abort-reclaim`, commit `488704520`
(local master fast-forwarded `e2c57de2d`→upstream `83745c0a2`, 8 commits, none touching the
blocking/atomic/abort path). Backup patch `/tmp/scst-caw-abort-reclaim.patch`.

- Fix in `scst/src/scst_targ.c`: new `__scst_check_unblock_aborted_scsi_atomic_cmd()`
  detaches an aborted atomic-blocked cmd from every blocker's `scsi_atomic_blocked_cmds[]`
  (preserving the non-NULL⇔count>0 invariant, freeing the array when empty to avoid UAF) and
  re-activates it; `__scst_unblock_aborted_cmds()` gains a `dev_exec_cmd_list` reclaim walk
  in the same dev_lock/IRQ-disabled region. Closes the orphan window where an aborted
  atomic-blocked cmd whose blocker never completes (mass NEXUS_LOSS under CAW storm) pins a
  conn refcount forever.
- Doc correction: CAW is SCSI_ATOMIC, not serialized; the CAW↔READ cycle is "impossible by
  construction" — yet it happened, hence the reclaim path.
- **Version marker:** `modinfo -F version scst.ko` → `3.11.0-pre+caw-abort-reclaim.1`.
  Currently-installed baseline is `3.11.0-pre` (OLD, unfixed).
- Deploy: `cd /src/scst/scst && make && sudo make install` to
  `/lib/modules/$(uname -r)/extra/scst.ko`, then reload scst (umount mxfs on all nodes +
  iSCSI logout first, or virsh reset). **Reloading the scst module is NOT a host reboot —
  RULE 2 permits it.** As of sess72/78 this fix was BUILT but **NOT yet installed/verified**.

---

## Prevention / infra hardening

- **Chunked BLKZEROOUT** ([[sess15-run14d-wedge-recurrence-and-silent1]], v0.4.11):
  `tools/mkfs_mxfs.c zero_region` now issues `BLKZEROOUT` in **4MB chunks** instead of one
  ~33MB WRITE SAME — removes the strictly-serialized cmd that starved >60s → the wedge
  trigger. (sess14 first flagged: consider chunking/regular-write fallback.)
- **Pre-mkfs rmmod barrier** (sess15): every node verified umounted+rmmod'd (6 retries)
  before NODE0 mkfs — mkfs racing a live CAW heartbeat was a wedge trigger.
- **Guest SCSI timeout widen:** `echo 180 > /sys/block/sda/device/timeout` per node —
  prevents 30s-timeout→ABORT_TASK→nexus-loss under load, independent of transport
  ([[test-cluster-scst-stack]]).
- **Never TaskStop a cluster run mid-test** ([[sess47-scst-wedge-pr-recovery-procedure]]):
  killing a `posix_phase_timing`/`run_tests` run mid-test leaves remote orphans holding
  ilocks, can crash/shut-off VMs (11/16 spontaneously `shut off`), and re-triggers the wedge.
  Let it finish/fail, THEN harvest dmesg (persists). Contaminated orphans also cause false
  SESS50-STARVE hangs — `pkill -f "run_tests|mxfs_test|find /mnt|rm -rf /mnt"` on all nodes
  and prefer a full `scripts/cluster_reset_n.sh 16` + `reset4.sh 16` before trusting a result.
- **NEVER reboot to recover** ([[sess15-run14d-wedge-recurrence-and-silent1]]): the old
  `@reboot`-hook + `sudo reboot` protocol was followed and **hung clyde hard — user had to
  HW-reset**. This is the origin of RULE 2. The `scripts/clyde_boot_recover.sh` @reboot cron
  from sess14 (self-disarming: wait scst + target, iscsiadm login with node.startup=manual,
  wait /src NFS, then `ccloop --resume-run`) is legacy — do not rely on reboot at all.

---

## Other infra-recovery notes

- **VMs fail virsh-start, iSCSI LUN dead (ENXIO)** ([[sess50-infra-iscsi-recovery-and-mkfs-busy]]):
  by-path symlink exists and session logged-in, but `dd if=/dev/sdX` → ENXIO;
  `iscsiadm --rescan` does NOT fix. FIX: targeted logout+login of the affected targets on
  clyde (`iscsiadm -m node -T iqn.2026-05.local.mxfs:disk1nN --logout` then `--login`).
  SCST service stays `active` throughout — do NOT restart it first.
- **mkfs "device is busy (mounted?)" with nothing mounted** (sess50): the loaded mxfs module
  opens /dev/sda at insmod (CAW disklock heartbeat, kworker/R-mxfs, refcount>0), so O_EXCL
  mkfs fails and rmmod fails "Module in use". Correct flow: do NOT manually insmod before
  reset4; use `scripts/cluster_reset_n.sh 16` (virsh destroy+start) so VMs boot with NO
  module, then reset4/fresh_cluster_mount mkfs's in a clean rmmod window.
- **Sequential per-node prep** (sess50, sess51): `cluster_reset_n.sh`'s parallel
  `prep_tcm_node.sh | ssh` on 16 nodes at once intermittently PREP_FAILs ~12/16 from NFS read
  contention on mxfs.ko; run prep SEQUENTIALLY → succeeds on all.
- **NFS export evaporates after host churn** (sess43): re-add with `exportfs -o
  rw,sync,no_subtree_check,no_root_squash,fsid=4321 192.168.120.0/24:/src/mxfs` (fsid= is
  required), remount each node `mount -t nfs 192.168.120.1:/src/mxfs /mnt/mxfs-src`.
- **QNAP iSCSI target dies under storm** ([[sess72-tcp-dlm-scaling-harness-fixed-invalid-sweep]]):
  QNAP `192.168.1.4:3260` went persistently CLOSED under a 16-node mkdir storm (its
  NFS/SSH/web stayed up — only the iSCSI target service died; no admin creds to restart).
  The QNAP appliance target does not survive this load; TCP-DLM-on-QNAP blocked until user
  restarts it. sess72 pivoted to running TCP DLM on the SCST LUN /dev/sda instead
  (`scripts/scst_scale.sh`, force_transport=1). Two INVALID qnap_scale.sh sweeps were
  discarded (mounted stale un-formatted FS because mkfs_mxfs binary missing → added MKFS_OK
  abort guard `FORM-FAIL-MKFS`; per-step iSCSI logout/login hardening raced the form →
  reverted to simple `--login`; harden once cluster-wide, not per-step).

---

## Storage-stack topology (evolution)

**Per-node SCST rebuild — sess26** ([[sess26-storage-infra-pernode-sessions]], 2026-06-11):
- Cluster moved off dead `disk1b` (stale WERO PR key 0x43356bc + 46 zombie closing sessions,
  cleanup threads D-state — still there until reboot) onto SCST device **`disk1`** (backing
  `/home/steve/disk-1.img`, 20G fallocated).
- `disk1` recreated with **`async=1; o_direct=1`** (create-time params). Root cause proven:
  buffered pwrite to one backing file serializes all nodes on the inode i_rwsem → ~930MB/s
  ceiling; async+o_direct → ~2.8GB/s NVMe-bound (16-node parallel dd 10.5s→3.8s/node).
- **16 per-node iSCSI sessions/targets** `iqn.2026-05.local.mxfs:disk1` + `disk1n2..16`, all
  LUN0→disk1; clyde logs into all 16, each VM points at its own by-path device. This makes
  **PR fencing REAL** (each node a distinct nexus, own key = node_id, WERO enforced) — with
  the old shared single-session nexus it was theater. Consequence: stale-epoch nodes get
  legitimately fenced → `heartbeat write failed: -52` (EBADE) → shutdown; ALWAYS full virsh
  destroy/start of all 16 before criterion runs after any aborted run.
- `/etc/scst.conf` NOT updated (runtime-only) — after a clyde reboot the disk1n2..16 targets,
  LUN mappings, and async/o_direct flags must be re-created. VM XMLs are persistent.
- multipath.conf blacklists vendor `SCST_FIO`.
- Scaling truth (build `2D425C215C` v0.5.5): honest 16-writer pre-fix 1n=2470…16n=14072
  (569%); post-fix 1n=4037…16n=6928 (171%, gate ≤150%) — flat 1→8n, failure isolated to
  8→16n. Intermittent CAW storm on one node (104k caw_lock / 110k FUA reads / 22.2s wall vs
  ~850/5.2s normal) NOT yet root-caused (suspect ag_lock_nb trylock loop, not inode_lock).

**MAJOR PIVOT 2026-06-14 — LIO/tcm_loop replaces SCST iSCSI** ([[test-cluster-scst-stack]]):
- The entire SCST iSCSI stack was TORN DOWN and replaced by a **LIO fileio + tcm_loop single
  shared LUN, LOCAL, no iSCSI/network/initiator-login**. This **dodges the sess14-68
  iscsi-loopback host-wedge class entirely** (no iscsi_conn_cleanup kthreads).
- Chain: `/home/steve/disk.img` (50G fallocated) → LIO **fileio** backstore `mxfs`
  (write-through, `emulate_write_cache=0`) → **tcm_loop** LUN0 → local `/dev/sdX`
  (vendor `LIO-ORG`, model `mxfs`). `scripts/lio_tcm_setup.sh {setup|status|teardown}`.
  Stable symlink `/dev/mxfs-shared` → live sdX (sdX letter + WWN change across re-setup;
  re-run setup after any host reboot). `scripts/wire_vms.sh` / `scripts/define_vms.sh`
  (canonical, all 32 identical: 4 vCPU/4096MB, virtio-scsi, shareable /dev/mxfs-shared→sda).
  Full doc `docs/test_infra_lio_tcm.md`.
- Cluster is **no longer partitioned** — all test1–test32 available for /src/mxfs (old
  test1-16=v5 / test17-32=.1 split GONE). All are libvirt VMs under `qemu:///system` (root),
  shared LUN `/dev/sda`, mount `/mnt/shared`. Reach nodes via
  `tools/mxfs_sshpass.sh <host> /tmp/.mxfs_pass`. `/src` is NFS from `192.168.1.4:/src`
  (do NOT touch clyde exports).
- **Trade-off:** LIO/tcm_loop does **NOT do SCSI CAW reliably** (the original reason the
  project moved to SCST) — it is for testing the **TCP DLM** transport (`force_transport=1`,
  needs no CAW/PR). For CAW testing, SCST is still required. `tools/prep_tcm_node_scst.sh`
  still keys on vendor `SCST_FIO` + a live `sg_compare_and_write` CAW check — both wrong for
  LIO (`LIO-ORG`/`mxfs`, no CAW) and must be updated before use on this stack. Note: test2
  historically under-provisioned (2 vCPU/2GB) — verify before scale tests.

---

## The `silent=1` residual (separate from the wedge, but surfaced alongside it)

[[sess15-run14d-wedge-recurrence-and-silent1]]: on build `9C2D4FA6`, `zero_silent_loss`
(480s budget, ~120s/iter incl. remount) hit **silent=1 ~1 iter in 6** (pre_drop=1599 AND
post_drop=1599 — a name never durably visible, before and after drop_caches). Zero P108,
zero DABUF_MAP_HOLE, zero shutdowns in the all-16 dmesg harvest (forensics under
`.ccloop/runs/14d31183-.../forensics-s15/`). A NEW bug class, not the old dir-block families.
Post-hoc name-ID was impossible (iter2 re-mkfs wiped the namespace), so per-node error
capture + on-loss missing-name enumeration were built into the workload script — the next
failing run self-diagnoses.

---

## MXFS-side items co-located in these memories (not infra, brief pointers)

- **P136 drain-rescue** (build `7BD3933D`, KEEP, [[sess43-scst-unwedge-and-p136]]): fixes
  cluster-wide shutdown where an orphaned IFLUSHING cluster buffer never got submitted →
  AIL item orphaned → EX never released → peers STARVE 120s → SHUTDOWN_CORRUPT_INCORE. Fix in
  `mxfs_ail_drain_inode_sync`: at iter≥512, if IFLUSHING && pin==0 && buf not on delwri &&
  trylock && b_list empty → delwri-queue+submit (P136-DRAIN-RESCUE). Real remaining blocker:
  16-node concurrent shared-dir COLD-cache create loses entries (781/800) — durable dir-block
  lost-update.
- **P78 torn-dinode barrier** (build `7D1492FC`, [[sess78-scst-caw-abort-reclaim-fix-and-p78-torn-format-barrier]]):
  fixes `posix_semantics_multi16` >600s; `xfs_iflush` forces the matching data-fork bit into
  `ili_fields` on multi-node DIR so the literal area is rewritten to match di_format after a
  LOCAL→EXTENTS conversion (detector `P78-FMT-TORN-FIX`). NOT yet deployed/verified.

---

*Sources folded: [[sess14-scst-wedge-host-reboot]], [[sess15-run14d-wedge-recurrence-and-silent1]],
[[sess26-storage-infra-pernode-sessions]], [[sess43-scst-unwedge-and-p136]],
[[sess47-scst-wedge-pr-recovery-procedure]], [[sess50-infra-iscsi-recovery-and-mkfs-busy]],
[[sess51-scst-caw-read-wedge-full-recovery-proven]], [[sess69-scst-wedge-cleared-NO-REBOOT-via-unwedge]],
[[sess72-tcp-dlm-scaling-harness-fixed-invalid-sweep]],
[[sess78-scst-caw-abort-reclaim-fix-and-p78-torn-format-barrier]], [[test-cluster-scst-stack]].*
