---
name: compiled-rig-infra-physrig-and-project-decisions
description: Compiled: rig/infra traps that fabricate FS failures, the physical QNAP/PVE campaigns, the NET2 planning arc, and standing project decisions.
metadata:
  type: project
tags: [c, o, m, p, i, l, e, d, ,,  , i, n, f, r, a, ,,  , r, i, g, ,,  , p, h, y, s, r, i, g, ,,  , q, n, a, p, ,,  , p, v, e, ,,  , n, e, t, 2, ,,  , s, c, s, i, p, r, ,,  , p, r, o, j, e, c, t, -, d, e, c, i, s, i, o, n, s, ,,  , h, o, s, t, -, n, o, i, s, e]
---

# Rig infrastructure, the physical campaigns, and standing project decisions

## 1. Infrastructure traps that fabricate filesystem failures

Every one of these presented as an MXFS coherency or liveness defect. Check them **before**
opening a ledger entry.

- **Node root disks fill and fabricate victim failures.** test1-4 have 20G+ roots; test5-32 only
  ~6-8G, and kernel logging was triplicated (rsyslog syslog + kern.log + journald). Once a small
  disk hits 100%, `dd if=/dev/urandom of=/tmp/...` writes **0 bytes** with stderr swallowed, the
  node md5s an empty file, and every peer reports a size/content mismatch — indistinguishable
  from a read-coherency bug, and the victim is always in the 9..32 range.
  **Diagnostic tell: an `.md5` containing `d41d8cd98f00b204e9800998ecf8427e` is the md5 of empty
  — the SOURCE was empty at write time** ([[infra-node-root-disks-fill-and-fabricate-victim-failures]]).
- **ccloop leaves predecessor sessions ALIVE and WORKING.** At relay it spawns the next session
  but does not terminate the previous `claude`, which is orphaned to PPID=1 and keeps executing
  its Stop-hook loop — launching rival `run.sh` invocations that power-cycle nodes mid-run.
  One session found two predecessors alive, one of them 5.7h old and still launching retries.
  **Kill them at session start** ([[infra-ccloop-leaves-stale-sessions-alive-KILL-AT-START]]).
- **…but a run-lock conflict is more often your OWN orphans.** A long stretch was spent hunting a
  "rival ccloop session" contending for `/tmp/mxfs_run.lock` with a fresh PID every 1-2 minutes.
  It was timeout-orphaned per-node ssh children. `readlink /proc/<pid>/cwd` settles it in seconds
  ([[infra-timeout-orphans-hold-run-lock-not-rival-session]]).
- **Kernel ring drift.** test19-23 had booted without `log_buf_len=16M`, so their 256KB ring wraps
  in ~40s under MXFS print load — poisoning every dmesg-window scan and producing a persistent
  5-node FAIL that had a multi-build "history" ([[rig-test19-23-log-ring-drift-fixed]]).
- **The ssh wrapper flattens its arguments** (`CMD="$*"`), so a multi-line or quote-heavy remote
  script gets re-tokenised across three quoting layers. An embedded `sed -i "s/.../"` arrived as
  `sed -ie` and **mangled `/etc/default/grub` on 17 nodes**. Rule: remote one-liners only; for
  anything complex, build the script locally, SCP it, then `bash` it
  ([[infra-sshpass-wrapper-flattens-args-no-complex-scripts]]).
- **Calling that wrapper with the passfile omitted wrote the lab password into command-named
  files and directory trees in the repo root** ([[infra-sshpass-2arg-litters-repo-with-password-files]]).
- **`/src/mxfs` is NFS with root-squash behaviour** — files display root-owned regardless of who
  wrote them, and during one incident all client writes were silently denied
  ([[infra-src-mxfs-is-nfs-root-squash]]).
- **Host neighbours move the numbers.** Proven with a raw dd-direct probe **with MXFS not in the
  path**: guest RTT p50 1.85ms idle → 6.6ms during a 32-node storm. Per-op wall is ≈5.5-6.5
  round-trips × RTT at every measured point, and the build under suspicion issued the *same*
  round-trip count as a previously-green build — **MXFS exonerated twice over**. Also measured:
  printk cost ≈30µs/line ≈ 0.45ms/op, negligible
  ([[sweep81-host-noise-perf-margin-analysis]], [[sweep81-progress-board]]).
- **Stale performance ceilings lie.** The `.raw_fio_ceiling.<cond>.json` files were 5 days old
  and captured on a quiet host; and the ceiling script's size-bounded legs completed sub-second
  on fast paths, reporting **in-flight burst absorption as "ceiling"** (one condition measured
  95GiB/s — 24× physical NVMe). Fixed to time-based legs. Separately, an unescaped colon in a
  by-path device name made fio **create regular files and benchmark memory**
  ([[sweep81-progress-board]]).

## 2. Storage-backend corrections (two, both important)

The backend has been mischaracterised twice, in opposite directions:

- **For the TCP rig it is LIO fileio, not SCST.** `/dev/sda` is a LIO fileio backstore over a
  file on the host, exposed to both VMs via virtio-scsi from **one LIO instance on one host** —
  so both VMs read and write the same image through a **single coherent host page cache**. Any
  cross-node read staleness there is an MXFS in-core divergence, *not* a FUA/write-cache problem,
  and `fua_disable=1` is harmless. **Do not chase FUA on that backend — it is a dead end**
  ([[storage-backend-is-lio-fileio-not-scst]]).
- **And LIO fakes CAW** — it reports CAS success without persisting — so CAW cannot be validated
  on it at all. TCP DLM work was deliberately put on LIO as a *known quantity* while CAW requires
  the SCST rebuild ([[infra-lio-for-tcp-scst-for-caw-rationale]]).

## 3. The physical rig — QNAP and Proxmox

**Campaign complete: 15/15 PASS** on the physical pve1/pve2 + QNAP iSCSI rig with TCP DLM,
including a **dead-peer `sysrq-b` finale** — instant TCP disconnect detect, 40s grace with EX
frozen, heartbeat expiry, slice recovery, the survivor writing through the entire window,
**umount in 0.42s**, and a clean rejoin at 0ms gate. Mechanics worth reusing: a stale DKMS
package in `updates/dkms/` **shadowed** the hand-installed module, and `MXFS_DEV=/dev/sdb` is
mandatory because the default `/dev/sda` is the PVE system disk
([[physrig-campaign-COMPLETE-15of15-green]], [[physrig-fixes-v74-76-landed-and-verified]]).

**The QNAP PR mystery, closed by measurement.** The target purges **all** registrations on iSCSI
logout/login **without bumping PRgeneration** (non-conformant — registration lifetime equals
session-event lifetime), and UNREGISTER also does not bump the generation. With those two facts
the previously paradoxical cycle ledger became consistent
([[physrig-qnap-PR-reconstruction-CLOSED]]).

That campaign's defect dossier found the critical one: the **TCP branch proceeded unfenced when
SCSI-PR registration failed** (the CAW branch aborts), so a node ran a whole tenure unregistered,
its journal-slice write bounced EBADE — **and MXFS ate the log error with no shutdown**. A crash
in that state loses committed transactions ([[physrig-qnap-battery-defect-dossier]]). Fixed by
deferring the PR unregister until after `xfs_unmountfs`, and by aborting the mount on register
failure with a one-shot injection knob to prove both arms
([[physrig-fixes-v74-76-landed-and-verified]]).

**PVE-specific findings:**

- **AGI umount wedge** — `umount` in unkillable D-state forever, module refcount stuck at 1.
  Root proven with a per-buffer HOLD/RELE ring: `mxfs_ag_meta_track` takes a hold on every logged
  AG-meta buffer, released **only** by the write-completion iodone — which never fires on a
  shutdown abort. Three buffers stuck at hold=2. Fixed with a one-shot token + reclaim on the
  shutdown-abort path, verified by deterministic fault injection
  ([[pve-agi-buf-hold-leak-umount-wedge-not-sess76-readahead]],
  [[pve-agi-wedge-ROOT-agmeta-track-hold-leak-FIX-and-pve1-hung]],
  [[pve-agi-wedge-FIXED-AND-VERIFIED-agmeta-reclaim]]).
- **Spurious `-EAGAIN` on an O_DIRECT write to an inode just evicted by `drop_caches`**, at N≥2
  only, zeroing both fio write numbers while reads were fine — and the native-XFS N=1 baseline of
  the identical test passed ([[pve-fio-odirect-write-eagain-after-dropcaches]]).
- **A retracted A/B.** The fix for that bug was claimed to "deterministically regress" dir_reuse,
  "A/B PROVEN" on 2 passes vs 2 fails. **That conclusion was wrong — the A/B was confounded by rig
  load**, and the fixed build later passed 11/11
  ([[pve-timestamp-update-ex-iflush-breaks-create-visibility]]).

## 4. Formation and fencing fixes (the D-series)

- **D7 — the settle gate.** A 4.7-20s joiner EX stall was the wall-clock membership-settle gate:
  every EX acquire blocks until the view has been stable for 20s, and a joiner's first EX lands
  ~250ms after its own join event. **The gate freezes every node's EX acquires after any
  membership change**, not just the joiner's. Fixed with a view-signature convergence proof —
  an FNV-1a hash of the sorted member list carried in the lease beacon, with the wall-clock window
  kept only as fallback ([[d7-settle-gate-root-and-view-proof-fix]]).
- **D6 — clean-umount goodbye.** After a peer's clean unmount the survivor's next EX blocked 38s.
  The receive path for the leave message **never updated membership**. Fixed to 10ms, with the
  broadcast gated on `!withdrawn` so a fenced node can never claim clean departure
  ([[d6-d4-d8-goodbye-prfence-selfcheck-fixes]]).
- **D4 — PR fencing was entirely missing in v5.** The legacy blind preempts were user-mode only
  and not in the kernel build, so a TCP-dead-but-disk-alive peer could keep writing. Fencing now
  runs **first** in both dead-node paths, before purge/remaster/slice-replay.
- **D9/P125** — `ilock_end` early-returned on the single-node check when membership had collapsed
  to 1 by unlock time, skipping the holder decrement for a begin taken in the multi-node era.
  Leaked holder counts block the reclaim gates — the busy-inodes-after-unmount and slab-leak
  family ([[p125-holder-leak-singlenode-gate-root-fix]]).
- **Full fence resolution verified end to end** on the cawp rig: a preempted key made the victim's
  next heartbeat bounce EBADE within ~2s → withdraw → shutdown → acquires refused → **no
  auto-re-register**. Fencing latency equals the heartbeat interval, independent of user I/O.
  Ghost heartbeat records were forged to prove the join gate discounts them
  ([[cawp-gate-pr-fence-full-verification]]).

## 5. The NET2 arc — planned, reviewed, partly built, then cut

The plan was re-scanned against the live tree by parallel verification agents (core claims held;
15 errata), then GPT-reviewed: **safety model sound, but no-go as a one-pass plan** — it bundled
five hard distributed-systems projects. The recommendation was the smallest version that fixes
the proven defect: reliable, incarnation-qualified, effect-idempotent midcomms over the direct
mesh, plus mandatory fence-before-reclaim ([[net2-plan-rescan-errata-0.10.120]],
[[net2-gpt-plan-review-verdict]]).

The user overrode the staged framing — *"later stages means never on this project"* — and v2
designed the two under-specified pieces in full: a **MEPOCH membership authority** (a single
committed record as THE authority, with lease/heartbeat as observer votes only, exclusions
requiring attached fence-done proof as a commit precondition, persisted in each node's own
single-writer heartbeat sector so a partitioned node can self-fence with **zero network**), and
**epoch-fenced shard consensus** deriving configs from committed epochs so the both-groups-quorate
hole closes without joint quorum ([[net2-plan-v2-full-system-designs]]).

Steps 1 and 2 landed green ([[net2-step1-gate1-green-0.11.0]],
[[net2-step2-gate2-user-green-0.11.1]]) before the later GPT verdict — *CAW is salvageable, do
NOT build NET2* — ended the effort. The identity discipline was imported into CAW instead.

Related architectural review: the multi-session trajectory of adding non-atomic latch fields to
`xfs_buf`/`xfs_inode` one at a time was judged **whack-a-mole** and given a concrete redesign
direction ([[gpt-consult-dir_reuse32-architectural-review]]).

## 6. Standing project decisions and context

- **CAW is the priority transport.** The shipping target is enterprises migrating off VMware onto
  Proxmox, running VM images on a shared enterprise SAN LUN — exactly the CAW use case. TCP DLM is
  the must-keep fallback ([[project-caw-priority-enterprise-vmware-proxmox-san]]).
- **MXFS is public** at `github.com/sshoecraft/mxfs`, **GPL-2.0-only** (mandatory — it is a
  GPL-2.0 Linux-XFS derivative), copyright under the full legal name. The README states it was
  *"written entirely by AI… not by a human using an AI tool"*, reworded deliberately after the
  first phrasing was judged ambiguous. Full-tree publication was the user's informed choice after
  the leak risk was flagged ([[github-public-repo-mxfs]]).
- **mxfs.1 and v5 are NOT mirror images** — a framing the user explicitly corrected. mxfs.1 is a
  bespoke hand-written XFS-like filesystem with its own cache layer (so it can drop and re-parse
  on BAST); v5 is a fork of the **actual** upstream Linux XFS tree
  ([[mxfs1-vs-v5-not-mirror-images]]).

## 7. Open/unresolved items carried here

- **Mass-unmount `blk_execute_rq` wedge** — a plain coordinated unmount of all 32 nodes on a
  healthy, idle, freshly-mkfs'd cluster wedged 21 of 32 in D-state **in the block layer**, not in
  `xfs_buf_iowait` ([[NEW-BUG-mass-unmount-blk_execute_rq-wedge-2026-07-11]]).
- **The dir_reuse hang signature moved into the SCSI layer** — no longer `xfs_buf_iowait` but
  `scsi_execute_cmd`/`__timer_delete_sync` ([[wedge-root-has-moved-to-scsi-layer-2026-07-11]]).
- **SB summary-counter cross-node drift confirmed live** by a controlled `df -i` churn test,
  though the clean-unmount on-disk state still matched the checker
  ([[sb-counter-recheck-2026-07-11-live-drift-confirmed]]) — later root-caused as the percpu
  lazy-counter asymmetry.

## 8. Historical design records (pre-v5 era, retained for lineage)

The native-XFS format plan that produced the current on-disk envelope
([[xfs_native_format_plan]]) and the completed mkfs implementation notes
([[mkfs-plan]]); the plan to replace `alloc.c`'s hand-rolled btree with XFS's cursor engine,
written because that code zeroes records instead of deleting them, never updates parent keys, and
has no cursor abstraction — *"138+ bugs are symptoms"* ([[btree-engine-replacement]]); the
numbered bug-fix ledger of that era ([[bugfix-history]]); the two 4-node duplicate-dirent
investigations, whose root was BAST-triggered dir-cache eviction forcing a full reload and
re-serialize on **every** file creation ([[bug59-investigation]], [[bug60-investigation]]); the
2026-03 production-readiness roadmap ([[roadmap]]); and the early performance and storage
characterisations ([[perf-session]], [[storage-investigation]]).
