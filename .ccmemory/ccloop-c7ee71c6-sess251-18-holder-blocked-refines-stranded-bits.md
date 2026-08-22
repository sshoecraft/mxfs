---
name: ccloop-c7ee71c6-sess251-18-holder-blocked-refines-stranded-bits
description: sess251: #18 mass-wedge hypothesis REFINED — stuck AG grants have LIVE blocked holders (test8 ag=2 rsync pid 137s, P12 holders=1), NOT stranded platt…
metadata:
  type: project
tags: [ccloop, defect-18, noino, aglock, rule4]
---

# sess251 — #18 D-NOINO-RELFENCE-AIL-FREEZE-474 mechanism refinement

## Refutation of the sess249 handoff hypothesis
The handoff's H ("post-swap remount leaves STRANDED AG holder bits; P5N disk_held=0 names them") is WRONG on its own evidence:
- `P5N ... disk_held=0` is the **benign branch** (xfs_mxfs_dlm.c:41127): a multicast BAST hint for an AG the node provably does NOT hold, pending >3s. It means SOMEONE ELSE held that AG >3s — a symptom of fleet-wide stuck grants, not stranded bits.
- test8's own capture (sess249 transcript line ~290): `P12-AGBAST-RX ag=2 holders=1 readopt=7 page_ms=137446 holder=29871/rsync` — a LIVE in-core holder: an rsync thread held ag=2's EX for 137s with on-disk waiters [3,27]. ag=2 ex_epoch=158.

## Refined mechanism hypothesis (RULE 4 open)
AG EX holder *threads* block for minutes while holding the AG (blocked on WHAT is the open question — another AG's CAW poll / log space / ILOCK). Waiters stall in CAW poll (some holding ILOCK per the CLAUDE.md design tension — xfs_bmap_btalloc never got the v0.3.148 ILOCK-drop fix xfs_create got) → peer AILs freeze → noino relfence (8 frozen pushes, xfs_mxfs_dlm.c:20087) fail-closed shutdowns → shutdown nodes never release their AG EX (invariant 1) → cascade to 20/32 nodes. Post-mortem slotdump's 24/25 EX-held AGs = EFFECT of shutdowns, not cause.

## Missing link + instrumentation that already exists
`P12-HOLDERTASK` (xfs_mxfs_dlm.c:41063, in 0.11.489): dumps holder's stack via sched_show_task when holders>0 && page_ms>15s, capped 6/boot. It FIRED on the wedged run but was never pulled and dmesg is GONE — test-node journald is NOT persistent (boot -1 on test8 = June 30 image build). ALWAYS capture dmesg before fleet teardown; `scripts/collect_incident_dmesg.sh <outdir> <since-utc> nodes...` exists.

## Rig state left by sess251
- All 32 VMs booted fresh (were shut off); iSCSI sessions NOT logged in yet (no /dev/mapper/mpatha) — prep_node.sh handles login/multipath in later steps.
- Platter untouched: aged fs + 20 dirty journals + 24/25 AG EX-held by dead incarnations (archived in tests/forensics/sess249_noino_mass_wedge_slotdump.txt).
- `./run.sh 32 caw rsync_paired` refuses (marker wants MOUNTED). prep_cluster would MKFS — avoid. Plan: manual cluster form WITHOUT mkfs: on test1 `MXFS_DEV=/dev/mapper/mpatha bash /src/mxfs/tests/setup/prep_node.sh caw` then remaining 31 in parallel (pass MXFS_KO_MD5=$(md5sum /src/mxfs/mxfs.ko)), which also exercises 20-dirty-journal recovery; then filtered run passes the marker check. Fall back to prep_cluster (mkfs) only if recovery of the dirty platter fails/wedges.
- After the run: immediately collect_incident_dmesg.sh into tests/forensics/sess251_* for ALL 32 nodes + fresh slotdump; grep P12-HOLDERTASK stacks — they name the blocking edge.
- Boot trap: wait for /run/nologin to clear on all nodes before run.sh (pam_nologin garbage breaks its srcversion probe).
