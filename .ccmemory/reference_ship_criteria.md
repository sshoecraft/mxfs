---
name: criteria-ship-gate
description: "MXFS ship-gate verifier suite (SUCCESS_CRITERIA.md + tests/criteria/). How to run it for v5, what was adapted from .1."
metadata: 
  node_type: memory
  type: reference
  originSessionId: 335bbd54-62a5-4783-93da-29e01b327fe3
---

# MXFS ship-gate / success criteria

- **`/src/mxfs/SUCCESS_CRITERIA.md`** is the ship gate spec (copied from
  /src/mxfs.1 on 2026-05-29). Verifier scripts live in
  **`/src/mxfs/tests/criteria/`**. Each prints `RESULT: PASS|FAIL ...`,
  exit 0/1, and persists to `/src/mxfs/.criteria_results.json`.
- Run the whole gate: `tests/criteria/verify_ship.sh` (stops at first FAIL)
  or `--keep-going` (survey: run all). `--status` prints the JSON table.
  Run one criterion: `tests/criteria/<name>.sh --nodes N`.
- 19 gating criteria: mkfs_timing, chk_clean, dkms_install, online_resize,
  cluster_ops_timing, wedged_unmount, online_membership, dmesg_clean,
  cache_caps, posix_semantics (×2: nodes 1 and 16), cache_coherency,
  strong_consistency, zero_silent_loss, crash_consistency,
  fence_during_write, single_node_paired, rsync_paired, scaling_curve.
  (soak.sh only with `--include-soak`.) Perf criteria run last.

## Adaptations made when copying .1's suite to v5 (so it targets v5, not .1)
- `tests/criteria/lib.sh`: `MXFS_REPO` default → `/src/mxfs`;
  `DEFAULT_NODES` — the cluster is NO LONGER partitioned (2026-06-14): all of
  test1–test32 are available to this repo. Pick the node count to fit the test
  (small N for iteration; larger only when scale is the point) rather than
  defaulting to a fixed 16. See [[test-cluster-scst-stack]].
- **Mount syntax differs:** .1 used `mount -t mxfs -o dlm_transport=tcp`.
  v5 has NO `dlm_transport` mount option — transport is the `force_transport`
  module param (0=auto/CAW default, 1=TCP). Added `MXFS_MOUNT_OPTS` (default
  empty = CAW) in lib.sh and replaced the `-o dlm_transport=` literals in
  lib.sh, cluster_ops_timing.sh, online_resize.sh, online_membership.sh.
- **`verify_ship.sh` had a real bug:** it ran `bash "$SCRIPT_DIR/$entry"`
  with `$entry="script.sh --flag val"` quoted as one path → every criterion
  "No such file or directory". Fixed with `read -ra` to split script+args.
- `tools/prep_tcm_node_scst.sh` device detect → vendor `SCST_FIO` (see cluster memo).

## Inherited .1 results (NOT v5; for contrast only)
On .1's last runs: single_node_paired FAIL (mxfs 252% of XFS), rsync_paired
FAIL (365%), scaling_curve FAIL (timeout); most correctness PASS. v5's own
results live in `/src/mxfs/.criteria_results.json` after a run.
