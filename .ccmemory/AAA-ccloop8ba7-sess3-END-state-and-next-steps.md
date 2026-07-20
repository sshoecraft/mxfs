---
name: AAA-ccloop8ba7-sess3-END-state-and-next-steps
description: sess3 END: 32/caw 19/20 (only cache_coherency FAIL). Root-caused+FIXED iter1b garbage-cluster read-race (P133 sync-init, build 76FA993D BUILT NOT DEP…
metadata:
  type: project
tags: [ccloop-8ba7ae5c, sess3-end, handoff, cache_coherency, 32node]
---

# sess3 (ccloop 8ba7ae5c) END STATE — read FIRST next session

## Criteria position
criteria.json: 1/2/4/8/16 caw = 100% complete. 32/caw = 19/20 PASS; ONLY cache_coherency 32/caw FAIL
(ladder 20260716T172745Z, test1 uv-ghost node7_file30). THE one remaining criteria blocker.

## This session's findings (three distinct bugs, one family)
1. **PROVEN static double-alloc** (ladder aftermath): uv-dir + posix_multi forks both owned fsb 1311015
   & 1835313; all 6 uv blocks re-handed out. Mechanism UNPROVEN — every fence probe silent (PROBE-A,
   P125, P88, P75, P79, P121, P117-coldread, P70/74, P47, P3) on 24/32 nodes (1-8 rotated).
   See [[AAA-ccloop8ba7-sess3-PROVEN-double-allocation-uv-vs-posixmulti]] and GPT consult
   [[AAA-ccloop8ba7-sess3-GPT-consult-false-fresh-acquire-lineage]] (H-A/H-B false-fresh discard theory
   → REFUTED by iter_1b silence of P130/P131; mechanism still open).
2. **iter_1b catastrophic read-race — ROOT-CAUSED + FIXED**: posix_multi 0/32, 85× xfs_inode_buf_verify
   EFSCORRUPTED = urandom over just-carved .strong_consistency chunk (AG40 agbno16 ino 83886208).
   Quiesced xref = CLEAN + no dangling dirents → NOT a double-alloc: peer lookups (lock_flags=0, NO
   inode-DLM) FUA-read a fresh chunk's home LBA BEFORE the carver's cluster-init destaged (init durability
   was tied ONLY to AG-DLM release; visibility travels via dir-DLM which releases first; AG affinity keeps
   carver's AG cached for seconds+). Verifier hard-fails on prior-owner garbage → EIO, NO retry path.
   **FIX (root, ordering)**: xfs_ialloc_inode_init mxfs branch now xfs_bwrite's the fully-CRC'd v5 cluster
   buffer synchronously at carve (P133-ICLUSTER-SYNCINIT, capped 20 prints; once per 64 inos). Content
   idempotent; cancelled-tx/crash harmless. alloc_buflist queueing kept.
3. uv-ghost (test1, ladder): unexplained; GPT says same fence family via dir-block staleness; test1-8
   journals rotated. Watch during repro iterations.

## Builds
- 0.10.109 srcversion 4462813A = probes only (P130 lineage cert + 4 unlock-site lineage_open clears +
  single→multi reset; P131 superset discard log; P75 cil_resident; P-DBLALLOC disk_owner + AGF
  discriminator). DEPLOYED to nodes during iter_1b.
- **0.10.110 srcversion 76FA993D = 4462813A + P133 sync-init fix. BUILT on clyde, NOT YET DEPLOYED.**

## NEXT STEPS (in order)
1. `timeout 590 scripts/dblalloc_repro.sh 2` (prep auto-deploys 76FA993D; MXFS_EXTRA_MODARGS default
   dblalloc_probe=1 in the harness). Expect: P133 fires ~dozens, posix_multi collapse GONE.
   Prep convergence flake ~1/2 (node stuck active_count=31) → just rerun with new iter label.
2. Iterate (labels 3,4,5...) ~5+ clean passes. Per iter the harness pulls probe journals to
   tests/logs/dblalloc_repro/iter_*/ and runs the uv/pm static check. For FULL confidence also run
   `python3 scripts/xref_owners.py /home/steve/disk.img` after unmounting all 32
   (umount via tools/mxfs_sshpass.sh loop; xref needs QUIESCED image). Watch for: uv-ghost recurrence,
   double-alloc recurrence (xref DUAL-OWNED), P130/P131 fires (would finally name mechanism #1).
3. When repro iterations are clean: full ladder `MXFS_DEV=/dev/mapper/mpatha ./run.sh 32 caw` (unfiltered
   = re-preps + runs ALL applicable; ~75 min incl dir_reuse 3242s; run in 5-min foreground chunks per
   RULE re: background, or background+poll per sess8 pattern). cache_coherency@32 PASS flips criteria.
4. Regression: re-run 16/caw ladder (all PASS today) + spot 8/4/2/1 (playbook
   [[AAA-NEXT-SESSION-PLAYBOOK-caw-dlm-multipath-criteria]] step 4). fio_perf budget 30s is miscalibrated
   (actual 428s, calibration mode tolerates) — don't chase.
5. All green → echo YES > /src/mxfs/.ccloop/runs/8ba7ae5c-35d8-4efa-9f72-44504bb63a45/criteria-met
   (cite showstat.sh 1..32 outputs as evidence).

## Env crib
- Cluster: all 32 UNMOUNTED now, module 4462813A loaded (prep reloads). Backing /home/steve/disk.img,
  xfs_off=100704256 (parse mxfs sb anyway), mpatha 2-path iSCSI.
- SSH: tools/mxfs_sshpass.sh <host> /tmp/.mxfs_pass '<cmd>'. Node journals UTC; test1-8 rotate FAST.
- P-DBLALLOC content hits have FALSE POSITIVES (foreign-dead reuse; in-core-below-disk AGF differ is
  normal mid-tx). Only xref/inobt cross-check confirms real double-alloc.
- run.sh: filtered runs need marker match (srcversion!) else error; `./run.sh 32 caw prep_cluster` =
  forced fresh prep; /tmp/mxfs_run.lock flock (stale file harmless; check pgrep run.sh).
- awareness/xfs.md + pal.md not yet updated with sess3 changes (Stop-hook nag pending): P130/P131/P133
  additions + lineage field pag_dlm_lineage_open in xfs_ag.h.
