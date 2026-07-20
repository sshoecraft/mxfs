---
name: sess123-tenure-id-agi-coherency-design
description: sess123 (ccloop): PROVEN root of AGI unlinked-list corruption + Gemini's tenure_id redesign to replace the failed gen/LSN preserve-vs-discard heurist…
metadata:
  type: project
---

## sess123 (ccloop run 14d31183) — AGI unlinked-list coherency: PROVEN root + structural fix

### Context
cache_coherency is the sole failing ship criterion (11/12 pass). unlink_visibility subtest shuts a node down. Resume plan (sess122) said disable read-side P110 interlock → restore 3/4. I built that (`70826FA0`, P110 LOG-ONLY, pal/linux/xfs_buf.c:2785), power-cycled+reset4, ran unlink_visibility: STILL FAIL. **P110 was a backstop masking the real bug, not the cause.**

### PROVEN mechanism (RULE 4, direct dmesg, build 70826FA0)
4-node concurrent unlink/rmdir. Node test1:
- `P82-ADD ino=4194433 agno=2 agino=0x81 bucket=1 rc=0` — unlinked-list INSERT committed OK (AGI bucket1 in-core = 0x81).
- ~3ms later: `P117-INAIL-STALE-ARTIFACT daddr=4174642 agi buf_gen=0 pag_gen=1 — discarded prev-epoch in-AIL artifact` → plain-bio read pulls on-disk AGI over in-core.
- `P71-INSTR agi-unlinked-garbage agno=2 bucket=1 head_agino=0xffffffff disk_head=0xffffffff ... agi_gen=0 pag_gen=1 agi_disk_differs=1` → `xfs_iunlink_remove_inode` line 632 XFS_CORRUPTION_ERROR → SHUTDOWN.

**The node DISCARDED ITS OWN committed-but-not-yet-durable AGI insert mid-tenure**, then re-read the stale on-disk AGI (NULLAGINO) → insert lost → corruption.

### WHY the gen heuristic structurally fails
`b_mxfs_ag_gen` is stamped to `pag_dlm_meta_gen` in ONLY 2 sites: the SCSI-FUA read success path (xfs_buf.c:1772) and the discard-rebranch (xfs_mxfs_dlm.c:5370). **Default config is `fua_disable=1` (SCST coherent cache) → AG-meta read via PLAIN BIO → gen NEVER stamped → buf_gen=0 forever.** So once a peer bumps pag_gen to 1, every this-node-ahead AGI buffer looks gen-lagging and the in_ail discard branch (xfs_mxfs_dlm.c:5371-5465, sess19b/sess117/sess120) fires. The `mxfs_buf_is_undestaged()` LSN guard (meant to protect this-node-ahead in_ail buffers) mis-decides and lets the discard through.

**The deeper reason every patch (sess19/42/43/102/103/110/117/120/122) failed:** `in_ail`, `b_log_item`, dirty/pin, and LSN all CONFLATE two physically-identical-looking cases: (a) sess117's genuinely-stale prev-epoch log-tail artifact (drained durable, peer wrote newer → MUST discard+cold-read) vs (b) this session's current-tenure committed AGI insert (must PRESERVE). Only "which DLM lock tenure produced this content" distinguishes them — the dimension the heuristics never captured.

### THE FIX (Gemini RULE-5 architectural design) — replace gen/LSN with DLM-tenure lifecycle
Rip out per-buffer `b_mxfs_ag_gen` + `pag_dlm_meta_gen` + `mxfs_buf_is_undestaged` LSN heuristic. Replace with a tenure-keyed cache lifecycle:
1. Add `u64 b_tenure_id` to struct xfs_buf (mxfs fields) and `u64 ag_dlm_tenure_id` to struct xfs_perag.
2. **On fresh AG-DLM acquire** (the slow-path site that currently bumps pag_dlm_meta_gen): `pag->ag_dlm_tenure_id++`.
3. **On AG-meta buffer access/lookup:** if `bp->b_tenure_id != pag->ag_dlm_tenure_id` → prev tenure → hard-invalidate (clear XBF_DONE|_XBF_FUA_FRESH → forces plain-bio cold-read; SCST coherent cache serves peer's durable image) AND set `bp->b_tenure_id = pag->ag_dlm_tenure_id`. WARN_ON if such a buffer is dirty/has b_log_item (means release-drain failed).
4. **Within tenure (b_tenure_id == ag_dlm_tenure_id): buffer is AUTHORITATIVE, NEVER a discard candidate** — zero heuristic checks. This preserves the AGI insert from P82-ADD through the matching remove.
5. Absolute rule: a buffer with `b_log_item != NULL` is never discarded while tenure matches (you hold AG EX → no peer can have advanced disk).

### Release-side drain WITHOUT the sess111 wedge (Gemini)
sess111 deadlocked synchronously pushing the global AIL from the release context. Instead, decoupled async worker (mxfs_drain_wq, holds zero XFS locks): (1) quiesce AG (mark MXFS_AG_RELEASING, block new local txns on this AG, wait current ones), (2) `xfs_inodegc_flush(mp)` (stop inodegc re-dirtying AGI), (3) `xfs_log_force(mp, XFS_LOG_SYNC)` (push CIL→journal, UNPIN buffers — satisfies WAL), (4) walk per-AG buffers, `xfs_buf_delwri_queue` the dirty/log-item ones to a local list, (5) `xfs_buf_delwri_submit(&list)` (direct block-layer write, bypasses xfs_ail_push deadlock vector), (6) `mxfs_ag_dlm_release_caw(pag)`, set NL.

### Build/iterate (BINDING)
- Current cluster: build `70826FA0` (P110 log-only) on test1-4, but test1 shut down after the run — needs power-cycle+reset4 before next trusted run.
- ALWAYS: `sudo virsh -c qemu:///system destroy+start` ALL 4 → `INSMOD_OPTS="fua_disable=1 instr=0" bash tests/reset4.sh 4` → verify srcversion on all 4 + dmesg -C → run subtest.
- Subtest: `MXFS_NODE_OFFSET=0 MXFS_TESTS_DIR=/src/mxfs/tests bash tests/run_tests.sh --nodes 4 --phase cluster --test test_unlink_visibility --pass-file /tmp/.mxfs_pass --device /dev/sda --mount-point /mnt/shared`.
- RULE 4: implement tenure_id incrementally, measure unlink_visibility after each build. Keep P71-INSTR/P82-ADD/P117 probes as regression gates.

Related: [[sess23-ccloop-suppression-was-corruptor-3of4]] [[sess122-ccloop-RESUME-p110-readside-regression]] [[sess103_lessons]] [[sess117_lessons]] [[sess111_drain_wedge_fix]]
