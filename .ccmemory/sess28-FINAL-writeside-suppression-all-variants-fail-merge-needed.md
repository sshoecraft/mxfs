---
name: sess28-FINAL-writeside-suppression-all-variants-fail-merge-needed
description: sess28(ccloop) FINAL: write-side dir loss characterized. Pure-stale suppression→SHUTDOWN; full-subset→readdir=316; read-side fix→no effect. P-WMERGE:…
metadata:
  type: project
---

## sess28 FINAL HANDOFF — dir_reuse 8/tcp write-side loss thoroughly characterized; criteria NOT met

### What this session PROVED (decisive, clean-cluster, RULE 4)
1. **The loss is WRITE-SIDE, read is coherent.** Clean run (no concurrent driver): rdmiss=1, **diff1=0** (in-core dir block ALWAYS == platter at addname over 300 samples), p28c=0, corrupt=0. The dirent is added onto a coherent base then reverted by a stale destage. Confirms sess27. [[sess28-DECISIVE-loss-is-writeside-read-coherent-diff0-p28c0]]
2. **Read-side fix is a DEAD END.** mxfs_dir_addname_coherent (build 9AB8E8AE, all 3 formats, platter ground-truth reread) ENGAGES safely (no wedge/shutdown, 355s) but does NOT prevent the loss (diff1=0 -> nothing to catch). DEFAULT 0.
3. **P-WMERGE classification of clobbering dir-data writes** (dir_writeprobe=1, build C71C4EA9, pal/linux/xfs_buf.c::xfs_buf_submit_bio): test1 floods ≥300 **pure-stale** writes (incore_extra=0, disk_extra>0; e.g. daddr=120 disk_extra=153 incore_extra=0 = a single write about to revert 153 peer entries — the classic block-0 ABA). test2-8: a few **MERGE-NEEDED** writes each (incore_extra>0 AND disk_extra>0 = both writers have unique entries).
4. **ALL drop-suppression variants FAIL:**
   - dir_subset_guard=1 (suppress any disk_extra>0): CATASTROPHIC readdir=316/800 — drops the legit MERGE-NEEDED concurrent-growth writes. [[sess28-REFUTED-subset-guard-overfires-catastrophic-readdir316]]
   - Refined (suppress only incore_extra==0 pure-stale): FAIL wall=91s, **corrupt=1 SHUTDOWN** — suppressing those writes is STRUCTURALLY UNSAFE (the FS/log expects them; emulating ioend leaves an inconsistency -> immediate shutdown). A legit REMOVE also looks pure-stale (disk_extra=1, incore_extra=0).

### The core dilemma (for next session)
A clobbering dir-data write either (a) drops a peer's concurrent add (write it = lose peer) or (b) is a stale rewrite (suppress it = shutdown / resurrect a remove). Suppression is the wrong tool. The MERGE-NEEDED case PROVES the only correct fix is a **content union-merge at the write chokepoint** (or at the read/RMW base): before writing a dir-data block where disk has extra inumbers, GRAFT disk's peer dirents into the in-core image so the write is a superset of BOTH. For pure-stale writes, the merge naturally re-adds the 153 disk entries -> the write becomes a no-op-equivalent superset (safe, no shutdown, no loss). This unifies both cases: ALWAYS merge disk's extra dirents into the outgoing in-core block (rebuild bestfree + offsets), never suppress.
- CAUTION: sess21 shortform union-merge had an offset-collision corruption (fixed via fresh monotonic offsets, xfs_dir2_sf_put_offset). A DATA-block union-merge must place grafted dirents in genuinely-free space and rebuild bestfree (xfs_dir2_data_freescan) + the leaf/freeindex bests. Risk: getting the on-disk dir3 structure exactly right.
- Alternative if merge is too risky: investigate WHY these stale writes are issued at all (the read base was coherent at addname per diff1=0, so the staleness is injected between addname and destage = a peer modifies after we release EX; the EXISTING NL-release dirskip P16/P17 should catch an NL-released write but the loss persists -> check the P16 `mode` field on the clobbering write to see if it's EX-held or NL at destage; if EX-held, the EX holder is destaging a stale base = needs the merge; if NL, the dirskip predicate has a gap).

### Keeper state: build F3DF2B06 (== prior keeper 164A6D5D behavior; ALL sess28 levers default OFF: dir_addname_coherent=0, dir_subset_guard=0, dir_writeprobe=0). Refined subset_guard (incore_extra==0 gate) is in the code but default-off. New inert xfs_buf field b_mxfs_coherent_gen. Tooling: tests/tcp/drc_one.sh (EXTRA=... for modargs, captures p28c/p26/p12/rdmiss/corrupt/P-WMERGE), drc_diag.sh, drc_platter.sh.
### INFRA LESSON (cost me hours): a background driver (drc_diag/drc_platter) can SURVIVE `pkill -f <name>` and keep spawning run.sh, CONTAMINATING concurrent runs (two drivers mkfs the same LUN). ALWAYS `ps -eo pid,etime,cmd|grep -E 'drc_|run.sh 8 tcp'` and kill the driver PID explicitly; verify 0 before trusting any 8-node result.
See [[sess28-DECISIVE-loss-is-writeside-read-coherent-diff0-p28c0]] [[sess22-GPT-fix-design-freeslot-doublealloc-readdir799]] [[sess21-FIX-union-merge...]].
