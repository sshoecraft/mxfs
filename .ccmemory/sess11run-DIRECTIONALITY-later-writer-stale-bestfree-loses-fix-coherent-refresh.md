---
name: sess11run-DIRECTIONALITY-later-writer-stale-bestfree-loses-fix-coherent-refresh
description: sess11(ccloop) directionality of the dir-block slot double-alloc: EARLIER writer (node4_f4) SURVIVES, LATER writer (node2_f1.md5, +1.2s) is LOST. Lat…
metadata:
  type: project
---

## sess11 (ccloop) — directionality + fix direction for the PROVEN dir-block free-slot double-allocation

### Directionality (build C0290572, lost=node2_f1.md5)
At the contested slot daddr=2093296 off=2768:
- test4 wrote node4_f4 FIRST (123.404, realns ...881929116) -> node4_f4 PRESENT on disk (SURVIVED).
- test2 wrote node2_f1.md5 LATER (+1.2s, 124.609) to the SAME slot -> node2_f1.md5 MISSING (LOST).
The LATER writer loses. So test2's addname read a STALE bestfree for block 2093296 (its cached/used image did NOT reflect node4_f4 occupying off=2768, even though node4_f4 was durable 1.2s earlier), placed node2_f1.md5 at the "free" off=2768 (onto the occupied durable slot), then test2's in-core block was coherently re-read/reverted to the disk image (node4_f4 at 2768) before/at flush -> node2_f1.md5 dropped. (Matches the earlier sess11 "entry vanishes from in-core before durable_signal".)

### ROOT (final): the modify-path bestfree is STALE on a contended dir. test2's EX-acquire evict+cold-read FAILED to refresh block 2093296's bestfree (kept a stale cached block, or fast-path reused it), so the dir2 addname free-slot search double-allocated a slot a peer already used. 1.2s gap => NOT a durability race (node4_f4 was long durable); it's a READ/refresh-coherency gap on test2's side (stale cached dir block bestfree).

### FIX DIRECTION (next session): force a COHERENT refresh of the dir data block (bestfree) before addname on a contended dir (i_dlm_dir_gen>0), so the free-slot search reflects every peer's committed dirents. The existing mxfs_dlm_dir_modify_refresh -> mxfs_dir_evict_data_blocks evicts CLEAN stale blocks, but it is failing to evict/refresh block 2093296 here (likely the b_mxfs_dir_gen >= i_dlm_dir_gen gen-gate treats the stale block as fresh, or the XBF_TRYLOCK skip, or a fast-path acquire). Candidate fixes: (a) on a contended-dir modify, FUA-re-read (coherent) every dir DATA block before addname regardless of the gen gate (bounded: only the dir's data blocks, only when gen>0) so bestfree is authoritative; (b) make the EX-acquire evict actually fire for these blocks (audit why 2093296's evict was skipped — add a probe at mxfs_dir_evict_data_blocks for this daddr showing the keep/skip reason: gen, TRYLOCK-EAGAIN, undurable). PRIOR caution: blanket acquire-side eviction/refresh STALLS the dir-EX handoff (sess11 drain_evict in_ail fix hung; sess50 starvation) -> scope tightly + watch RULE-0 timing.

### DECISIVE NEXT PROBE: at mxfs_dir_evict_data_blocks, for the storm dir, log per-block the keep/skip decision (daddr, b_mxfs_dir_gen vs i_dlm_dir_gen, TRYLOCK rc, undurable) so you can see WHY block 2093296 was NOT cold-refreshed on test2's acquire before its stale-bestfree add. Also dump the bestfree[] the addname used (in xfs_dir2_data_use_free / before placement) to confirm test2 saw off=2768 free.

### Tree: C0290572 (clean baseline + inert FIX3 + SAFE dirwr-gated probes incl P11-DATALOG w/ off=). Cluster grub log_buf_len=16M. Repro: /tmp/...scratchpad/drc4_d1.sh (dirwr=1). Criterion NOT met. See [[sess11run-ROOTCAUSE-PROVEN-cross-node-dirblock-freeslot-double-allocation]] [[sess11run-SMOKINGGUN-datalog-entry-bytes-logged-then-vanish-no-evict-no-reload]].
