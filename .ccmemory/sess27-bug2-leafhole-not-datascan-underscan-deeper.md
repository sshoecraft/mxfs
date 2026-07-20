---
name: sess27-bug2-leafhole-not-datascan-underscan-deeper
description: sess27 BUG2 update: under partial_iwrite=0, datascan ndb=2 (di_size NOT stale) but still MISSES node2_f10 that readdir lists. NOT under-scan. Deeper…
metadata:
  type: project
---

## sess27 (ccloop 8ddb16a2) — BUG2 (leaf-hole under partial_iwrite=0) is NOT a datascan under-scan

### Refuted: datascan extent-map fix (build 9753480F)
Changed mxfs_dir2_datascan_lookup to compute ndb from the data-fork EXTENT MAP instead of di_size/blksize. Result: ndb=2 EITHER way (di_size=8192 was NOT stale). dir_reuse with partial_iwrite=0 STILL FAILs: readdir=200/200, lookup_fail=97-98, P26-DSCAN=20 P26-DSCAN-MISS=20 P22-DATASCAN-HIT=0 P26-IGET-FAIL=0. So the datascan scans BOTH data blocks correctly but MISSES node2_f10 — which readdir (same round, same data blocks) LISTS. The extent-map change is harmless/more-correct robustness; KEEP or revert (no behavior change vs di_size here).

### The new paradox to crack next session
readdir reads the dir DATA blocks and lists node2_f10 (so node1's data block HAS node2_f10's dirent). The datascan (xfs_dir3_data_read, same daddr, same buffer cache) reads the SAME data blocks but does NOT find node2_f10. Same buffer-by-daddr → should be same content. Yet readdir finds it and datascan doesn't. Possible causes to investigate:
1. readdir and the lookup-path datascan read DIFFERENT in-core data-block states (readdir's getdents buffers vs xfs_dir3_data_read buffers diverge — maybe readdir reads via a reload that the lookup path doesn't, or vice-versa). Check: does xfs_readdir call mxfs_dlm_reload_inode / a different refresh than xfs_lookup? (xfs_lookup calls mxfs_dlm_dir_consumer_refresh at top; readdir may do more.)
2. The data block is DURABLY missing node2_f10's dirent on disk, and readdir lists node2_f10 from a STALER cached data block (with the dirent) while datascan re-reads a FRESHER block (without it) — i.e. a durable DATA-block lost-update (node1 whole-wrote a stale dir data block reverting node2's dirent). Under partial_iwrite=0 the missing set GREW (now includes node2_f1 which was valid under partial_iwrite=1) — consistent with whole inode writes shifting/worsening a separate dir-data-block revert.
3. The dirent compare in the datascan (xfs_dir2_compname) fails for node2_f10 for some reason (hash/ci mismatch) — unlikely.

### NEXT decisive probe
Instrument the datascan inner loop: for the FAILING name (node2_f10), log every dirent name it sees in each data block scanned (or log "scanned db X, Y entries, node2_f10 present=0/1"). Simultaneously log the data block daddr readdir reads vs datascan reads for the same dir. This settles whether it's (1) different buffers/states or (2) durable data-block revert. If durable data-block revert → it's the SAME write-side lost-update class (extend the dir guard / release-drain to fully cover dir DATA blocks under whole inode writes). If different in-core states → unify the readdir and lookup refresh paths.

### Tree state: build 9753480F = clean baseline + diagnostics + partial_iwrite toggle(default 1) + datascan-extent-map + unused b_mxfs_idirty_mask. Behavior == original for default args. partial_iwrite=0 confirmed to PASS cache_coherency/strong_consistency/posix_multi (see [[sess27-partial-iwrite-0-viable-only-leafhole-remains]]). Reboot cluster before runs (test2 boot-wedge).
</body>
