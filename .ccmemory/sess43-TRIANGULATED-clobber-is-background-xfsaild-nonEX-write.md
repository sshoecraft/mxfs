---
name: sess43-TRIANGULATED-clobber-is-background-xfsaild-nonEX-write
description: sess43 CORRECTED: dir writes are active-process (bash/dd/rm), NOT background xfsaild. writemerge disamb=0 because bio-submit is decoupled from the EX…
metadata:
  type: project
---

## sess43 (ccloop) FINAL — CORRECTED (an earlier version of this memory wrongly said "background xfsaild"; the comm data REFUTES that). Read with [[sess43-FIX-twosided-owner-scan-dir-blocks-map-independent]].

### What the dland comm data actually shows
Across ALL o=131 dir-data writes in a fail: **comm=bash 7629, dd 7299, rm 1866, kworker only ~30 total.** So the dir writes are overwhelmingly **ACTIVE PROCESS context** (addname during create via bash/dd; unlink during rm-rf via rm), NOT background xfsaild reflushes. The count-regression I found (daddr=16745864, 143→98) is **comm=rm** = rank1's legitimate `rm -rf "$D"` teardown (count 20→1), NOT a clobber.

### Why the union-merge writemerge (dir_choke_merge) is INERT: `disamb=0` ALWAYS
`mxfs_dir3_data_writemerge` runs at **bio SUBMIT** (`xfs_buf_submit`), which is **decoupled from and runs AFTER the EX-held modify transaction commits + drops the lock** (async writeback of the committed buffer). So at submit time the owner dir is no longer "EX-held-by-us with a valid current-tenure removed-set" → `mxfs_dir_choke_merge_remset` returns disamb=0 → the graft is never sanctioned. P-WMR-REACH fires 183× (disk≠in-core at submit) but never merges. **The bio-submit chokepoint structurally cannot use an EX-held check** because submit is decoupled from the modify txn.

### Net state of the search (what is and isn't true)
- TRUE: serialization is correct (MX-DOUBLEGRANT silent); the loss is a durable single-dirent stale-base divergence; release-flush owner-scan and acquire retire-evict are both PROVEN insufficient (this session); the chokepoint stays content-silent (in-core ⊇ disk at active writes).
- OPEN: the exact moment/path the victim leaves durable disk is STILL not pinned to a single line. The rm-rf-per-round REUSE stressor (ino=131 + daddrs freed+reused each round) is central — a stale in-core base at rank1's rm, OR a reused-daddr starting a round dirty, are live suspects not yet excluded.

### Best next experiments (next session, RULE 4) — pin the EXACT loss event, don't guess a fix:
1. Use the ROTATION-IMMUNE stream (DRC_STREAM / the per-rank stream file the test writes, tests/tcp/drc_cap/stream_rank*.log) + reduced DRC_ROUNDS (e.g. 4) so the CREATE-wave writes of the failing round are not rotated out of the dland ring (the 4096-entry ring only kept the tail = rm-rf teardown of the last round this session).
2. Trace ONE victim end-to-end in a short run: P13-NADD/LADD (which daddr+round the .md5 dirent was added to) → dland trajectory for THAT daddr in THAT round → identify the write (comm + incarn + count + node) that produces the final image LACKING the victim. Decide: is it (a) a create-wave stale-base RMW (active addname on a node whose base lagged the durable disk), or (b) a rm-rf teardown on a stale base leaking/clobbering across the round boundary via daddr reuse, or (c) a reused-daddr that started the round with stale prior-incarnation content (verify the sess40 incarnation-skip P40-INCARN-ABA-DIRSKIP fires for the data block).
3. Only after (1-2) pin the path, fix at THAT path (rebase-on-durable at modify/rm time, or incarnation-gate the reused daddr).

### Build keeper 39C98098 (dir_owner_scan default 0 = 1/2/4-equivalent). Cluster clean. Cross-ref [[sess43-FIX-twosided-owner-scan-dir-blocks-map-independent]] [[sess41-PROVEN-799-is-post-submit-writeorder-not-stalebase-merge-dead]] [[sess40-FIX-dirblock-ABA-writeback-skip-build-B9F9326E]].</body>
