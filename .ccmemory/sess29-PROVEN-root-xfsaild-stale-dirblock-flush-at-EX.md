---
name: sess29-PROVEN-root-xfsaild-stale-dirblock-flush-at-EX
description: sess29 PROVEN (P29-DATAWRITE+P-LEAFWRITE+P16): dir_reuse 2/tcp durable loss = xfsaild async-flushes STALE dir DATA/leaf blocks while dir EX-held; rea…
metadata:
  type: project
---

## sess29 (ccloop 8ddb16a2) — dir_reuse_coherency 2/tcp root PROVEN with new write-side detector

### Method
Built 75FD71CC = baseline 0270D870 + new **P29-DATAWRITE** detector (pal/linux/xfs_buf.c, in the P56 block; helper `mxfs_dir3_data_fingerprint` counts live dirents + inumber sum/xor of the buffer-being-written vs the coherent on-disk plain-read). Ran `MXFS_EXTRA_MODARGS="dirwr=1" ./run.sh 2 tcp dir_reuse_coherency`.

### DECISIVE evidence (both nodes)
- **P29-DATAWRITE tag=CLOBBER** and **P-LEAFWRITE tag=CLOBBER**: almost all have **comm=xfsaild/sda** (the async AIL flush), writing a dir DATA/leaf block that drops dirents/hashvals the COHERENT disk has. e.g. test1 daddr=2600 block-0 reverting 5→4→3→2→1; test2 leaf daddr=2096952 buf 126/disk 123 etc.
- **P16-DIRBLK-SUBMIT** for the clobbered daddrs: `mode=5` (EX), `nl=0`, `would_skip=0`, `enforce=0`, comm=xfsaild. So the dir is **EX-held by THIS node** at flush time → the existing NL-release chokepoint skip (`mxfs_buf_xfsaild_skip_dir_write`) does NOT apply.
- **dirskip=0** (mxfs_dirskip_enabled): the write-side skip is DISABLED anyway (only enforces the NL arm; tenure-mismatch arm is detector-only — proven false-positive on block→leaf conversion).
- **DIR-STALE-SKIP** (read keep-guard): `ino=131 blk=1 pin=1 pincnt=1 has_bli=1 li_empty=1 undest=1 buf_gen=0 inode_gen=8` — a PINNED+undestaged stale dir block is KEPT (can't re-read a pinned buf → corrupt). This is how the stale base survives re-acquire.
- **P106-MR-EVICT**: 179/104 (always evicts on new_incarn/gen), **P106-MR-SKIP: 0** — modify-refresh fires, but only evicts CLEAN blocks; pinned/undestaged stay stale.
- bufincarn == cur i_generation on the clobbers → NOT incarnation-ABA; it's WITHIN-incarnation async-flush staleness.

### ROOT (PROVEN, == sess65 theme)
DLM EX serializes the logical create, but **xfsaild async writeback does NOT respect tenure**. On a tenure boundary (node releases EX, peer modifies dir, node re-acquires), the node's cached dir DATA/leaf buffer is stale; the read-side keep-guard CANNOT refresh it while PINNED/undestaged, so the node RMWs a stale base and/or xfsaild later flushes the stale buffer over the peer's newer durable image → durable dirent/hashval loss. Two faces: DATA-block dirent loss (node1_f1..f13) + LEAF-hash hole (node2_fNN.md5 readdir-yes/lookup-ENOENT).

### CAVEAT on the detector
P29 "buf_cnt < disk_cnt" ALSO fires on legitimate rm-rf removals (buffer shrinks, disk lags) — false positives. The real clobber signal is "disk has an inumber the buffer LACKS" (buf is missing committed entries), not raw count. Refine before trusting counts blindly.

### FIX DIRECTIONS (next, RULE 4 — not yet validated)
1. **Write-side superset-skip** at bio chokepoint: skip an xfsaild dir DATA/leaf write iff coherent disk is a strict SUPERSET of the buffer (disk has every entry buf has + more) → provably safe, kills stale-subset clobber. Gate multi-node+dirblock; measure RULE-0 perf (per-write read).
2. **GFS2-style release invalidation** (project_gfs2_coherency_pattern): on dir EX release, force-checkpoint (unpin) + xfs_buf_stale the clean drained dir buffers so no stale async flush + next acquire re-reads fresh. Check if release drain does xfs_log_force.
3. Leaf face may need leaf-rebuild (MXFS_IF_DIR_LEAF_STALE, default off) once DATA blocks are coherent.
Build 75FD71CC on cluster (test1=.186/test2=.182, dnsmasq-reserved now). Marker NOT written.
