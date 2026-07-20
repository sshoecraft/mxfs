---
name: sess68-writeprobe-countdrops-need-incarnation-tag
description: sess68: always-on write-side P68-DWR probe shows per-daddr dirent-count DROPS (block0 daddr=120: 154->117) but can't separate lost-update from rm-rf…
metadata:
  type: project
---

## sess68 — write-side count-drop probe lands; needs incarnation tagging to be decisive

Continues [[sess68-MAPDIVERGE-rules-out-extentmap-loss-is-pure-datablock-RMW]].

### Added always-on write-side probe P68-DWR
xfs/libxfs/xfs_dir2_data.c `xfs_dir3_data_write_verify`: for a multinode dir, count ALL "node[1-8]" dirent names in the block being written + log (daddr, nodecnt, comm). Cheap, no-IO, ratelimited 4000. Goal: catch a daddr whose dirent count DECREASES = the durable lost-update in the act.

### RESULT: count drops DO occur, but ambiguous without incarnation tag:
- test2 block0 daddr=120: 154->117, 142->119
- test3 daddr=2093296: 87->44 ; test4 daddr=2093296: 152->1, daddr=2093304: 44->1, daddr=120: 155->146
- Drops to ~1 are clearly legit rm-rf+recreate RESETS (daddr reused for a fresh 1-entry incarnation). The mid-range drops (154->117, 87->44, 155->146) COULD be a real same-incarnation lost-update OR a legit shrink — **cannot distinguish** because the dir3 data-block header carries `owner` (inode #) but NOT the inode generation, so the write-time probe can't tag the incarnation.
- (This run lost single entries: node4_f29.md5 round 13, node3_f1.md5 round 14.)

### NEXT STEP (RULE 4, decisive): tag the write probe with incarnation + round so a count-drop WITHIN one incarnation (the bug) is separable from a cross-rm-rf reset (legit):
- The dir block header lacks di_gen. Options: (a) stamp the WRITING inode's i_generation into a b_mxfs field (e.g. b_mxfs_dir_incarn — already exists!) at modify time, and log it in P68-DWR; a count-drop with the SAME b_mxfs_dir_incarn across two writes = real lost-update. (b) Correlate P68-DWR timestamps with the test's PHASE markers (DRCph r=N PHASE=create-start/rm-done on /dev/kmsg) — a count-drop BETWEEN create-start and rm-done of the same round = lost-update; a drop straddling a rm-done = legit reset. (b) needs no code change — just interleave P68-DWR with the existing DRCph kmsg markers in one dmesg and check if the drop is intra-create-wave.
- Once a real intra-incarnation count-drop is confirmed on a specific daddr, the P68-DWR `comm=` field names the culprit: kworker/xfsaild = stale writeback of an undrained block; dd/bash/sync/md5sum = a live stale-base RMW. That pins write-side vs the fix site.

### SESSION NET (criterion NOT met): 
- KEEP (proven): gap-B fix (`mxfs_dlm_dir_inode_durable` non-LOCAL, dirty-gated) — makes grown dir extent map durable at release; P68-GROWREL-VERIFY confirms DURABLE 48/48.
- RULED OUT: extent-map divergence at modify (P68-MAPDIVERGE=0), cached-block survival (drop_caches → owner-evict collected=0), extent-map release durability (gap-B confirms), DLM double-grant (sess62).
- NARROWED TO: pure dir-DATA-block content RMW lost-update at a daddr all nodes agree on.
- Build HEAD `EAB3D32098D503EB6B34391`: gap-B + probes (P68-DATAINIT, P68-GROWREL-VERIFY, P68-DWR always-on; P68-MAPDIVERGE/owner-evict gated off, code kept). Shipped-proven baseline 91962D4A.
- INFRA: test2 wedged once (D-state mxfs-ino-bast kworker blocking rmmod) → rebooted test2 VM (virsh destroy/start, allowed). If prep fails "bad nodes: testN(build mismatch)", that node's rmmod failed (stuck mount/worker) — reboot that test VM. Cluster left healthy (test1-4 mounted, no D-state).

REPRO: clean rmmod test1-4, `./run.sh 4 tcp dir_reuse_coherency` (~310s, ~1/15 rounds FAIL).</body>
