---
name: AAA-ccloopa864-sess1-STATE-binval-zombie-fixed-rm-pace-hunt
description: sess1(a8642ea1): dir_reuse@32 = last gap. FIX1 binval-retire (v0.10.34) proven; FIX2 random jitter (v0.10.35 05F2E45C). rm pace 55ms/unlink = bottlen…
metadata:
  type: project
---

# ccloop a8642ea1 sess1 — dir_reuse@32 is the ONLY criteria gap; two fixes in

## Board state (criteria.json, verified via showstat)
1/2/4/8/16/caw ALL 17/17 PASS. 32/caw = 16 PASS + **dir_reuse_coherency PENDING** — the single remaining gap for the whole criteria ("1/2/4/8/16/32 node caw dlm multipath test working 100%"). Invocation: `MXFS_DEV=/dev/mapper/mpatha MXFS_EXTRA_MODARGS="dirwr=1 dirland=1" timeout 5200 ./run.sh 32 caw dir_reuse_coherency`.

## Infra after clyde reboot (user rebooted host ~19:00Z Jul10)
- /etc/scst.conf is STALE (disk-1.img refs → boot-time scst.service FAILS; ignore it). Rebuild: `sudo ip addr add 192.168.120.2/24 dev br0` + `sudo MXFS_SCST_PORTAL_IP="192.168.120.1 192.168.120.2" scripts/scst_setup.sh setup` + boot 32 VMs + `scripts/mpath_up.sh up 32`.
- /tmp/.mxfs_pass wiped by reboot → restore from /home/steve/.mxfs/pass.
- After killing a run mid-flight: nodes wedge SSH-dead ASYNCHRONOUSLY (test17 then test20 then test25) — sweep ALL 32 for SSH, power-cycle dead, mpath_up 32, BEFORE relaunching. run.sh prep power-cycles some but ABORTS on ssh-dead at build-check.

## FIX 1 — PROVEN ROOT: binval'd buffer's undestaged debt wedges release fence (v0.10.34, xfs/xfs_trans_buf.c xfs_trans_binval)
Chain (all instrumented, run 20260710T193328Z on 7395C3EC): r2 rm-tail btree collapse frees rank1's bmbt leaf (daddr=18839216) with lseq=102>wseq=100 (last 2 logs = collapse+free, correctly never written); mxfs seq accounting survives the free; daddr reallocated in r3 as dir DATA block (platter=XDD3 owner=131, written by another node); test1's release fence map-walk hits the cached corpse: done=0 stale=0 li_empty=1 undest → data_durable=0 forever + P3F-UNLANDED-LOST refuses garbage (bmbt image ∉ dir magics) ×15006 laps → 240s EX hold on ino=131 (P51-REL drain_ms=240177) → P97-RELFENCE-WEDGE shutdown → 14 peers die rc=-110 (2×120s starvation, "DLM inode lock unrecoverable") → cluster-wide FAIL. 16-node never hit it: 1600-entry dir stays EXTENTS fmt (no bmbt). FIX: in xfs_trans_binval equalize b_mxfs_written_seq=b_mxfs_logged_seq + P3B-BINVAL-RETIRE probe. VERIFIED on 20260710T202216Z: P3B fired 56×(rm, dir3 data/leaf/block bufs), r3 kill-zone passed clean, 0 P3F/P97/rc=-110 through r6.

## FIX 2 — rm pace: deterministic backoff phase-lock (v0.10.35, srcversion 05F2E45CDEE4D4576199064, dlm/dlm_caw.c caw_inode_backoff)
Round walls on v0.10.34: r1=222 r2=240 r3=261s (create ~20-44 + verify ~41-54 + **rm 159-176s**). Budget 140*32=4480s ⇒ need ≤186s/round. rm = 3200 sequential unlinks × ~45ms EX-handoff (P138-WAIT elapsed_ms≈45, sequential file inos). Decomposition: each unlink BASTs ~31 PR holders (every node md5-read every file in verify → PR cached); holders' unlock = read-modify-CAW on the SAME slot → thundering herd; P138-BAST stage split: clean file release su(unlock CAS)=10-23ms typ, 101ms tails. Old backoff `(retry+node*5)%7` = only 7 phases → ~5 nodes/phase re-collide forever. FIX: true-random jitter 1+rnd%min(6+2*retry,20) via mxfs_pal_get_random_bytes.
Measure NEXT: round pace on 05F2E45C (run 20260710T205926Z, pid 109162 clyde, log scratchpad/drc32-r3.log). If rm still >~110s/round → next lever = release-PR-on-last-close for clean regular files (kills the herd: 0 holders at rm; risk: cache_coherency re-read pattern re-acquires per read — check cc budget).

## Key techniques (this session)
- Per-node continuous capture: /root/dmesg.stream (suite starts it; survives ring rotation). scp to scratchpad for python analysis.
- Envelope raw platter read: img sector = xfs daddr + 196688 on /home/steve/disk.img (python open+seek, magic at +0, dir3 owner at +40..48, bmbt long-form owner at +56..64).
- P138-WAIT (acquirer, >40ms EX waits) / P138-BAST (holder stage split sa/sb/b1/b2/sc/sd/su µs) / P106-EXREL realns (cross-node handoff correlation) / P70-BP ENTRY..EXIT (bast pipeline span).
- DRCph round-phase markers: grep "mxfs-DRCph r=N rank=1 PHASE=" for create-start/create-done/verify-done/rm-done walls.
