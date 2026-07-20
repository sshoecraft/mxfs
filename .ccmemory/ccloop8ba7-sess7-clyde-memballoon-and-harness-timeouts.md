---
name: ccloop8ba7-sess7-clyde-memballoon-and-harness-timeouts
description: sess7 infra: clyde mem-exhaustion (32 VMs 4G→62GB RSS + full swap) caused multi-min I/O stalls → heartbeat purges/barrier fails. Fix: balloon VMs to…
metadata:
  type: project
tags: [ccloop-8ba7ae5c, sess7, infra, testbed]
---

# clyde host-pressure stalls + harness timeout semantics (sess7)

## The stall family that broke chunk-3 (cc 31/32 "cv barrier write") and killed runs
- clyde: 56 cores, 94GB RAM. 32 test VMs @4G max ballooned to ~2.2GB RSS each = 62GB + vLLM (~4.5GB) + host ⇒ available ~2GB, swap 8G/8G FULL → multi-minute reclaim/IO stalls.
- Symptoms on nodes: bdev_pipelined_read hung at mount (iter_16 test14), folio-lock waits >250s (test7 P67-AG-BAST-STALL page_ms=252s), sequential disklock HEARTBEAT expiries (slots 9/13/24/22) with lock purges — heartbeats are raw PAL bdev writes, so their loss = host-level I/O stall, NOT mxfs logic.
- The hold-and-wait cycle (folio holder → peer AG → own AG release → folio writeback) is REAL but bounded by CAW 120s timeouts; it unwinds. The sess34-pending "drop locks across CAW poll in xfs_bmap_btalloc/writeback" tension remains open but was NOT the chunk-3 root — host pressure was.
- **FIX applied: `virsh setmem testN 2621440 --live` for all 32 (4G→2.5G)** → qemu RSS 62→31GB, 30GB free. Guests healthy at 2.3G (fio is O_DIRECT). Plus swapoff/swapon to clear the 8GB swap debt (43s). VM restarts would re-lose this — re-balloon after any virsh destroy/start cycle (prep escalation reboots nodes! consider making run.sh prep re-apply setmem, or define VMs with 2.5G).
- MQTT coord broker = **192.168.1.149 (external host, NOT clyde)**; mosquitto inactive on clyde is normal. COORD_TIMEOUT default 120s.

## Harness timeout semantics (run.sh run_coord)
- Per-node ssh dispatch timeout tt = manifest budget (×N if linear) — **×20 under RULE0_CALIBRATE=1**. fio_perf: 30s flat → tt=600s/node. NEVER wrap run.sh in `timeout` shorter than tt+dispatch (~tt+60) or the kill leaves mount casualties (killed mid-O_DIRECT fio → node shutdowns → next run pre-assert "not mounted" → forced re-prep). Killed-run wreckage cost this session ~4 prep cycles.
- fio_perf @32/caw true wall: 225s (healthy, build 8C047F6F) but varies with LUN/host contention; treat >600s as failure, not <590.
- After ANY killed run: `fuser /tmp/mxfs_run.lock` → kill chain, expect 1-N unmounted nodes, force fresh prep.
- prep escalation reboots stuck nodes via virsh (that's the "escalating" line) — normal.

## dblalloc_repro journal pull gotcha
`... | gzip | base64 -w0` then LOCALLY `base64 -d | gunzip` — do NOT grep the base64 stream (GNU grep treats the 700KB single line as binary → empty output). Banner lines are stderr-only; 2>/dev/null suffices.
