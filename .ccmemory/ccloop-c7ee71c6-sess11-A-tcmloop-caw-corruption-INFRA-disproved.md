---
name: ccloop-c7ee71c6-sess11-A-tcmloop-caw-corruption-INFRA-disproved
description: sess11 ROOT: cawp@16 catastrophe = LIO tcm_loop CAW multi-seg SGL bug (kernel, not mxfs). Page-crossing data-out corrupts write half. CAW validation…
metadata:
  type: project
tags: [caw, tcm_loop, lio, infrastructure, rule6-disposition]
---

# sess11 — cawp-on-LIO catastrophe DISPROVED as mxfs defect (infrastructure)

## Root cause (kernel target-core + tcm_loop, proven from clyde with no VMs involved)
`tests/caw/caw_align_probe.c` (built, in-tree): CAW 0x89 with the 1024B compare+write
payload at controlled page offsets, direct against /dev/sda (tcm_loop) on clyde:
- off 0/1024/3072 (payload within one page): **OK every time**
- off 3088/3584/3600/4080 (payload crosses a page boundary): **CORRUPT every time** —
  bytes beyond the first page arrive as zeros or RECYCLED STALE BOUNCE content
  (looked like qemu heap: repeating record arrays w/ 0x5777... PIE-heap ptrs).
- upstream flaw: `target_core_sbc.c compare_and_write_callback` — comment
  "Currently assumes NoLB=1 and SGLs are PAGE_SIZE.." — write-phase SGL built as
  {page(entry0), block_size, entry0.offset + block_size}: both halves assumed in ONE
  sg entry. tcm_loop passes the initiator's raw SGL through (2 entries when the user
  buffer crosses a page); iSCSI targets RX into their own PAGE_SIZE buffers → immune.
- compare half uses sg_copy_to_buffer (nents-correct) → compares usually still pass →
  **CAW returns SUCCESS while writing garbage** (silent corruption).

## Why per-VM russian roulette
qemu scsi-block passes CAW via SG_IO using a per-instance bounce buffer at a fixed
heap address (bpftrace on sg_io: dxferp%4096 was 3088 on the broken VM = crossing;
1152/256/976 on the 3 clean VMs = within-page; payload bytes at sg_io entry were
COMPLETE on both good+bad VMs — qemu delivers correctly). addr is ASLR-rolled per
qemu start → P(cross) = 1023/4096 ≈ 25% per VM instance. 16 VMs ⇒ ~99% ≥1 broken ⇒
sess10's cawp@16 carnage (cc 444/590, CAW EX publish rc=-108, LIO "Detected
MISCOMPARE at offset 4" storms = peers CAWing against a corruptor's garbage slots).

## Consequences / decisions
- **tcm_loop can NEVER host CAW conditions** (any guest kernel CAW rides qemu's bounce).
  tcp condition unaffected (no CAW). dlm_lock_correctness.sh's old "LIO/tcm_loop
  ILLEGAL REQUEST" comment is outdated — modern LIO advertises+accepts CAW and
  corrupts it via tcm_loop instead.
- CAW family (cawp/cawd/caw) validation → SCST stack (custom CAW-patched modules in
  /lib/modules/$(uname -r)/extra, scstadmin present, scripts/scst_setup.sh exports
  /home/steve/disk.img as iqn.2026-05.local.mxfs:shared on 192.168.120.1:3260,
  tears down LIO first — mutually exclusive on the same img). scst.service boot
  failure = stale /etc/scst.conf (disk-1.img) — IGNORE, harness uses sysfs directly.
  Historical: 32/cawd board ran green on SCST (ccloop 7251 sess1, 0.11.7 era).
- mxfs hardening idea (unfiled): mount-time CAW probe should DATA-VERIFY its CAW
  (read-back compare), not just status-verify — a corrupting-but-ACK'ing stack would
  then fall back to TCP instead of forming a broken cluster.
- bpftrace scripts in scratchpad (sgio_caw.bt / sgio_addr.bt) — trivial to recreate:
  kprobe:sg_io, hdr+4=dir(-2=TO_DEV), +10=iovec_count, +12=dxfer_len, +16=dxferp.
