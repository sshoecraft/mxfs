---
name: ccloop-c7ee71c6-sess47-TAIL18-386c2-media-vs-transit
description: sess47 final: 386 c2 fatal (ring c2_386 saved) — relay's DECISIVE experiment: raw O_DIRECT dump of victim chunk from another node (media correct + FU…
metadata:
  type: project
---

# 386 cycle-2 fatal → the decisive experiment (relay first move)

Ring test2:/root/c2_386_t2_*.dmesg: P53 ino=0x3400148 old_ptr=0x147 (fossil), fatal. Store v3 + 3 install sites live; producer still ~1/2 cycles on test2. The install-site chase is not converging — run the DISCRIMINATOR before more hooks:

## Experiment (precedent: the 07-16 comment in mxfs_buf_is_multinode_dir_meta — raw O_DIRECT dump proved transient-vs-durable before)
On the NEXT fatal (or a caught overlay specimen): from a DIFFERENT healthy node, O_DIRECT-read the victim cluster's sectors (daddr+bt_sector_offset) and decode the victim slot's di_next_unlinked.
- MEDIA CORRECT (holds the committed value) while the failing node's FUA read saw the old value ⇒ **the LIO/SCST target serves stale data on the FUA-READ path** (cache-bypass reads pre-cache media; completion=cache) ⇒ fix is TRANSPORT-SCOPED, not more overlay sites:
  **Candidate fix F: cluster-buffer re-reads use PLAIN bio (cache-coherent) instead of FUA whenever the AG's pag_mxfs_inocl_wr_epoch is inside the unflushed window (our own recent write ⇒ the target cache holds OUR data ⇒ plain read is the CORRECT coherence point).** Mirrors mxfs_fua_disable semantics, scoped to clusters+own-window. The FUA-freshness rationale (peer handoff) is preserved outside the window because peers' handoffs destage+flush first (invariant 1).
- MEDIA STALE ⇒ the write truly never landed ⇒ write-side: FUA cluster WRITES + verify-after-write.

## Tooling
tools/ has caw_verify/fua_verify precedents for raw sector access; a tests/dump_dinode_slot.sh (node, daddr, slot) helper would make the experiment one command. bt_sector_offset = envelope offset (chk_mxfs geometry).

## Standing state
0.11.386, store v3 + 3 sites (machinery sound — specimens correct real fossils; coverage or transport is the gap). All history TAIL7-TAIL17. test2 withdrawn, ring saved; 31 green.
