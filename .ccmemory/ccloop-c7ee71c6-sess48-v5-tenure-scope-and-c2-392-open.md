---
name: ccloop-c7ee71c6-sess48-v5-tenure-scope-and-c2-392-open
description: sess48: v5 = tenure-scoped store (AG purge@unlock ×4 sites + LIVESKEW refusal, GPT ruling); c2-392 fatal = lost-remove fossil w/ store SILENT; 393 ad…
metadata:
  type: project
---

# sess48 late: v5 shipped; two fatal decodes; 393 diagnostics

## v5 (0.11.392) — from the GPT ruling (c3-391 inverted P53)
- Records now AG-TENURE-SCOPED: `agno` field; `mxfs_iunl_store_purge_ag(mp,agno,why)` called before ALL FOUR `mxfs_v5_dlm_ag_unlock` sites in xfs_mxfs_dlm.c (bast-inline ~39096, unmount force-release ~39148, deferred release_work_fn ~40599, iodone-fallback ~40698; each after inject-skip checks). RELLEAK (wr_epoch=0 at purge) = drain-gap evidence per GPT.
- LIVESKEW refusal in overlay: before grafting, RCU-peek `pag_ici_root` radix for the ino; live inode with `i_next_unlinked != record` ⇒ refuse + P-IUNLSTORE-LIVESKEW. (Coherent peek: all nu mutations + all 5 overlay sites hold the cluster buffer lock.)
- GPT key rulings: (ino,gen) store unsound cross-tenure (nu has NO ordering; gen ≠ nu-version); records = intra-tenure fossil protection only; buffer-graft against disagreeing live in-core edge is itself a corruption vector; wr_epoch=0 record at a post-drain release = protocol violation to alarm on.

## 392 soak: c1 CLEAN (9 benign intra-tenure grafts, 0 liveskew), c2 FATAL test2
c2 fatal shape (ring /root/c2_392_t2_1785737122.dmesg): P53 at INSERT: ino=0x3e001ad expected old=NULLAGINO, writing next=0xa6 (=i_next_unlinked), dinode ACTUALLY holds 0x1ab (live chain ptr), same gen 1642252300 both sides, bli=1 uncp=1. **Store 100% silent this cycle on test2 (ov=0 dc=0 ws=0 fw=0)**; only prior-incarnation GENSKEW (rec_gen=img_gen+1) at c1. Fleet-wide: ZERO AGPURGE/RELLEAK all of 392.
Decode: dinode's 0x1ab = leftover chain membership this runtime doesn't know ⇒ somebody's committed remove (0x1ab→NULLAGINO) never became durable/visible — cross-node (peer's store can't be seen locally) or a silent local record-lifecycle gap. The c3-391 poison mechanism (stale graft) can also travel via platter: LIVESKEW is NODE-LOCAL — a peer grafting its stale record can't see the live edge held here.

## 0.11.393 (deployed, guards clean) adds
1. P53-time store dump: `mxfs_iunl_store_query_print` called from the P53 block in xfs_iunlink_item.c → P-IUNLSTORE-QUERY (record gen/value/wr_epoch/agno or NO-RECORD + count).
2. AGPURGE-ALIVE proof-of-life (first 3 purge calls) — distinguishes "releases find nothing" from "hooks not on the real release path".
3. Sweep now counts RELLEAK/AGPURGE/LIVESKEW: `tests/iunl_soak_sweep.sh <mark>`.

## Next-fatal decision tree
- QUERY=NO-RECORD + this node once committed the lost value ⇒ local record-lifecycle gap (find who dropped it).
- QUERY=record present ⇒ overlay coverage gap (install path missed).
- RELLEAK on any node ⇒ drain gap at release (Invariant 1 violation — chase the unhomed write).
- AGPURGE-ALIVE absent ⇒ releases bypass the 4 hooks (find the real unlock path).
- LIVESKEW>0 ⇒ cross-tenure stale record caught in the act locally.

## Standing
0.11.393 fleet 32/32, soak protocol: mark (`echo 'MXFS-SOAK-MARK <m>' > /dev/kmsg` per node) + lap/idle/lap + sweep + matrix every ~2 cycles + reap guard at deploy. 11 defects OPEN of 39 (4 critical). Rings: c3_391 (t2), c2_392 (t2). History: sess48-DISCRIM-verdict-and-v4, sess48-CLMERGE-ROOT-PROVEN-site5, this.
