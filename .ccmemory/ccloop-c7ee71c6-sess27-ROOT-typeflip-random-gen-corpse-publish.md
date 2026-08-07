---
name: ccloop-c7ee71c6-sess27-ROOT-typeflip-random-gen-corpse-publish
description: ROOT PROVEN+FIXED sess27: D-DIRENT-INODE-TYPE-MISMATCH = RELOAD-TYPEFLIP-STALE-SKIP keeps a DEAD incarnation because XFS gens are RANDOM, then publis…
metadata:
  type: project
tags: [typeflip, inode-reuse, D-DIRENT-INODE-TYPE-MISMATCH, root-cause, sess27]
---

# sess27 ROOT CAUSE PROVEN + FIXED — D-DIRENT-INODE-TYPE-MISMATCH

Build 0.11.234 (`EF05E2534A9855795A875F8`). Knob `mxfs.typeflip_skip_same_incarn`
(default 1 = fix; 0 = legacy negative control).

## The bug, in one sentence

`RELOAD-TYPEFLIP-STALE-SKIP` (xfs_mxfs_dlm.c ~20198) kept the in-core inode
whenever `disk_gen <= incore_gen`. **XFS generations are RANDOM**, so on a
genuine cross-node inode-number reuse that comparison is a coin flip; when it
lost, the node kept a **DEAD incarnation** and its release drain **PUBLISHED
that corpse** over the peer's live inode — durable namespace corruption agreed
by all 32 nodes.

Note `sess96`'s own comment two lines above already said the gen comparison is
unreliable, but only patched the case where a lookup supplied a dirent ftype.
When `expect_ftype == XFS_DIR3_FT_UNKNOWN` (reload from a release/BAST path,
not a lookup) the broken comparison was the ONLY discriminator.

## Byte-exact capture (32/caw, ino 10485888, name `node15.txt`)

    test15  creates dir ino 10485888, gen 2697616535
    test15  frees it        EVICT-RING-FLAG incore_gen=...535 freed_gen=...536
    test15  reuses the number for a REGULAR FILE, new random gen 2379993492
    test30  RELOAD-TYPEFLIP-STALE-SKIP incore_mode=040755 disk_mode=0100644
            incore_gen=2697616535 disk_gen=2379993492 expect_ft=0
            <-- reads the CORRECT new image and REJECTS it
    test30  P170-CLWR publishes 10485888:40755:..6535   (realns ...79.98)
            2.5 s AFTER test15 published 10485888:100644:..3492 (realns ...77.48)
    all     dirent ftype=REG vs DIR inode; P95B spins 201 rounds, resolved=0

## THE LEDGER'S "SETTLED" VERDICT WAS BACKWARDS

`which_side_is_wrong: SETTLED (sess22): the DIRENT is the corrupt side` is
**REFUTED**. sess22 read the child's "disk" mode through the buffer cache — the
same path under suspicion — so both sides agreed and the reasoning was circular.
New probe `P207-COHERENT-TRUTH` reads the platter with a **plain bio** at the
resolver give-up; it showed `coh_mode=040755 coh_gen == incore_gen`, i.e. the
PLATTER ITSELF held the pre-free DIR image. A live inode can never carry a gen
older than its own free, which is what proves the platter is the stale side.
Consequence: sess22's `blocking_fix` ("root the dirent side") aimed at the wrong
half, which is why `typeflip_fail_unresolved` could never fix it.

## The fix

Gate the skip on the SAME INCARNATION (`disk_gen == incore_gen`) — exactly what
sess103 already did for the sibling `RELOAD-SIZE-DROP-SKIP`, and what the
guard's own documented target case (sess90's stale-cluster clobber) has.

## Paired A/B, ONE build, knob flipped at runtime, fresh mkfs per arm

| | A: `=0` legacy | B: `=1` fix |
|---|---|---|
| cache_coherency | FAIL 1/32 (failed=2) | PASS 32/32 654/654 23s |
| dirent_type_integrity | FAIL 5/32 unresolved=4 | PASS 32/32 unresolved=0 |
| P208 exposure | 432 `action=keep` | 223 `action=adopt` |
| RELOAD-TYPEFLIP-STALE-SKIP | 432 | 0 |
| P201 / P207 | 165 / 165 | 0 / 0 |

An earlier control iteration PASSED with **P208 = 0** — it never entered the
state. So the failure tracks the EXPOSURE, not the arm label, which is the
causal link: exposure>0 + keep = corruption; exposure>0 + adopt = clean.

**Make P208 knob-INDEPENDENT.** The first cut gated it on the fix, so the arm
that reproduces the corruption reported zero exposure and a passing control was
indistinguishable from one that never entered the state.

## THE REPRODUCER (this is what every earlier session missed)

    prep -> dirent_durability -> cache_coherency        (3 for 3 pre-fix)

`dirent_durability`'s 30-round mkdir/rmdir storm is the AGING pass that drives
cross-node inode-number reuse; `cache_coherency` then creates regular files that
land on the reused numbers. Running `cache_coherency` FIRST — manifest order, on
a fresh mount — does NOT reproduce it, which is exactly why the board showed it
green at 654/654 for many sessions. Harness: `tests/typeflip_ab.sh`
(`arm-prep`/`arm-measure`/`arm`), `tests/inode_cluster_clobber_capture.sh`.

## Refuted this session (do not re-walk)

`P206-RENAME-FTYPE-STALE` / `P206-LINK-FTYPE-STALE`: the hypothesis that
`xfs_vn_rename`/`xfs_vn_link` write a dirent ftype snapshotted from `i_mode`
BEFORE the ILOCK (which an MXFS reload can change) — **measured 0 on every node
while P201 fired**. The written ftype always matched the post-lock type. Probes
kept; knob `mxfs.rename_ftype_revalidate` ships default 0.
