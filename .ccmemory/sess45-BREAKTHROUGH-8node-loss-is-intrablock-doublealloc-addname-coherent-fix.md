---
name: sess45-BREAKTHROUGH-8node-loss-is-intrablock-doublealloc-addname-coherent-fix
description: sess45 BREAKTHROUGH: 8/tcp SINGLE loss PROVEN = intra-block free-slot DOUBLE-ALLOC (P13-COLLIDE node7 placed onto disk's node8_f8.md5). Platter curre…
metadata:
  type: project
---

## sess45 BREAKTHROUGH — the 8/tcp SINGLE-dirent loss mechanism, PROVEN

### DECISIVE evidence (tests/drc_detail8.sh, build C074A836, no instr):
Lost file round22 = node8_f8.md5 (all ranks readdir=799). The smoking gun on test7:
`P13-COLLIDE ino=131 daddr=14652640 off=2776 our=[node7_f8.md5] disk=[node8_f8.md5]`
→ node7's addname placed node7_f8.md5 at byte offset 2776 of block 14652640 where
node8 had ALREADY durably written node8_f8.md5 → **intra-block free-slot
DOUBLE-ALLOCATION**, node8_f8.md5 clobbered. NO P-DOUBLEGRANT, NO
P-STALEMASTER-GRANT, NO flap, NO P58-SELFSKIP at the loss → DLM serialized
correctly; NOT membership split-brain.

### KEY: the PLATTER is CURRENT, the IN-CORE base is STALE.
P13-COLLIDE does a plain-bdev read and SAW node8_f8.md5 on disk at off=2776. So
dir_release_fua_write=1 (the platter-lag writer fix) WORKS — disk has node8's add.
But node7's IN-CORE cached block for daddr=14652640 did NOT reflect it, so node7's
free-slot search picked 2776 as "free" → RMW clobber. This is an ACQUIRE-SIDE
stale-in-core-base double-alloc.

### THE FIX (testing now): dir_addname_coherent=1 (xfs_mxfs_dlm.c:5363, default 0;
mxfs_dir_addname_coherent_refresh in xfs_dir2_data.c:1603). Before the first add
into a CLEAN dir block, FUA-read the platter; if in-core != platter, invalidate +
reread + restart the addname. node7 would then see node8_f8.md5 at 2776 and pick a
different free slot → no double-alloc.

### WHY sess28 REFUTED dir_addname_coherent but it should work NOW:
sess28 (DEFAULT 0 comment): "engages (P28C-STALE fires ~1/run) but does NOT
eliminate the loss (rdmiss=1 persists)". CRITICAL: sess28 was BEFORE the
platter-lag writer fix (dir_release_fua_write). Back then addname_coherent's FUA
reread hit the LAGGING platter (LIO write-cache not flushed) → it reread a STALE
platter missing the peer add → couldn't fix the double-alloc. NOW with
dir_release_fua_write=1 forcing the platter current, the reread sees the peer's
add. The writer-side (platter durable) + reader-side (reread current platter)
fixes are COMPLEMENTARY and were never tested together until sess45.

### CAVEAT: addname_coherent only handles CLEAN blocks (returns 0 if
dirty/in-AIL/pinned). The collision block is clean on node7 before its first add,
so it should catch it. If a DIRTY-stale block still double-allocs, also need the
sess61 dirty-keep fix. Also watch RULE-0 slowness (per-clean-block FUA read).

### Config under test: build C074A836 (= dir_release_fua_write=1 default +
membership beacon + run.sh convergence gate + self-fence) + modargs
"memb_settle_ms=20000 dir_addname_coherent=1". batch8_addnamecoh.log.
If it passes reliably: make dir_addname_coherent=1 + memb_settle_ms=20000 DEFAULTS,
rebuild, full 1/2/4/8 tcp validation. See
[[sess45-RESURRECTED-platter-lag-fix-dir-release-fua-write-default-on]]
[[sess45-progress-platter-fixed-8node-splitbrain-stochastic]]
[[sess44-PROVEN-offset-collision-double-alloc-aoff1600-four-dirents]].
