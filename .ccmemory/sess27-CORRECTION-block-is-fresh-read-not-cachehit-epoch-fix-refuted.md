---
name: sess27-CORRECTION-block-is-fresh-read-not-cachehit-epoch-fix-refuted
description: sess27(ccloop) CORRECTION + REFUTED FIX: the dir-slot collision is NOT a stale cache hit. P28-CHECK proves b_mxfs_dir_epoch==valid_epoch==master on E…
metadata:
  type: project
---

## sess27 CORRECTION — the addname reads the block FRESH; the loss is durability, not cache-staleness

### What I built and why it's REFUTED
Implemented `dir_addname_epoch_refresh` (xfs_dir2_node.c xfs_dir2_node_addname_int, gated param default 0): on the addname's data-block pick, if the block's b_mxfs_dir_epoch lags the master dir epoch, refresh+restart so its bestfree reflects the occupied slot. Build 5B9A014F (= keeper + this inert gated fix + a P28-CHECK diagnostic). Ran 8/tcp param=1: FAIL, P28-ADDNAME-EPOCHSTALE fired **0x**.

### WHY it can't fire (P28-CHECK decisive, ino=131, every addname):
`b_epoch=100 valid_epoch=100 master=100 done=1 dirty=0 in_ail=0 pin=0` — ALWAYS equal. The data block the addname picks is FRESHLY READ at the CURRENT epoch every time (dir_gen_per_handoff invalidates on every handoff → the addname's read is a cache miss → FUA re-read → stamped current epoch). So it is NOT a stale prior-tenure cache hit; b_epoch never lags. The epoch/gen staleness model (sess16/sess23/this fix) cannot detect this loss.

### Corrected mechanism model
node7's addname FUA-reads the dir data block COHERENTLY (current epoch), yet the read returns content that does NOT include node5's just-added node5_f46.md5 → its bestfree shows off=1280 free → node7 allocates there → overwrites. So at node7's read time, the PLATTER did not have node5_f46.md5 at off=1280. This is either:
(a) WRITE-side durability: node5's add to off=1280 was not durable on the platter when node7 read (node5's release-drain gap, e.g. P11-FLUSH-UNCACHED, OR LIO device-cache returning a stale platter image to node7's FUA read despite emulate_write_cache=0), OR
(b) a genuine concurrent-allocation race: node5 and node7 each FUA-read off=1280 as free (neither's add durable at the other's read) despite EX serialization — implies durability lags EX release.
Either way: the binding issue is that node5's allocation of off=1280 is not visibly durable to node7's coherent read. Matches [[sess27-SYNTHESIS-slot-collision-needs-durability-ordering-not-more-rereads]] (durability ordering), NOT [[sess27-FINAL-disambiguation-readstaleness-targeted-reread-is-the-fix]] (that disambiguation was from ONE trace where node5's RELFLUSH happened to precede node7; in general it does not).

### NEXT (sess28): PROVE write-side durability at the collision (RULE 4)
At node7's addname read of the block (xfs_dir2_node.c, the P28-CHECK site), ALSO do an independent raw FUA read of the same daddr and dump whether the victim's dirent bytes are present on the PLATTER vs in the returned buffer. If platter lacks it → node5's write-durability gap (fix release-drain / P11-FLUSH-UNCACHED / FUA-write). If platter HAS it but the returned buffer lacks it → node7's read served a non-FUA stale buffer (fix the read path / device-cache). This single probe finally splits (a) vs (b). Build 5B9A014F is keeper-equivalent at default (param 0); cluster left clean. The P28-CHECK diagnostic is gated behind dir_addname_epoch_refresh=1 (off by default).
