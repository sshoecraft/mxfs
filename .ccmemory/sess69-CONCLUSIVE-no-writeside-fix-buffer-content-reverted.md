---
name: sess69-CONCLUSIVE-no-writeside-fix-buffer-content-reverted
description: sess69 CONCLUSIVE: legit rm and the clobber are BYTE-IDENTICAL in buffer state (in_ail=1,bdirty=0,pin=0,buf=disk-1) — NO write-side discriminator exi…
metadata:
  type: project
---

## sess69 CONCLUSIVE — no write-side fix is possible; the buffer content REVERTED

Final discriminator test (build DE3A7E21): for `kind=data delta=1` dir writes:
- `comm=rm in_ail=1 bdirty=0 pin=0` ×184 (legit rm-rf removals)
- `comm=xfsaild in_ail=1 bdirty=0 pin=0` ×6 (THE clobber)

**IDENTICAL buffer state** (in_ail, clean, unpinned, buf_cnt=disk_cnt-1, bufgen==dirgen, real_mode=EX, same incarnation). A legit removal and the durable clobber are indistinguishable by EVERY signal available at the write-submit chokepoint (count, hash, dirty, pin, in_ail, tenure, gen, incarnation, real grant mode, txn context). 

⇒ **No write-side suppression/skip fix can work** — anything that suppresses the clobber also suppresses legit removals (= resurrection / empty-dir, the proven enforce=2 catastrophe). STOP pursuing write-side chokepoint fixes (dataclobber/dirskip/owner-fence — all dead ends).

### What this proves about the root
The clobber buffer (block 0, daddr=120, content=154) is a CLEAN in-AIL buffer that is BEHIND durable disk (155), while the node holds EXCLUSIVE EX, same incarnation. A clean buffer's b_addr = its last-applied content. For disk to be 155 while this buffer is 154, the buffer content must have gone BACKWARD (it was 155 at the time disk was written, then reverted to 154). Under exclusive EX the only way is:
1. **A stale READ re-populated daddr 120**: after the buffer destaged at 155, the acquire-evict cleared XBF_DONE, and the next read re-fetched STALE 154 content (non-coherent read, or a stale cached page) into b_addr → b_addr=154 → xfsaild reflushes 154 over disk 155. ⇒ a READ-coherency bug (re-read returned content older than durable disk).
2. **daddr-120 ALIASING under reuse**: dir block 0's logical→physical mapping (daddr 120) was reused/remapped within the round so "disk@120" at write-time ≠ "disk@120" at read-time.

### REQUIRED next instrument (the only way forward)
Trace the b_addr CONTENT HISTORY of daddr 120: log (entry-count, realns) at EVERY dir-block READ-completion AND WRITE-submit for daddr 120 (uncapped, streamed). Reconstruct the sequence: find where the count goes BACKWARD (e.g. write 155 → later read/populate 154). That backward step is the bug:
- If a READ populates 154 after disk is 155 → read-coherency (the FUA/cold re-read returned stale; check fua_disable, the read path's source, SCST cache). 
- If daddr 120 was freed/realloc'd between → aliasing (trace dir bmap alloc/free for the dir inode + daddr).
Add the read-completion fingerprint at xfs_da_read_buf done / the dir3 verify, gated by dirwr, owner==dir.

### Session refutation tally (all with direct evidence — do NOT retry)
phantom-EX, double-grant, split-master, reacquire-evict-incomplete (P-DE-BLK SKIP=0), release-not-durable, reload-skipped (P116=0), detectable-stale-base (P-TDS-RMW stale_base=0), extent-map-divergence (MAPDIVERGE=0), non-owner-flush (real_mode=EX), write-side suppression (catastrophic + indistinguishable from rm), bdirty/pin/in_ail discrimination (identical to rm).

### Conclusion
The bug is a buffer-content REVERSION on dir block 0 (reused daddr 120) — a READ re-populating stale content OR daddr aliasing — flushed by xfsaild while legitimately holding EX. Fix is on the READ/alloc side, not the write side. Build DE3A7E21 baseline+detector (inert at production). Marker NOT written — criterion NOT met. See [[sess69-CONFIRMED-clobber-is-inail-clean-superseded-buffer-reflush]].</body>
