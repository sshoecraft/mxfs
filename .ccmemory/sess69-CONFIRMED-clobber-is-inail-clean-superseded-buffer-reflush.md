---
name: sess69-CONFIRMED-clobber-is-inail-clean-superseded-buffer-reflush
description: sess69 CONFIRMED: clobber = xfsaild reflush of an in_ail=1/clean/unpinned dir block-0 buffer (reused daddr 120) 1-behind durable disk, EX held. Fix =…
metadata:
  type: project
---

## sess69 CONFIRMED buffer state at the clobber (build DE3A7E21, dataclobber=1 detect)

The single-dirent clobber write, full state (6 samples, all consistent):
```
P-DATACLOBBER-SKIP kind=data owner=131 daddr=120 buf_cnt=154 disk_cnt=155 bufgen=8 dirgen=8
  mode=5 real_mode=5 in_txn=0 in_ail=1 bdirty=0 pin=0 bflags=0x32
  incarn==bincarn stale=0 comm=xfsaild/sda
```
Decisive facts:
- **real_mode=5 (EX)** — node holds genuine exclusive EX (non-owner-flush REFUTED).
- **in_ail=1, bdirty=0, pin=0** — the buffer is in the AIL but CLEAN (already destaged, XFS_LI_DIRTY clear) and UNPINNED. It is a LINGERING committed buffer, NOT un-checkpointed work.
- **buf_cnt = disk_cnt - 1** — it is 1 entry BEHIND the durable on-disk block.
- **bufgen==dirgen, same incarnation** — current tenure, same dir incarnation. NOT gen-stale, NOT ABA.
- daddr=120 = dir block 0 (reused every round); holds up to ~164 small entries.

### Mechanism (now precise)
xfsaild flushes a CLEAN in-AIL dir block-0 buffer whose b_addr content (154) is a SUPERSEDED earlier version — disk already advanced to 155 (a later commit to the same daddr). Flushing the 154 reverts disk, dropping the entry. The node holds EX throughout (so this is its OWN superseded buffer, not a peer's). Because the buffer is clean (not dirty/pinned), the acquire-evict's undurable-keep guards do NOT protect it from being flushed, and clearing XBF_DONE does not stop xfsaild from writing the lingering BLI's b_addr.

### Why every prior fix missed it
- Count/set suppression (dataclobber): can't distinguish from a legit rm (both buf=disk-1) → enforce=2 emptied the dir. REFUTED.
- Tenure/gen/incarnation guards: bufgen==dirgen, same incarn → all pass it as "current". 
- Owner-fence (held<EX skip): real_mode=EX → wouldn't fire.
- Stale-base-reload (68 sessions): the modify base wasn't detectably stale (it's a write-time superseded-buffer reflush, not a read-time stale base).

### THE DISCRIMINATOR + FIX (next session)
A legit rm flush is the LATEST committed version of the block (no newer version exists). The clobber is a SUPERSEDED version (a newer committed image of the same daddr exists — disk has it). So: **skip an xfsaild dir-DATA/leaf flush iff the buffer is in_ail + CLEAN (bdirty=0,pin=0) AND a newer version of that block exists** (disk content has strictly MORE/different entries AND the buffer carries no un-checkpointed work). Safe because: clean+behind-disk = nothing to lose (disk ⊇ buffer); a legit rm buffer is DIRTY at the moment its removal is the live change OR is the latest (no newer disk version with the removed name re-added). 
- INSTRUMENT to confirm the discriminator: at the clobber, check if there is a DUPLICATE/newer xfs_buf or a higher-lsn BLI for daddr 120 (the "two versions for one reused daddr" theory). If a duplicate buffer exists, the root is buffer-cache aliasing under daddr reuse — fix = on freeing/reallocating a dir block daddr, evict+remove-from-AIL any stale buffer at that daddr so no superseded version lingers.
- SAFER FIX (no suppression risk): skip the flush ONLY when `in_ail && !bdirty && !pin && disk is a strict superset of buffer` (clean superseded image). Since the buffer has NO un-checkpointed work (clean), skipping its write loses nothing and prevents the revert. Test carefully against rm-heavy paths (unlink_visibility).

### Status
Build DE3A7E21 (baseline + dirwr-gated detector w/ real_mode + AIL state; inert at production). Repro: `MXFS_EXTRA_MODARGS='dataclobber=1 dirwr=1' MXFS_TEST_ENV='DRC_ROUNDS=20 DRC_STREAM=1' ./run.sh 4 tcp dir_reuse_coherency`. Cluster healthy (test3 was virsh-reset mid-session after a wedged mxfs-ino-bast kworker). Marker NOT written — criterion NOT met. Supersedes the non-owner-flush direction in [[sess69-FINAL-clobber-indistinguishable-from-rm-real-held-ex]]. See [[sess69-ROOT-xfsaild-reflush-stale-dir-buffer-behind-disk]].</body>
