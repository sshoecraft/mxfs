---
name: sess28-PROVEN-readside-staleness-targeted-platter-guard
description: sess28(ccloop) DECISIVE: dir_reuse 8/tcp loss is READ-SIDE staleness, PROVEN by targeted platter guard (P28W-CLOBBER REAL hit on a FAIL run). Refutes…
metadata:
  type: project
---

## sess28 — read-vs-write DEFINITIVELY resolved: it is READ-SIDE staleness

### The flaw in sess27's "write-side" verdict
sess27 concluded write-side from P28-PLATTER = 76 MATCH / 0 DIFFER (in-core==platter). But that probe full-block-memcmp'd RANDOM addname reads (76 of ~800/round); it almost NEVER sampled the rare ~1-2 actual collision reads. "76 MATCH" only proves non-collision reads were coherent — it never measured the collision read. The write-side conclusion was unsound.

### The decisive instrument (build 9074441C; param dir_addname_platter_guard)
New probe in `xfs_dir2_node_addname_int` (xfs/libxfs/xfs_dir2_node.c, right after `aoff` computed, before `xfs_dir2_data_use_free`): FUA-read THIS daddr from the platter and check ONLY the slot we are about to write (aoff). Classify: REAL clobber = platter block is a CURRENT valid data block of THIS dir (pmagic==XDD3/XDB3 && powner==ino) AND a live dirent sits at aoff (freetag!=FREE, namelen 1..255, inumber!=0). Else = STALEALLOC (benign stale pre-alloc bytes at a freshly-grown daddr — these are the aoff=64 dirty=1 false positives seen at guard=1; harmless, we legitimately overwrite garbage).
- guard=1 = log only; guard>=2 = if block CLEAN, drop XBF_DONE|_XBF_FUA_FRESH + xfs_trans_brelse + `goto restart` so the read path FUA-refetches coherently (bestfree then skips the occupied slot). One-shot latch `platter_guarded`.

### THE PROOF (run 3 FAILED, guard=1):
`P28W-CLOBBER ino=131 dbno=3 daddr=39771336 aoff=2424 len=24 clean=1 dirty=0 in_ail=0 dir_gen=52 loaded_gen=52 pmagic=0x58444433 powner=131 pino=2099122 pnl=12 pname=[node5_f1.md5] incarn=3443405496 igen=3443405496 — REAL`
- pmagic=0x58444433="XDD3"=XFS_DIR3_DATA_MAGIC, powner=131==ino → current valid block of this dir.
- pname=[node5_f1.md5] = a REAL live peer dirent durable on the platter at aoff=2424.
- **incarn==igen** → SAME incarnation (NOT a dead-incarnation ABA, so sess40 incarn-fence is irrelevant here).
- **clean=1 dirty=0 in_ail=0** → in-core block is CLEAN (NOT our own dirty work) → the coherent re-read fix is SAFE (loses nothing).
- **dir_gen==loaded_gen (52==52)** → the node5→node7 handoff/refresh was MISSED (the lossy epoch never bumped node7's gen), so node7 served a stale CLEAN cached block whose bestfree offered the occupied slot.
- PASS runs (1,2): 0 REAL hits. FAIL run (3): exactly 1 REAL hit → loss. Perfect correlation.

### CONCLUSION (confirms [[sess27-FINAL-disambiguation-readstaleness-targeted-reread-is-the-fix]], refutes the write-side head)
The clobberer reads a STALE cached CLEAN dir data block (missing the peer's durable add) because the handoff gen-bump was missed; its bestfree offers the peer's occupied slot; use_free overwrites it. FIX = the targeted coherent re-read at the slot-pick (guard>=2), which does NOT depend on the unreliable epoch/handoff detection — it checks the PLATTER directly at the decision point. Testing guard=2 now (6 runs). If it converges to 100%, that is the fix. Build 9074441C, modargs `dir_gen_per_handoff=1 dir_modify_extent_adopt=1 dir_addname_platter_guard=2`. Cross-ref [[sess28-PROVEN-readside-staleness-targeted-platter-guard]] [[sess27-HANDOFF-head-state-and-next-step]] [[sess22-GPT-fix-design-freeslot-doublealloc-readdir799]].
