---
name: sess11run-DECISIVE-dirent-absent-at-durable-signal-entry-handoff-during-create
description: sess11(ccloop) DECISIVE: lost dirent committed (rval=0) but ABSENT from in-core at durable_signal ENTRY (PRELOGF=0, before log_force, same-thread ILO…
metadata:
  type: project
---

## sess11 (ccloop) DECISIVE — the durable dirent loss revert happens DURING the create transaction, not later

### Probe: PRELOGF (build E5DFBB14, KEEP — lightweight, clean 55s repro)
`mxfs_dir_dump_block_names(dp,"PRELOGF")` called at mxfs_dlm_dir_durable_signal ENTRY (xfs_mxfs_dlm.c, BEFORE xfs_log_force) — dumps every cached DATA block's in-core names. Gated dirwr/instr + ino<=256. (The earlier per-addname call site in xfs_dir2.c was O(n^2)/perturbing and was REMOVED.) Helper mxfs_dir_dump_block_names exported in xfs_mxfs_dlm.c ~1247.

### DECISIVE EVIDENCE (lost=node1_f34.md5, creator=test1, round 1, clean repro)
test1 dmesg timeline (single thread comm=bash, ILOCK_EXCL):
- 24.314 P127-DIRMISS name=node1_f34.md5 size=8192 gen=4 dlm_mode=3(PR) — pre-create lookup.
- 24.643654 P-CRNAME add=[node1_f34.md5] cino=1943 fmt=2.
- 24.644003 P-CRNAME-DONE rval=0 — ADD SUCCEEDED.
- 24.644028 P-DSIG ino=131 gen=5 flush=1 — durable_signal runs for THIS create.
- 24.644035 P11-POSTADD PRELOGF daddr=120 names=[. .. node1_f1 node1_f2 ...] (off0).
- 24.644042 P11-POSTADD PRELOGF daddr=2095136 names=[node4_f22.md node4_f23.md ...] (off1).
- node1_f34.md5 appears in ZERO PRELOGF / P-RELFLUSH / P11-FLUSH-CLEANSKIP lines clusterwide (grep full lines, not truncated).

### CONCLUSIONS (narrows the root massively; partly REFUTES the GPT concurrent-evict theory)
1. The committed dirent is ABSENT from in-core just 32us after rval=0, at durable_signal ENTRY, BEFORE xfs_log_force — so the revert is NOT in the log_force/flush window and NOT a later subsequent-create evict. It is reverted essentially AT/INSIDE the create transaction.
2. Dir gen bumps 4 (pre-create lookup) -> 5 (this create's durable_signal) = a DLM HANDOFF / peer-modify happened DURING this single create. So the create's PR->EX path (lookup at mode=3 PR, then upgrade to EX to add) spans a contended handoff. The EX-(re)acquire does P62-RELOAD + P106-MR-EVICT (cold-reads the peer image). HYPOTHESIS: the reacquire-reload/evict that is part of the create's EX acquisition lands AFTER the in-core dirent insertion (or the addname re-reads/rebalances onto a peer's cold image) and REVERTS the just-added dirent. The dir was size=8192 (2 data blocks off0=daddr120 node1-data, off1=daddr2095136 node4-md5) — node1_f34.md5 ended up in neither.
3. This is single-threaded within the create under ILOCK_EXCL — so it's NOT a concurrent peer-BAST evict (GPT's leading guess). It's the create's OWN EX-acquisition reload/evict interplay with addname, under a mid-create handoff.

### NEXT (RULE 4): instrument the create's EX-acquire vs addname ordering
Add probes to capture, for ONE create: (a) when the create acquires/upgrades EX (P106-EXGRANT/ACQ-SLOW) and does P62-RELOAD/P106-MR-EVICT, vs (b) when xfs_dir_createname's addname modifies the data block, vs (c) PRELOGF. If a RELOAD/EVICT timestamp falls BETWEEN addname and PRELOGF -> the create-internal reload reverts. Likely culprits: xfs_create calls mxfs_dlm_dir_modify_refresh at xfs_inode.c:1323/3388 — verify it runs BEFORE or AFTER xfs_dir_createname; if the dir EX is upgraded (PR->EX) INSIDE createname (xfs_da split path acquires?), a reload there reverts. Also check whether the addname's leaf/data split re-reads blocks that get cold-filled from the peer image mid-transaction. FIX likely: ensure no reload/evict/cold-read of dir DATA blocks occurs after the first in-core dirent modification within a create transaction (treat the transaction's touched dir buffers as pinned vs reload for the duration), OR re-apply the dirent after any mid-create reload.

### Tree: E5DFBB14 = clean baseline + inert FIX3 + P11 probes (P11-FLUSH-UNCACHED/CLEANSKIP, PRELOGF, mxfs_dir_dump_block_names) — ALL dirwr/instr-gated, default-inert, buildable. Cluster test1-4 (grub log_buf_len=16M). Repro: `bash tests/tcp/drc4_capture.sh 24` (dirwr=2, ~55s, reliable). Criterion NOT met. See [[sess11run-HANDOFF-evict-fix-insufficient-revert-under-ilock-next-probe]] [[sess11run-ROOT-committed-dirent-reverted-by-evict-before-publish-GPT-fix]].
