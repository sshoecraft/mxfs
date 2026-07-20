---
name: compiled-dirreuse-run6614-sess5-coldread-salvage-master-epoch-zero
description: sess5(run6614): undestaged dir-block cold-read salvage fixes cache_coherency (2/tcp 17/17); dir_reuse blocked by master dir_epoch=0 disabling gates.
metadata:
  type: project
tags: [compiled, dir_reuse, cache_coherency, coldread-salvage, dir_epoch, lost-update, run6614, sess5]
---

## sess5 (ccloop run 6614) — dir-block cold-read salvage + master dir_epoch-zero root

Two coupled results this session on the shared-LUN dir coherence path:
(1) a **breakthrough cold-read SALVAGE** fix that closed the ~50-session
`cache_coherency` shutdown blocker (2/tcp now 17/17 at tree-default force_block=1),
and (2) a **proven root** for the remaining `dir_reuse_coherency` lost-update:
the master `dir_epoch` intermittently returns 0, disabling every epoch-gated
staleness fast-path. Final handoff build **9762C6C6**; criterion NOT met,
marker NOT written.

---

### Build progression (chronological)
- **C7C10753** (probes-only) — deterministic fb1 2/tcp cache_coherency repro; captured full probe timeline. [[sess5-ccloop-MEASURED-dblalloc-birth-fires-forceblock1-2tcp]]
- **F8444712** — undestaged cold-read salvage in `xfs_da_btree.c`; cache_coherency 2/tcp @ fb1 PASS 2/2 (was deterministic 0/2). THE breakthrough. [[sess5-ccloop-FIX-undestaged-coldread-salvage-BREAKTHROUGH]]
- **AB674659** — Fix A alone (drop `!in_ail` from keep-guard bypass); DISPROVEN, still FAIL. Fix A kept as harmless complement, insufficient alone.
- **59784327** — salvage + soak dump_stack gate; full `./run.sh 2 tcp` = 17/17 at default fb1. [[sess5-ccloop-MILESTONE-2tcp-17of17-forceblock1-salvage]]
- **3EF92062** — added owned_ex-INDEPENDENT standalone salvage for the SHUTDOWN face (2/tcp still 17/17, 4/tcp 13/17). [[sess5-ccloop-CHECKPOINT-progress-and-dirreuse-two-faces]]
- **E101D113** — live 4/tcp dir_reuse failure probes; proved master dir_epoch=0 root. [[sess5-ccloop-ROOT-dirreuse-master-epoch-zero-disables-gates]]
- **AAA382D5** — GPT-5.5 design: relepoch-based stale-base evict (TESTING). [[sess5-ccloop-FIX-relepoch-evict-gpt-design]]
- **9762C6C6** — FINAL: query-max dir_epoch + kept salvage/deferred-stale/soak-gate. 2/tcp 17/17 verified 3×. [[sess5-ccloop-HANDOFF-state-fixes-and-next]] [[sess5-ccloop-REFINED-ROOT-idlmepoch-no-bump-fastpath-handoff]]

---

### FIX 1 — undestaged cold-read SALVAGE (KEEP, VERIFIED)
File `xfs_da_btree.c`, in-core-invalidated branch (~line 3302).

**Root (RULE-4 proven):** multinode dir DATA blocks are UNDESTAGED (destage only
at DLM release, P16=0). A freshly created/REUSED dir block0 whose on-disk daddr
still holds a freed prior owner's un-zeroed dir3 block (or garbage) lives only
in-core. One of the ~10 `XBF_DONE`-clearing sites (evict/reload/modify-refresh)
clears DONE on that undestaged buffer; `xfs_da_read_buf` then COLD-READS stale
disk → `xfs_dir3_block_verify` owner-mismatch/CRC → shutdown. Proven cases:
ino=132 daddr=112 read garbage owner=0x91..; ino=2097281 daddr=2093344 read
foreign owner=2097280 (block freed from 2097280, disk_nlink=0, realloc'd but
never zeroed). [[sess5-ccloop-FIX-undestaged-coldread-salvage-BREAKTHROUGH]]

**Fix:** when incore finds the dir DATA buffer with DONE cleared AND it is
undestaged (payload-LSN this-node-ahead) AND in-core header owner == this inode
AND not XBF_STALE AND b_addr live → RESTORE XBF_DONE and serve in-core content
instead of cold-reading disk. Raw DONE-clear sites don't stale the buffer, so
b_addr is intact; the in-core copy is the only authoritative one. Scoped
multinode dir only. Probe `P5-UNDEST-SALVAGE`.

**Two faces of the shutdown** the salvage addresses: original salvage sat in a
gate SKIPPED when the creating node holds EX (owned_ex=1), missing the
EX-holder cold-read of a reused block0. Build 3EF92062 added an owned_ex-
independent salvage restoring XBF_DONE on any undestaged self-owned dir DATA
block before the read (probe `P5-UNDEST-SALVAGE-EX`). [[sess5-ccloop-CHECKPOINT-progress-and-dirreuse-two-faces]]

**Underlying alloc issue (measured):** on C7C10753 fb1, `P-DBLALLOC-BIRTH
foreign=1` FIRES (refutes the sess4 "0 foreign" handoff) — test2 bnobt handed
daddr 2093344 (a FOREIGN LIVE XDB3 block owned by test1's still-live
`.cache_coherency` barrier dir ino=2097280) to a new dir ino=2097281 →
cross-node bnobt free-space DOUBLE-ALLOC between two live dirs. test2 never
freed 2097280 (gen-mismatch INACT-SKIP-STALE; ino still LIVE) yet its in-core
bnobt never saw test1's allocation → stale bnobt, coldread_discard failed to
prevent it. Low-metadata twin: test1 ino=132 block0 @ daddr=112 (~fsb 14) got
a metadata-region block. **force_block tie-in:** fb1 forces barrier dirs →block
(hands them the victim data block); fb0 keeps them shortform → cache_coherency
PASSES @ fb0. The salvage removed this force_block tension for 2 nodes (passes
at BOTH fb settings). [[sess5-ccloop-MEASURED-dblalloc-birth-fires-forceblock1-2tcp]]

### FIX 2 — soak dump_stack gate (KEEP)
`pal/linux/xfs_buf.c`: gated P-DIRSTALE / P-DIRFREE diagnostic `dump_stack()`
behind `mxfs_instr_enabled`. They emitted "Call Trace:" during normal ops,
which soak's dmesg DPAT scan (matches 'call trace') counted as errors → false
FAIL. Pure diagnostic noise; soak now PASSES. [[sess5-ccloop-MILESTONE-2tcp-17of17-forceblock1-salvage]]

### Other kept fixes (build 9762C6C6, all verified not to regress 2/tcp)
- **deferred-stale** (`b_mxfs_stale_pending`): acquire-reload locked-skip; fires 500×, marginal, no regression.
- **query-max dir_epoch** (`dlm.c:2509` returns MAX across local mirrors): marginal, harmless.
- Fix A keep-guard tweak + `P-DBLALLOC-AGF` FUA-compare probe: harmless. [[sess5-ccloop-HANDOFF-state-fixes-and-next]]

---

### PROVEN ROOT — dir_reuse_coherency lost-update = master dir_epoch returns 0
Measured on live 4/tcp failure (E101D113): readdir=300/exp=400, lookup_fail=0 =
**100 dirents durably clobbered** by node-addname stale-base RMW.
`P29-DATAWRITE CLOBBER=0` on all nodes → NOT a stale-write; it's a stale-READ
base. Probe timeline:
- `P2-EPOCHPLACE`: 314× on test1, ALL `unestablished=1` (master_ep=0), zero stale_base — placements use authoritative master epoch 0 (local valid_ep=186).
- `P44-GRANTDIREPOCH` ino=131: local lock dir_epoch = 0 / 8 / 22 (test1), 2/9/17/25/32 (test2) — LOW and sometimes 0.
- `P51-SENDGRANT` (master test1): dir_epoch_sent up to 190, sent=0 NEVER — the master COMPUTES + SENDS a correct monotonic epoch.

**Root:** `mxfs_v5_dlm_inode_dir_epoch()` (`dlm/v5_mount.c:1420` →
`mxfs_dlm_grant_dir_epoch` `dlm/dlm.c:2509`) returns the LOCAL granted lock's
`lk->dir_epoch`, which is stale/zero vs the master's sent epoch. A zero
master-epoch DISABLES every epoch-gated dir coherence guard (prior_tenure evict,
tenure_stale/epoch_stale read gate, newtenure evict all require
master_ep/cur_mep != 0) → stale-base RMW protection INERT → the clobber.
Send-side correct; the LOCAL store/query of dir_epoch is the bug: rapid
fast-path re-grants leave a stale/duplicate local mirror; advance-only store at
`dlm.c:3317` updates only the first match; the query picked the last
highest-mode mirror = often stale/0. [[sess5-ccloop-ROOT-dirreuse-master-epoch-zero-disables-gates]]

**Applied mitigation (9762C6C6):** `mxfs_dlm_grant_dir_epoch` now returns MAX
dir_epoch across ALL local granted mirrors (epoch monotonic → max = most
current). Re-enables gates whenever any mirror is nonzero. Marginal alone.

### REFINED ROOT — BOTH coherence signals fail on the storm dir's fast-path re-adoption
On 9762C6C6 the already-coded relepoch-reread at buffer-USE
(`xfs_da_btree.c:4041`, GPT Step 4, correct undestaged keep-guard) is INERT:
`P50-RELEPOCH-REREAD` fired 0× while dir_reuse still failed 2/6. Why both
cross-node-handoff signals fail for the storm dir (ino 131):
1. **Master dir_epoch propagation broken** — returns 0/stale (local mirror lags master's sent value), disables prior_tenure/tenure_stale/newtenure gates.
2. **Local `i_dlm_epoch` does NOT bump** on the storm's handoff — relepoch (stamped = i_dlm_epoch at read) is never < i_dlm_epoch at next read ⇒ relepoch-reread never fires ⇒ the reliable-local signal ALSO can't detect the handoff.

**Conclusion:** the storm dir hands the inode-EX grant to a peer and back via a
FAST-PATH cached-grant RE-ADOPTION that (a) skips acquire-reload (which would
unconditionally stale dir blocks), (b) does NOT bump `ip->i_dlm_epoch`, (c) does
NOT refresh the local lock's dir_epoch. Node RMW's a stale cached base a peer
superseded → 100/400 dirents clobbered. [[sess5-ccloop-REFINED-ROOT-idlmepoch-no-bump-fastpath-handoff]]

### The acquire-reload locked-skip GAP (pinpointed)
`mxfs_dlm_reload_inode` acquire-side (`xfs_mxfs_dlm.c` ~13310-13408): on fresh
inode-EX acquire the reload walks ALL dir extents and UNCONDITIONALLY stales
cached dir blocks (`xfs_buf_stale` + clear XBF_DONE, gen/epoch-independent,
correct) — BUT uses `xfs_buf_trylock`; a LOCKED block (in-flight xfsaild
writeback of this node's own prior-tenure stale copy) is SKIPPED
(`n_locked_h18++`, P-H18-INSTR locked_skip=1 observed). The surviving stale
block is then RMW'd by the next addname → peer's 100 dirents clobbered. sess37:
blocking `xfs_buf_lock` here DEADLOCKS (lock inversion); bounded-retry+msleep
REGRESSED. Read-path (`xfs_da_read_buf`) fixes CAN'T reach it: addname holds
dir EX (owned_ex=1) so read-time revalidation is skipped, and the epoch signal
is laundered / `xfs_trans_read_buf` txn-cache-hit bypasses the gate. Staleness
must die at ACQUIRE (reload) or WRITE-completion, not read. [[sess5-ccloop-dirreuse-lostupdate-acquire-reload-locked-skip-gap]]

---

### GPT-5.5 roadmap (RULE-5 consult, for next session)
**Core: gate dir stale-base correctness on the RELIABLE LOCAL `ip->i_dlm_epoch` /
`b_mxfs_relepoch`, NOT the broken master dir_epoch.** A cached dir buffer is a
stale RMW base iff `b_mxfs_relepoch < ip->i_dlm_epoch` (released/lost the dir
grant since the block was last read coherently; Inv-1 drained our work at
release). Immune to the DLM propagation bug; same signal sess50 write-side
reflush-skip trusts. i_dlm_epoch bumps on grant-loss/release (8 sites, incl.
`xfs_mxfs_dlm.c:9454`). Two prerequisites learned by REGRESSION:
1. **Do NOT relepoch-evict at the EVICT site** (build AAA382D5 mxfs_dir_evict_data_blocks ~4646): regressed to 3/8. The modify-evict already force-evicts clean/destaged blocks; the ONLY blocks it keeps are undestaged-in-AIL (this-node CURRENT work), and relepoch (stamp lags after modify) false-flagged those → evicting LOST our dirents. REVERTED.
2. **FIRST fix the `b_mxfs_relepoch` STAMP reliability** (GPT Step 3): stamp `b_mxfs_relepoch = i_dlm_epoch` on every local MODIFY under EX (`xfs_dir2_data_log_entry`), not just on read (currently only at `xfs_da_btree.c:4009/4075` + `dlm.c:22456`). Then relepoch < i_dlm_epoch reliably means "not touched this tenure".
3. **THEN enforce at READ/addname site** (Step 4/5), preserving the undestaged keep-guard: force coherent re-read of a stale DESTAGED block before the addname free-slot search; must cover `xfs_trans_read_buf` txn-held path and run even under owned_ex. Add a last-chance guard in `xfs_dir2_node_addname` before the bestfree scan; if any placement buffer (data/leaf/free) is stale → restart addname.
4. **Secondary — fix DLM propagation:** canonical `res->dir_epoch`, refresh ALL local mirrors + fast-path cached-grant re-adopt paths (not first-match-break); query returns res->dir_epoch not a scanned mirror. Init i_dlm_epoch to 1 not 0; bump on VOLUNTARY release too. Acquire-purge is a perf optimization, NOT the correctness backstop.

Analogous working pattern to mirror: the AG cached-grant reclaim at
`xfs_mxfs_dlm.c:18889` which DOES bump meta_gen + coldread-discard on
re-adoption. [[sess5-ccloop-FIX-relepoch-evict-gpt-design]] [[sess5-ccloop-REFINED-ROOT-idlmepoch-no-bump-fastpath-handoff]]

---

### Column status at handoff (tree default force_block=1, build 9762C6C6)
- **1/tcp**: unrun (expect tooling residuals: online_resize/dkms_install/fault_io_error — orthogonal to DLM).
- **2/tcp = 17/17 ✓ SOLID (verified 3×)** — the ~50-session cache_coherency deterministic-shutdown blocker FIXED; also fixes sess67 force_block=1 regression (passes at BOTH fb settings).
- **4/tcp = 4/17-ish**: cache_coherency 4/4 ✓. Blocker = dir_reuse_coherency ~70% flaky (readdir-undercount lost-update) + its shutdown face CASCADES to fault_netpartition / fence_during_write / tcp_dlm_scaling.
- **8/tcp**: unrun.
- Fast repro: `scripts/drc_reliability.sh 4 8`. [[sess5-ccloop-MILESTONE-2tcp-17of17-forceblock1-salvage]] [[sess5-ccloop-HANDOFF-state-fixes-and-next]]

### REFUTED this session (don't repeat)
relepoch-EVICT (3/8, evicts current work); relepoch-REREAD alone (inert 0×, 4/6);
broad owned_ex read-salvage that KEPT undestaged buffers (2/6, over-fires on
shared readers); query-max dir_epoch alone (~4/6); dir_tenure_evict +
dir_tenure_stale_bypass (4/5); force_coherent + tenure_evict (3/6); deferred-
stale alone (6/8); Fix A alone (still FAIL — buffer arrives at read with DONE
already 0, keep-guard never runs). [[sess5-ccloop-dirreuse-lostupdate-acquire-reload-locked-skip-gap]] [[sess5-ccloop-HANDOFF-state-fixes-and-next]]
