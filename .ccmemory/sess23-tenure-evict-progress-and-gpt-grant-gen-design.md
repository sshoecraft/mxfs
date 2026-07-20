---
name: sess23-tenure-evict-progress-and-gpt-grant-gen-design
description: sess23(ccloop): build 0EA92470 default-OFF param dir_tenure_evict (modify-only epoch evict + GPT 9.1 release undestaged-clear) REDUCES dir_reuse 8/tc…
metadata:
  type: project
---

## sess23 (ccloop) — dir_reuse readdir=799 progress + GPT-5.5 grant-gen design

Keeper still D589FA5F-equivalent. NEW build **0EA92470** adds a **default-OFF** param `dir_tenure_evict` (keeper inert when unset). CRITERIA NOT MET.

### Fresh reproduction facts (build D589FA5F, instr=0, representative)
- dir_reuse 8/tcp fails DETERMINISTICALLY+DURABLY: r14→`node6_f1.md5`, r24→`node5_f1.md5`, identical across clean reboots, ALL 8 nodes agree (durable on LUN, survives drop_caches). Victim is always `node<X>_f1.md5` (first md5 sidecar). 145 checks, 143 pass.
- **P17-CLOBBER-DROP** (pal/linux/xfs_buf.c:3137, count-based, gated dirwr/instr) confirms dir DATA blocks destaged with FEWER live dirents than the same daddr held (stale-base RMW). NOTE: P17's per-daddr max table keys on (daddr,owner-ino) which are REUSED across rounds → cross-round FALSE POSITIVES; not reliable alone.
- The EX-owner RMW read in xfs_da_read_buf is gated `!owned_ex` → the read-time invalidation is SKIPPED for the modify/RMW path. The EX-owner's RMW base is refreshed ONLY by mxfs_dir_evict_data_blocks (via mxfs_dlm_dir_modify_refresh at op-start), whose keep-guard preserves in-AIL-undestaged blocks.

### What dir_tenure_evict=1 does (build 0EA92470)
1. MODIFY-EVICT epoch override in mxfs_dir_evict_data_blocks (~line 2846): identical condition to the existing P16-PRIORTENURE-EVICT (`b_mxfs_dir_epoch < i_dlm_dir_valid_epoch` + clean/!dirty/!pin/!delwri/DONE → undurable=false) but gated on `dir_tenure_evict` so it runs WITHOUT the read-path epoch_stale. Probe `P23-TENURE-EVICT`.
2. RELEASE-side GPT-9.1 fix in mxfs_dir_flush_data_blocks (~line 1631): after `xfs_bwrite` proves a dir block durable, `dbp->b_mxfs_written_seq = dbp->b_mxfs_logged_seq` (authoritatively clear undestaged bookkeeping so the keep-guard stops preserving drained blocks).

### RESULTS (each a clean 8-node reboot)
- dir_evict_prior_tenure=1 (BOTH read+modify epoch sites): r20 loss then r21-24 got=0 = **SHUTDOWN cascade** (refuted again on this build).
- dir_tenure_evict=1 (modify-evict only): **NO shutdown**, P23 fired 20×; losses VARIABLE: once r7 (1 entry); once r3+r16 (r16 lost 17 contiguous node6 md5 = whole-block clobber).
- dir_tenure_evict=1 + GPT-9.1 release-clear (build 0EA92470): **NO shutdown**, only r10 lost `node7_f29.md5` (single entry). Best result yet but still 1 residual.

### KEY NEW CONCLUSIONS
- **The read-path epoch_stale (xfs_da_btree.c:3333-3401, clears XBF_DONE on in-AIL buffers during PR reads) is the SHUTDOWN source of dir_evict_prior_tenure — NOT the modify-evict.** The modify-evict epoch override is SAFE (runs under our own EX hold). This SPLIT is the actionable finding.
- **i_mxfs_ex_grant_seq is 0 for dirs** (egseq=0 in 96% of P68-EVDECIDE) — cannot be used as the dir tenure counter. The maintained dir tenure counter is i_dlm_dir_valid_epoch (master-authoritative, level-triggered, set in P-FASTEX-EPOCH at xfs_mxfs_dlm.c:11800).
- **b_tenure_id is reused for AG-meta (sess123) AND bmbt — stamping it on dir DATA buffers caused a shutdown cascade** (daddr reuse → AG-meta tenure logic misreads it). Do NOT reuse b_tenure_id for dir blocks; use a dir-specific field (b_mxfs_dir_epoch).
- The residual single-entry loss = a block whose b_mxfs_dir_epoch does NOT lag valid_epoch (epoch under-fires for that block) = the read-restamp race (xfs_da_btree.c:3157-3162) / GPT §5 "EX granted before peer's release-drain is durable on the LUN".

### NEXT (GPT-5.5 design, see [[sess23-gpt5.5-grant-generation-coherency-design]])
The robust fix is a MASTER-authoritative per-EX-grant generation, stamped at the RELEASE DRAIN FENCE (durability-synchronized, not modify/read — avoids the epoch's false-positives), compared at re-acquire: evict any dir block whose release-gen predates the current grant (foreign EX since → must refresh) EVEN IF in-AIL-undestaged (Inv1 → nothing un-drained survives release). Needs the DLM master to (a) return current grant-gen + "foreign-EX-since-last-seen" synchronously in the grant reply, and (b) NOT grant the next EX until the previous owner's drain landed on the LUN (close the grant-before-durable window). Try: enlarge the modify-evict to use the master epoch (mxfs_v5_dlm_inode_dir_epoch) but ONLY if b_mxfs_dir_epoch is ALSO stamped from the master epoch (consistent source), to catch the under-firing block without false-positiving current work.
