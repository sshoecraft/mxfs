<!-- sess431 RULE-5 ruling: D-0351 free image never lands because the cluster merge restores the platter over the P55C-staged free slot; fix = explicit pe… -->
# sess431 GPT ruling — FREE-publication claim (D-0351)

## Proven mechanism (s437 timelines, 56/123 P-DIALLOC-DISKLIVE)
P55C-FREE-FLUSH copies the free image into the cluster buffer at inode-NL (sanction = AG pubwrite tenure, no RELFLUSH). `mxfs_iflush_cluster_merge_dirs` protection mask = RELFLUSH | (EX && dirty_seq==ex_grant_seq) | (PR dir in AIL) → the free slot is unprotected → sess62 restore arm overlays the platter's LIVE predecessor (P239 arm=restore, P-CLMERGE restored bmode=00 dmode=040755) → P56-NL-LOGGED-DIR-SKIP masks the (now dir) slot / a file slot is rewritten live. Free never lands → same node DISKLIVE 35 s later.

## Ruling (gpt-5.6-sol)
- Do NOT infer authority from in-core state (freeob/PUBOB/mode/gen): not a coherent authorization object, not bound to the obligation epoch, cannot tell uninterrupted tenure from lost-and-reacquired.
- Mint an explicit per-slot FREE-publication CLAIM at P55C under the pubwrite token: {AG epoch, ino, slot, gen, flush_seq, buffer identity, obligation ref}; valid through merge, final mask, submission, durable completion. AG release must refuse while an obligation/claim is outstanding (the existing release gate does this via the pubob store).
- Use the SAME claim in the merge (buffer wins) and in the partial-write mask (authorized at NL) — the file-type accident that writes mode-0 slots is not an authority rule.
- Stale claim (epoch moved, buffer differs, seq rolled back): never submit the old free image; do not let the restore's write discharge the obligation (fail closed → obligation open → AG held → recovery/re-copy).
- Unexpected LIVE gen ≠ ours-1 while the obligation is open indicates tenure loss / local recycle / legacy corruption → trace + fail closed, never "older chain" by inference.
- Evidence chain to prove: obligation created → claim minted → merge kept → mask included → submitted → durable iodone → discharged → AG unlocked; assert no unlock while pending, no claim accepted after epoch change, no claimed slot overlaid/omitted.

## Landed 0.39.5 (sv C9664916D13CB2BCB3674D9)
`i_mxfs_freepub_{bp,epoch,seq,gen}`; `mxfs_freepub_claim_valid/clear` (xfs_mxfs_dlm.c after pubwrite_end); mint in xfs_iflush after the stage stamp; merge KEEP arm before the revoke `continue`; P238 rollback `cls=freepub-stale` clears PUBOB_FLUSHED; xfs_buf.c logged branch `P-FREEPUB-WRITE` authority class; clears at iodone durable / pub-skipped / abort / discharge / recycle. Probes: P-FREEPUB-CLAIM, -KEEP, -WRITE, -CLAIM-STALE, -CLAIM-CLEAR why=.
