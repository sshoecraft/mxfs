---
name: ccloop-c7ee71c6-sess351-GPT-ruling-sb-counter-clean-skip-design
description: sess351 RULE-5 ruling for #94 idle-slice SB refusal: narrow counter-only clean-skip (masked compare vs effective SB, whitelist icount/ifree/fdblocks)…
metadata:
  type: project
---

# sess351 RULE-5 ruling — D-IDLE-SLICE-WSKIP-REFUSAL-AG-QUARANTINE-0130 fix shape

Full text in sess351 transcript (task ki00uxoru). Ruling: BOTH producer- and
replay-side; immediate mitigation = narrow replay-side accounting carve-out.

Governing principle: a skipped foreign txn is refusal-grade ONLY if skipping it
can omit NON-RECONSTRUCTIBLE state. Lazy SB counters are reconstructible from
AGF/AGI; growfs/feature/UUID/geometry/quota SB changes are NOT.

## Immediate (pre-exact-gate) clean-skip classifier — ALL must hold
1. txn structurally valid + committed;
2. EVERY item is a recognized primary-SB buffer image (exact blkno/len, no
   DQUOT/QUOTAOFF/ICREATE/unknown/secondary-SB/other buffers, valid framing);
3. every image has syntactically valid v3 token CLASS_SB, expected resource
   (UNPROVEN acceptable for this legacy path since nothing is applied);
   genuinely untagged/malformed remain hard refusals;
4. decoded image differs from EFFECTIVE SB state at that replay point ONLY in
   whitelist: sb_icount, sb_ifree, sb_fdblocks (+frextents only if rebuilt;
   checksum/LSN handled as derived, NOT semantic). Non-counter mismatch =>
   fail closed (existing refusal). Compare decoded structures in txn order,
   not raw bytes / sampled disk. False refusal acceptable; false clean-skip not.
5. recovery marked NEEDS_SB_COUNTER_REBUILD (durable, BEFORE accepting skip).

Growfs safety: an already-home growfs image passes the masked compare and is
harmless to skip; a not-yet-home one fails the compare and stays refused.

## Skip-and-rebuild, never apply
Never apply foreign counter images (stale vs cluster aggregate). Rebuild from
per-AG metadata under the recovery/allocation barrier, install where nodes
consume them / epoch refresh, persist, clear marker, publish success, THEN
unfreeze slot+grants. "Recompute at next mount" alone is insufficient for a
live cluster. Rebuild failure => quarantine names the AGs the REBUILD
implicates, not auto-AG0.

## Producer-side final
New authenticated SB_COUNTER_ONLY subtype (or dedicated counter-maintenance
log item) emitted only by the lazy-counter path; capture-seam purity (no
cohabit with non-counter SB dirties, no unrelated items). WRITE_AUTH=7 scoped
to counter-maintenance recognition ONLY — never authority for arbitrary SB
changes. Exact-gate ladder: CLASS_SB+verified counter-only -> CLEAN_SKIP+
rebuild; other CLASS_SB -> terminal refusal.

## Accounting split (audit while in there)
untagged_skips conflates 6 populations. Split: hard_refused (txn),
missing_token / invalid_token / authority_refused / class_refused (images),
clean_skipped_sb_counters (txn+images). TERMINAL PREDICATE = hard_refused>0
ONLY. Quarantine mask derives only from hard-refused effects. Mixed txns never
downgraded (txn-atomic classification). Per-replay counter reset. Shared pure
classifier helper used by blanket path, shadow evaluator, and future gate — no
second parser. Reserve "untagged" wording strictly for missing token.

## Prohibited failure modes
growfs silently skipped; stale foreign counters applied; success published
before rebuild; crash losing rebuild obligation (write-ahead marker); mixed txn
partial exemption; WRITE_AUTH as blanket SB authority; compare racing writers;
routine counters still quarantining AG0.
