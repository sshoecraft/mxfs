---
name: caw-dir_reuse-FINAL-verify-cost-necessary-optimistic-caw-only-helps-create
description: dir_reuse FINAL analysis (code-confirmed, corrects prior optimistic-CAW over-claim): verify phase (dominant ~79s) = read_slot+CAW-add-PR+FUA on OCCUP…
metadata:
  type: project
---

## dir_reuse perf — FINAL cluster-independent conclusion (ccloop 0d6e174d sess2, code-confirmed)

Completes + CORRECTS [[caw-dir_reuse-GFS2-compare-cost-is-CAW-disk-transport-latency-not-model]] (which
over-claimed optimistic-CAW as a general win). Analysis is now complete for what's determinable without host.

### Code-confirmed facts:
- CAW acquire = find_slot→read_slot (1 FUA round-trip) + mxfs_pal_bdev_compare_and_write (1 round-trip). A
  SHARED/PR read-lock ADDS a holders_pr bit via the CAW (dlm_caw.c:189 holders_for_mode PR) — it is NOT a
  read-only check. On MISCOMPARE (sense 0x0E) the CAW returns -EAGAIN and the caller RE-READS the slot
  fresh (pal/linux/kern.c:2844,3242,3272) — no current value is returned.
- ⇒ Optimistic-CAW (skip read_slot, guess state, CAW) only wins on a CLEANLY-EMPTY slot: the CREATE phase
  (fresh inode alloc → empty slot → guess empty → 1 round-trip). It does NOT help the VERIFY phase (biggest,
  ~79s): those 1600 acquires target OCCUPIED peer-inode slots (holders/tombstones) → optimistic CAW
  miscompares → re-read → back to 2 round-trips. So verify = read_slot + CAW-add-PR + FUA-inode-read = ~3
  round-trips/inode, LARGELY NECESSARY.

### THEREFORE (honest, code-grounded):
- dir_reuse's DOMINANT cost (verify) is largely irreducible under the current coherence model — it's the
  price of per-inode PR coherence over the disk-CAW transport (all clustered FS use this model; mxfs pays
  it in disk round-trips vs GFS2/OCFS2 network-DLM messages). This is BUDGET-LEGITIMATE per
  TIMEOUT_BUDGETS.md's "record healthy PASS wall" method.
- CREATE phase: optimistic-CAW (empty-slot fast path) is a real, bounded win to try (1→saves the read_slot).
- VERIFY phase: the ONLY reduction is a coherence-MODEL change — an "optimistic READ" that does read_slot
  (confirm no peer holds EX) then FUA-reads the inode WITHOUT adding a PR bit (skip the CAW), relying on the
  read to confirm EX-free. Saves 1 round-trip/inode (~⅓ of verify). RISK: weaker read isolation — a peer
  taking EX right after the check races (during dir_reuse verify there are NO concurrent writers = barrier
  passed, so it'd be safe there, but the model can't assume that globally). Needs careful design + host
  validation; do NOT ship blind.

### NEXT SESSION (host) decision tree — updated + FINAL:
1. Run dir_reuse@16/32 to COMPLETION → confirm CORRECTNESS (0 loss) + record true healthy wall.
2. Try optimistic-CAW on CREATE (bounded, low-risk) → re-measure create phase.
3. If still over budget (verify dominates): EITHER accept budget = measured healthy wall (defensible —
   necessary coherence I/O, GFS2/OCFS2-model-inherent, no native equiv) OR carefully prototype the
   optimistic-READ (risky) behind a param + validate coherence. Prefer the budget-correction; it's honest.
4. Only then, if doubt remains, RULE-5 Fable consult (reference sources GFS2+OCFS2 already read).
