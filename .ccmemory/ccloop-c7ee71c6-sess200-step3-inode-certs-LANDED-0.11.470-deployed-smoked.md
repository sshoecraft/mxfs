---
name: ccloop-c7ee71c6-sess200-step3-inode-certs-LANDED-0.11.470-deployed-smoked
description: sess200: step-3 first increment LANDED+DEPLOYED as 0.11.470 (sv 4382FAEFA146D50E90DF775): per-inode class-1 release certs live at knob=0; smoke PASS.
metadata:
  type: project
---

# sess200 — build-order step 3 first increment (sess197 ruling)

## Landed: 0.11.470, srcversion 4382FAEFA146D50E90DF775
All edits in xfs/xfs_mxfs_dlm.c only (no header change, incremental build OK):
- `mxfs_relbar_close_or_defer(ip, arm, cert)` — now the COMMON per-inode
  release-proof body. Optional `struct mxfs_release_cert *` filled with
  dirty_seq/oblig at quiesce and post-drain (oblig = pend-dur clamped u32),
  `timeout=1` on WRQ-budget exhaustion, and calls
  `mxfs_relcert_count_tripwire_retry()` when pass-1's recheck bounces to
  pass-2 (previously uncalled — handoff item 2 closed).
- New static helpers right after it: `mxfs_inode_relcert_finish` (fills
  cas_attempted/cas_result/drain_ns/dirty_seq_tripwire/oblig_cas/
  inflight_cas(IFLUSHING)/ticket fields, emits) and
  `mxfs_inode_relcert_defer` (defer_kind=OBLIG, emits).
- Both wire-unlock arms in mxfs_dlm_bast_process emit class=MXFS_RELCLASS_INODE
  certs: "noanchor" (cert local `p282c` in the p6zc block; unlock rc now
  captured instead of `(void)` — cert-only, behavior unchanged) and
  "anchored" (cert in the rb_defer scope; finish after
  `p6u_rc = mxfs_v5_dlm_inode_unlock_open(...)`). Routed-ICLUS branches
  emit NO class-1 cert (class-2 iclus_disk_release cert covers those).
- Ticket semantics copied from ICLUS site: required=1,
  completed = !mxfs_fua_disable || mxfs_target_cache_protected (F2 domain).
- Observation-only; relbar proof behavior unchanged.

## Deployed + verified
- 32/caw knob=0 (no MXFS_EXTRA_MODARGS — restores shipped default after
  sess199's knob=1 rig), prep 73s, 32/32 converged.
- Smoke (test1 create 40 files shared dir, test2 read+append+sync):
  P280-RELEASE-CERT-TOTAL test1 attempts=43, test2 attempts=42,
  success=0 cas_dirty=0 cas_noticket==attempts, zero defers/timeouts/
  wedges/tripwire_retries. Exactly the ruled F2-domain shape; knob=0
  vacuity from sess199 CLOSED.

## Facts
- VERSION file does NOT reach mxfs.ko (Kbuild -D plumbing absent; modinfo
  has no version field). srcversion is the only deploy identity.
- run.sh accepts MULTIPLE test names: `./run.sh <N> <dlm> [test ...]` —
  use it to chunk the board into <10min foreground calls.

## Next
1. Full knob=0 regression board on 0.11.470 (chunk cells with per-chunk
   RULE-0 budgets from tests/suite/manifest BUDGET_S; dir_reuse pace family
   marginal — sess199 precedent).
2. Step-3 continuation: DEMOTING/DRAINING state machine; convert remaining
   per-inode epoch-end sites; then step 4 (F4 obligation registry, dir first).
3. Ledger #2: record sess199 knob=1+knob=0 board pair in its entry.
