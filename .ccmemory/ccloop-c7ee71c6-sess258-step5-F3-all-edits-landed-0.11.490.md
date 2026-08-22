---
name: ccloop-c7ee71c6-sess258-step5-F3-all-edits-landed-0.11.490
description: sess258: step-5 F3 COMPLETE — all 8 edits landed+built 0.11.490 sv B8A561D0; keyed proof/tickets/tripwire telemetry-only; NOT rig-verified; next = 32…
metadata:
  type: project
---

# sess258 — step 5 (F3) implementation complete, 0.11.490

All 8 edits from the sess253 ruling landed and built clean:
VERSION 0.11.490, mxfs.ko srcversion B8A561D0E04957E337361E6
(2026-08-14 14:03Z). NOT deployed/verified on the rig yet.

What landed (all xfs/xfs_mxfs_dlm.c; substrate from sess256/257):
- `mxfs_iclus_make_durable(mp, base, cert)`: settle loop now treats
  xfs_buf_incore -EAGAIN as UNKNOWN (bounded retry → proof_failed,
  P289-ICLUS-SETTLE-UNKNOWN) instead of settled; keyed icwr proof:
  lookup no-create (NULL + icwr_untracked>0 = poisoned),
  wait_event_timeout(icwr_wq, inflight==0, 100ms) →
  P289-ICLUS-INFLIGHT-TIMEOUT; capture submit/complete gens →
  mxfs_blkdev_flush_epoch → verify inflight==0 + gens unchanged +
  dirty recheck (trylock-fail = fail); one bounce on gen movement
  (P289-ICLUS-GEN-MOVED); fills cert icwr_daddr/inflight_final/
  gen_final, ticket_status (fua=0: rc==0→REAL_FLUSH else FLUSH_FAILED;
  fua=1: PROTECTED/NO_DOMAIN), proof_failed.
- disk_release: PROVED requires !oblig_cas && !proof_failed; final
  pre-CAS keyed tripwire re-samples entry vs cert → tripwire=1 + back
  to DRAINING (counts cas_unproved); ticket_completed from status.
- relbar: mxfs_relbar_ticket_ok(ip) — fua_disable || flush_epoch >
  i_mxfs_pub_durable_fepoch (read durable → smp_rmb → stamp, pairing
  the sess257 stamp sites); fast-path PROVED gated on it; closed path
  earns one direct flush + recheck, else proof_failed + FLUSH_FAILED
  and rel_state stays DRAINING (release proceeds — telemetry only).
- relcert_finish: ticket_seq/stamp_epoch/observed_epoch; fua=0
  revalidates vs CURRENT durable_seq → REAL_FLUSH or STALE (preserves
  FLUSH_FAILED); fua=1 → PROTECTED/NO_DOMAIN.
- emit: new counters relcert_proof_failed/ticket_stale/tripwires;
  success excludes proof_failed|tripwire; P280 + TOTAL extended.
- F3 refusal reworded (proof RECORDS; step-6 deferral will BLOCK);
  F3_READY stays 0 per ruling item E.

Build trap fixed: the static forward decl at ~line 73 precedes the
xfs_mxfs_dlm.h include, so `struct mxfs_release_cert *` in it created a
prototype-scoped struct → "incompatible pointer type"/"conflicting
types". Fix = bare `struct mxfs_release_cert;` tag before the decl.

Next: deploy, ./run.sh 32 caw board (must stay green under default
fua_disable=1 — delta is only the keyed wait + recheck), check
release_cert_dump + ICWR-REGISTRY-TOTAL (proof_failed/tripwires ~0,
submits==completes), then build-order step 6 (deferred-release worker
blocking on proof_failed) → flip F1/F3 READY.
