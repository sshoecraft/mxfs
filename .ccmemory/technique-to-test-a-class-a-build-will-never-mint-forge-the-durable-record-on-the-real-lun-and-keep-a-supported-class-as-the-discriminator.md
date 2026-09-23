---
name: technique-to-test-a-class-a-build-will-never-mint-forge-the-durable-record-on-the-real-lun-and-keep-a-supported-class-as-the-discriminator
description: TECHNIQUE (s84): revoked fence classes are unreachable by running the code; forge them with recov_forge and include supported-class arms, or every re…
metadata:
  type: feedback
---

# Forge the durable record, and make one arm prove the gate can still say yes

A guard that refuses a REVOKED class is unreachable by running the software: a
build only ever mints the kinds it still supports, so no lap can produce the
input. This is general — any "refuse what an older build wrote" guard has the
same shape.

**Two routes, and they are complementary.**

1. **Inject at the durable write.** `dl_fence_cert_kind_inject` substitutes the
   kind after every constructor check, so a real fence really proves exclusion
   and the platter ends up carrying a revoked contract over a genuine outcome.
   Closest to the real failure, but it needs a kernel knob and it only reaches
   records this build's fence path can produce.
2. **Forge the sector.** `tools/recov_forge mkguard <slot> --live --stage 3
   --fence-kind K --fence-resv T --fence-prover N --desc-version V` writes a
   complete certificate into an unused heartbeat slot on the REAL LUN with the
   crc and identity binding recomputed. It reaches classes and descriptor
   versions no build will ever mint, needs no kernel change, and runs against
   the real mount path rather than a usermode reimplementation of the
   predicate. `tests/fence_kind_matrix.sh` is the harness.

**The part that is easy to get wrong: a matrix of refusals proves nothing on
its own.** A descriptor rejected for a missing field refuses exactly as loudly
as one rejected for its class, so "all eight arms refused" is equally
consistent with a gate that rejects everything. The fix is a *supported* class
as the discriminator: forge kind 17 and kind 23 — which this build accepts —
with ONE supporting field blanked (`--fence-prover 0`). Those must refuse
naming that field and must name **no** revoked class. That is a positive
measurement of the classifier passing a kind through.

**Never forge a fully valid certificate.** An accepted one authorises replaying
a journal slice that belongs to a live filesystem. Every arm must be refused by
something; the arm that proves acceptance works is a real fence on a real
victim (`tests/fence_strong_basis.sh proven`), not a forgery.

**Grade the certificate, not the sector.** Asserting the whole sector's crc is
unchanged turns a legitimate recovery-pending stamp into a failure about
relabelling. Compare the certificate fields and report the sector separately.

Measured 2026-09-20, 2-node TCP, eight arms at `fails=0`:
`tests/evidence/20260920T113047Z_fkm_s84b_retired16` and seven siblings.
