---
name: ccloop-c7ee71c6-sess312-GPT-ruling-inode-reldefer-containment-design
description: sess312 RULE-5 design ruling: INODE-class bounded defer containment — 10 required changes incl. defer-time admission closure, WEDGED gate, no reset o…
metadata:
  type: project
---

# sess312 — GPT design ruling: INODE-class release-defer containment

Approves mirroring the ICLUS sess307 machinery onto the INODE class
(60s no-progress / 300s total → wedge: pin + WEDGE cert + P-INODE-WEDGE
+ shutdown) with these REQUIRED changes:

1. DEFER-TIME ADMISSION CONTAINMENT: at first relbar proof failure enter
   a closing state; new proof-invalidating local admissions (EX at
   minimum) divert/wait — otherwise the 300s cumulative bound is
   unsound (local churn reopens obligations forever). Without this GPT
   does NOT approve the bounds for production. Existing holders drain
   normally. Need not be -EIO; can wait like the DEMOTING divert.
2. Explicit WEDGED admission gate in ilock_begin (terminal -EIO,
   acquire ordering). Mount-shutdown checks alone are insufficient
   (wedge→shutdown visibility window; teardown has no shutdown).
3. NO episode reset on local reacquire, repeated BAST, or cause-mask
   change. Reset ONLY on proved release completing its CAS. Cause
   changes are progress evidence (badness decrease refreshes prog_j),
   never episode boundaries — oscillating causes are why the 300s
   total bound exists.
4. Keep 60s/300s once admission is contained.
5. Episode deadlines carry across ALL dwork branches — BUSY included.
   Check deadline at every re-entry; wedge from the BUSY branch too,
   else a reacquired holder parks the episode in strikes-land (~30min).
   Backoff (25ms<<tries cap 1s + jitter) owns scheduling once episode
   active; clamp delay to remaining deadline.
6. FREEZE episode state on wedge (evidence), don't clear. Reset only
   after proved completion.
7. Explicit cause mask — OBLIG_OPEN, TICKET_STALE, F4_OPEN, F4_UNKNOWN,
   FLUSH_IOERR, UNKNOWN. Zero-cause defer = invariant failure, certify.
   Fatal durable-I/O error may wedge immediately (separate cause).
8. Teardown: unproven release with retry disabled (P6G-REL-STALE-
   TEARDOWN branch) = IMMEDIATE pin-only wedge (WEDGED + inode-resource
   pin so release_all can't strip unproven bits; no shutdown). Today
   this branch lets release_all strip the slot — same latent hole ICLUS
   pin closed for class 2.
9. Serialize proved-vs-wedge atomically (i_dlm_lock); one-shot wedge;
   CAS path re-checks WEDGED before submit; pin failure = stay wedged +
   shutdown, never retry.
10. Deterministic fault outcomes at INODE sites — FORCE the failure
    (forced still-dirty / forced ticket-stale / forced proof-fail), not
    delay-only hooks. Stages 7/9/10 are generic enum; add force param.

Test matrix (min): both arms; transient→recovery+reset; persistent
cause→60s wedge; oscillating→300s wedge; admission during defer; BUSY
after entry; success racing deadline; wedge racing CAS; teardown pin;
pin failure; eviction/lifetime; repeated BAST no-reset.

Cert/counters parity: episode id, elapsed, tries, cause masks, pin
result, wedge reason (noprog/total/io/teardown); counters for episodes,
wedges by reason, diverted/rejected admissions, pin failures.

Code anchors: close_or_defer 14732, defer emit 15040, arms 18852/19007,
stranded re-arm 19211-19269, busy strikes 19717+, teardown branch 19246,
ICLUS reference impl 47359-47467, pin v5_mount.c:5403 (generic
mxfs_dlm_caw_pin_resource + make_inode_resource:4886), fault engine
40409-40476, RELSTATE enum xfs_mxfs_dlm.h:850, i_mxfs_rel_state
xfs_inode.h:637.
