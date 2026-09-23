---
name: trap-a-verification-condition-that-a-healthy-build-cannot-produce-is-vacuous-by-construction-inject-it-at-the-verdict
description: TRAP (sess602, D-0947): the record demanded NOMAGIC>0 from churn, but a healthy carve FUA-inits and reads back every chunk, so churn can never produc…
metadata:
  type: feedback
tags: [D-0947, D-0946, dialloc, validator, injection, vacuous, harness, set-u, trap]
---

# A verification condition the healthy build cannot produce is vacuous by construction

D-0947's record demanded "the tight run must produce cerr=0 with `P947-VALIDATE-NOMAGIC` non-zero" as its closure evidence. s602b ran 8 rounds / 3200 creates on 0.84.15: cerr=0, gate fired 33 times, NOMAGIC=0 in every round. Not a failed verification — an unreachable one:

- Since sess444 every inode chunk is FUA-initialised at the carve and read back before its ICREATE record is logged (`P133-ICLUSTER-SYNCINIT`, `P948-SYNCINIT-READBACK`, xfs/libxfs/xfs_ialloc.c). No home in a fresh chunk is ever magic-less on a healthy build, and the tight churn reuses freed numbers inside existing chunks anyway.
- The original 600/600 failure (tests/evidence/sess572_create_eio) was ONE candidate, ino 95168, magic-less and picked by every create in turn (`P-DIALLOC-VALIDATE-EIO ino=95168` on every create). The 0.75.118 claim that "an un-destaged chunk's homes have no magic and the case is common" is not what the evidence shows: the one NOMAGIC hit on 0.75.118 was `n=1` after 13 rounds, and it was D-0948's foreign directory block.

What worked: inject the verdict, not the platter. Two test-only knobs (`dbg_validate_nomagic_n`, a countdown; `dbg_validate_nomagic_ino`, one number persistently) consulted by `mxfs_dialloc_validate_candidate` after a clean read; `tests/d0947_nomagic_repick.sh` drives the countdown, the persistent number (the sess572 shape, asserting the number is never handed out and becomes allocatable again once the knob clears) and the storm (200 injected, observing the progress rule). 27/27 twice on 0.84.16.

Before running a lap whose closure needs a probe count, ask whether the current build can reach the probe at all; a clean lap with the count at zero measures nothing either way (compiled-allocator-campaign-traps says the same for P946-VALIDATE-ALLOW).

Second, smaller: `tests/d0946_disklive_knob_vs_aging.sh` builds each round's remote command string in the local shell under `set -u`; a variable defined only in the sole-survivor pre-phase (`AD`) killed every plain tight lap at line 542, and the empty round line was then scored `mounted=0` and reported as "the filesystem died" (s602a). A missing round line is a harness failure and is now an ABORT that says so; names used inside a remote command must be defined for every mode.
