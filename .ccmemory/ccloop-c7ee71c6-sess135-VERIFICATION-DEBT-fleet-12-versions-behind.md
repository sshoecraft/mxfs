---
name: ccloop-c7ee71c6-sess135-VERIFICATION-DEBT-fleet-12-versions-behind
description: sess135 KEY FINDING: fleet runs 0.11.440, tree is 0.11.452 — 12 versions of landed, undeployed, unverified code. Verification is the bottleneck, not…
metadata:
  type: project
tags: [mxfs, sess135, verification-debt, rule6, process, rig, priority]
---

# sess135 — the campaign's actual bottleneck is VERIFICATION, not design

## The measurement

    test1: cat /sys/module/mxfs/srcversion  ->  DF0E1ABC1CEA16331E2DF6C   (= 0.11.440)
    tree:  modinfo mxfs.ko                  ->  A1C4A05CB6356F02B8625F6   (= 0.11.452)

**Twelve versions of landed change have never been deployed or boarded.**
0.11.441 through 0.11.452 — the sess112-135 work: the lreq registry, the
owed-ready queue, the D1 fallback-drain deletion, the lifecycle restructure,
the PAL fail-stop/defer primitives, the D2/D3/D4/D6 state machine, the
create() unwind fix. None of it has run on the rig.

## Why this matters more than any single defect

RULE 6 closes an entry only as DISPROVED or FIXED AND VERIFIED, and
"verified" means a test that exercises the cause passes. So **every one of
those twelve versions of work is un-closable by construction until it is
deployed.** Sessions 112-134 landed code and consulted GPT; the open count
did not move, and could not have.

The ledger's own numbers show this is recent, not chronic: 39 of 68 entries
ARE dispositioned (29 FIXED AND VERIFIED / 5 DISPROVED / 5 RESOLVED), 8 of
them closed as recently as 2026-08-04. The campaign closes defects when it
verifies. It has not verified in ~20 sessions.

Prompted by the user asking, mid-session: "have you solved a single defect?"

## The rule to carry forward

**Do not land a thirteenth unverified version before boarding.** `run.sh`
deploys the built .ko itself and ASSERTS the loaded srcversion on every node,
so the rig cycle IS the deployment:

1. `./run.sh 2 caw posix_multi` — cheap smoke (gate3 budget 120s, 32s actual).
2. If green: `./run.sh 32 caw` for the board.
3. Harvest the new teardown probes, which every unmount now exercises:
   P258-QUIESCE-STUCK / -LATE, P259-DEPART-UNCLEAN, P260-CAW-CTX-LEAKED,
   P261-ESCALATE-UNDELIVERED, P262-TEARDOWN-JOIN-STUCK / -LATE, P253-OWED-STUCK.
   A 32-node board runs stop() 32 times; that is the D2/D3/D4/D6 exerciser
   that already exists, and it costs nothing extra to read.

Rig risk is bounded and recoverable: `scripts/cluster_reset.sh` handles a
wedge, and RULE 2 forbids rebooting clyde ONLY — test1..test32 may be
`virsh destroy/start`ed freely.

## Caveat carried from sess113

sess113 called 0.11.441 "no-go for the 32-node rig". That verdict was about
the sess112 FIX being inadequate (sampling aggregate counters does not
establish exclusive ownership), not about the build destroying the rig.
Sessions 114-135 have been reworking exactly that. It is not a standing
prohibition on boarding.
