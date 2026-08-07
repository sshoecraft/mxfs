---
name: differential-invalid-when-loser-is-rank1
description: METHOD: a loser-vs-peers probe differential is only valid if the loser is an ordinary peer. Rank1's coordinator role alone gives x20-x158 departures…
metadata:
  type: reference
tags: [method, differential, rank1, false-lead, measurement, mount-degrades]
---

# A loser-vs-peers differential is invalid when the loser is rank 1

## The trap, and I walked into it

`tests/dd_loss_differential.sh` differences per-token kernel-probe frequencies
between the node that failed and its 31 peers. That works well when the loser is
an ordinary peer — it found the P6-MIDTENURE lead that way (loser test4).

Two `dirent_durability` 240s/240s truncations then landed on **test1 = rank 1**.
The differential showed test1 wildly elevated:

    P1-AGWAIT         110-200  vs peer median 3-7   (x25-28)
    P128-INACT-DEFER  153-176  vs peer median 0     (x154-177)
    P-DIRFLUSH        615-773  vs peer median 31-33 (x18-24)
    P-BLOCK0-CONVGATE 61-107   vs peers 0           (ONLY-LOSER)
    P-IGET-ENOENT     54-90    vs peers 0           (ONLY-LOSER)
    EVICT-RING-FLAG   0        vs peer median 30-33 (did NONE of their work)

I recorded that as "the probes name the backlog." **They do not.**

## The control that killed it

`tests/rank1_straggler_probe.sh` on a **FRESH-PREP PASSING run** (117s, 32/32,
`durable_loss=0`):

    PROBE                     rank1   peer_med  peer_max   ratio
    P1-AGWAIT                    92          1         6   x46.5  above every peer
    P128-INACT-DEFER            157          0         2  x158.0  above every peer
    P-DIRFLUSH                  800         37        56   x21.1  above every peer
    P-DIRDW                     394         19        28   x19.8  above every peer
    P12-WORK                     74          6        14   x10.7  above every peer
    P-BLOCK0-CONVGATE            62          0         0   x63.0  above every peer
    P-IGET-ENOENT                40          0         0   x41.0  above every peer
    EVICT-RING-FLAG               0         23        29    x0.0
    P6-MIDTENURE-RELOAD-SKIP     44         27        28    x1.6

Compare the failing values: P128-INACT-DEFER 157 passing vs 153-176 failing;
P-DIRFLUSH 800 passing vs 615-773 failing; P1-AGWAIT 92 passing vs 110-200.
**Essentially identical.** The elevation is the coordinator role — rank 1 drives
the teardown and extra bookkeeping — and it is present on perfectly healthy runs.
It has ZERO discriminating power for the failure.

## The rule

- Loser is an ordinary peer -> loser-vs-peers is valid.
- **Loser is rank 1 -> loser-vs-peers is meaningless.** Compare rank1-failing
  against **rank1-passing** (same node, same role, different run). That is the
  only like-for-like comparison.
- Before trusting ANY differential row, ask whether the losing node differs from
  its peers in ROLE as well as outcome. Role differences of x20-x158 will swamp a
  real signal completely.

## What this does and does not invalidate

- **Invalidated**: "AG-wait + inactivation-defer backlog on the coordinator is
  the D-MOUNT-DEGRADES-WITH-USE mechanism." Unproven; those probes are role
  noise.
- **Still standing**: the 240s truncations occur only on an aged mount and only
  on rank1; a fresh prep on the same build passes at 116-124s across 11 runs.
- **Unaffected**: the P6-MIDTENURE lead for D-SILENT-MKDIR-LOSS. Its loser
  (test4) was an ordinary peer, and P6 sits at x1.6 on rank1 — the role does not
  explain it.
