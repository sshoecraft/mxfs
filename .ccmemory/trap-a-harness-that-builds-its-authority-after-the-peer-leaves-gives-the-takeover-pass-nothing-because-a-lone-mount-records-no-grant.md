---
name: trap-a-harness-that-builds-its-authority-after-the-peer-leaves-gives-the-takeover-pass-nothing-because-a-lone-mount-records-no-grant
description: TRAP (s67l→s68a, 0.89.5): depart_takeover_unmount's ghost arm let B leave THEN had A create; a lone mount takes no grant and writes no ledger record,…
metadata:
  type: feedback
---

# A harness that builds its authority after the peer leaves gives the takeover pass nothing

**Measured** s67l (0.89.4) and s68a (0.89.5), tests/depart_takeover_unmount.sh on the 2-node TCP rig.

## What happened
The ghost arm's ordering was: B unmounts, then A alone creates NFILES files, then A unmounts as the last member and remounts, expecting the remount's takeover-only pass over its predecessor's ledger pages to run for minutes so an unmount can be issued inside it. On the freshly prepared filesystem the predecessor held 10 pages (test1 journal: `P-TAUTH-TAKEOVER departed=... pages_prepared=9 cand=10 total_ms=2714`) and the harness aborted: "the pass was not seen in flight (activations=10)". The s588 laps that measured ~15k pages did so on an aged ledger whose residue supplied the pages, not on the creates.

## Why
The authority ledger records GRANTS. A lone mount modifies everything at NL with no grant and writes no record. tests/join_during_takeover.sh already said so in its own comment (s591d/s592a: cand=4 on a fresh filesystem) and creates while both nodes are members.

## The fix
Reorder: create under two members (each create takes its inode's grant, ~14 ms; 8000 creates 102 s), then B unmounts (hands its pages to A: 4511 via=frozen-msg in s68a), then A unmounts last and remounts. s68a: 300 activations 12 s after the remount and still arriving, the unmount landed inside the pass (interrupted with 179 pages remaining, 541 ms, no stuck worker), the re-form's sweep took 9332 pages at ~30 ms a page (NFILES/40+120 s undershoots that; NFILES/20+120 fits), both nodes read all 8000 files.

## The lesson
Before trusting a harness whose measurement is "a pass long enough to interrupt", derive the pass length from what the workload RECORDS, not from what it creates, and check whether an earlier PASS got its magnitude from residue (sibling trap: `trap-a-defect-whose-magnitude-is-workload-residue-stops-reproducing-and-the-lap-reads-as-a-pass`). An activation count that plateaus at a small number before the first sample is the tell: read the P-TAUTH-TAKEOVER summary's cand= for the pass under test.
