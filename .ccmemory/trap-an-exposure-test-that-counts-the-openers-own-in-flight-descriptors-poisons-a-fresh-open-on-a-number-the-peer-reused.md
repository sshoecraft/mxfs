---
name: trap-an-exposure-test-that-counts-the-openers-own-in-flight-descriptors-poisons-a-fresh-open-on-a-number-the-peer-reused
description: TRAP (D-0979, s65b): the 0.89.0 "exposed shell's incarnation is immutable" reload test read i_mxfs_open_n, which the open increments BEFORE its prote…
metadata:
  type: feedback
tags: [open-unlink, incarnation, reload, D-0979, tcp]
---

# The open's own descriptors counted as exposure of the old incarnation

## What bit
0.89.0's containment for a lost open-holder mark: if the coherency reload finds the platter naming another incarnation (new generation) while the shell has descriptors or mappings, poison the shell (every op -ESTALE) instead of adopting. The predicate was `i_mxfs_open_n > 0 || mapping_mapped`.

But xfs_file_open increments `i_mxfs_open_n` BEFORE `mxfs_dlm_open_protect` (the C3 contract: a release racing the open must publish the mark), and the reload runs UNDER that protecting acquire. So a node that still caches a shell for a number the peer freed and reused (at NL, no descriptors, the ordinary case after an rm on one node and a create on another) opens the new file, the reload sees `opens=2` — the open's own two `exec` fds — with a generation mismatch, and poisons: a valid, freshly opened file reads -ESTALE (s65b arm C, `tests/evidence/20260919T052148Z_d0977/b_dmesg_armc.txt`: P-RECYCLE-GATE adopt=0 then P977-RELOAD-EXPOSED-MISMATCH opens=2 mapped=0).

Nothing else in the lap could see it: arms A/B (the registry) passed, and the harness's arm C only noticed because its victim happened to land on the arm-B number B had just cached. Before 0.89.0 the reload adopted the new incarnation, so this was a regression the same change introduced.

## The lesson
- "Exposed" and "must be protected by the mark" are different predicates on the same counter. The mark must cover an open in flight (else a release races it and the peer frees under the fd); the poison must NOT count it (it has not been handed an incarnation yet — the reload under its own acquire is what hands it one). Two counters: `i_mxfs_open_n` (all) and `i_mxfs_open_inflight` (inside the acquire), raised in-flight-first so a reader that sees the count sees the mark; `mxfs_inode_exposed()` = usable descriptors or mappings.
- A containment rule keyed on "has descriptors" needs to ask WHICH incarnation those descriptors were opened on. When the only in-core shell per number is shared across incarnations, an open that arrives after the reuse is a new-incarnation user by definition.
- The recycle gate's "adopt only a strictly NEWER generation" (signed compare) is false for a number the PEER re-allocated on a cache miss: v5 gives it `get_random_u32()`. The +1 ordering only holds for the local free's gen++ of the same lineage. It kept the old forks in s65b (adopt=0) and left the reload to sort it out; not the cause here, but the assumption is wrong and is recorded on D-0979's next step.
