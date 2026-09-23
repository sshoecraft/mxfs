---
name: technique-before-demanding-a-durable-predicate-inventory-what-each-guard-protects-and-whether-it-outlives-a-quiesce
description: TECHNIQUE (sess616, D-0956 DISPROVED): a consult's hazard 'ever_multi is per-mount, residue is not' was answered by reading all 16 consumers — each p…
metadata:
  type: feedback
tags: [sole-survivor, predicate, design, D-0956, consult, harness]
---

# Before demanding a durable predicate, inventory what each guard protects and whether it outlives a quiesce

**Context (sess616, D-0956 on 2/tcp, 0.85.4).** A design consult (sess574) named a
hazard: `ever_multi` (the flag behind `mxfs_v5_dlm_sole_survivor()` and
`mxfs_v5_dlm_never_multi()`) is per-mount "while residue is not", so a lone
remount after two writers turns every guard off. It was filed as a critical
integrity defect asking for a durable volume-lifetime fact (disklock slot
table, envelope flag) that must fail closed.

## What settled it

The question a guard needs answered is not "has this volume ever had another
writer" but "does state from another writer's epoch exist that THIS mount has
not reconciled". Reading all 16 consumers (7 sole-survivor, 9 never-multi):
every one protects in-core state of the current mount (pending dir reloads,
dentries, cached cluster passengers, phantom EX on recycled shells, unpublished
NL-logged inodes, cache-miss grants) or a departed peer's free that has not
landed yet, or is a diagnostic. None survives a clean unmount by every node plus
mount-time replay of a dead slice. The one consumer with a durable consequence
(deleting a fully-free inode chunk) had already been made unconditional on a
clustered volume, and that was verified across a lone remount by the d0949
across-mount arm (three laps, chunkfree=0, sole_probe=0).

What protects a lone mount's later peer is the conversion barrier at
admission (join-time flush/publication of NL-logged state), which is
membership-independent and identical for a never-clustered volume's first join.

Measured: `tests/d0952_sole_create_rejoin_coherency.sh` arm `lone` (both write,
both unmount, one mounts alone with P-SOLE-SURVIVOR=0 windowed to a mark written
AFTER the lone mount — the peer's departure had already made the previous mount
a survivor — creates/recycles/links/symlinks/renames without grants, peer joins,
both directions read back, cold chk_mxfs): s616b, s616c CLEAN.

## The lesson

- A consult's hazard is a hypothesis about a CLASS. Before designing a durable
  fact (on-disk format, hard to reverse), enumerate the class's consumers and
  ask of each: what state does it protect, and can that state exist after the
  quiesce the hazard describes? If none can, the predicate's lifetime is right
  and the hazard is disproved by inventory plus one measured lap of the exact
  scenario.
- The harness arm for "no memory of a peer" must window its survivor-note
  check to a mark written after the remount, or it fails its own precondition
  on the previous mount's note.
- A harness verdict that compares a directory listing count against NFILES
  breaks the day a later phase adds links/symlinks/subdirs; count the pattern,
  not the listing (s616a/b scored INCOHERENT on clean reads).

## Related
- `trap-closing-a-defect-on-one-call-site-leaves-the-class-open-368-to-5`
- `trap-a-design-consults-hazard-ranking-is-hypotheses-not-findings-measure-before-redesigning`
- `docs/rulings/sole-survivor-predicate-class.md`
