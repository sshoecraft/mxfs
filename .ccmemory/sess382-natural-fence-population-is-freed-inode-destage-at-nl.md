---
name: sess382-natural-fence-population-is-freed-inode-destage-at-nl
description: sess382 MEASURED: 41/41 natural fence-abandoned publications are freed-inode destage at NL (mode=0, gen+1, xfsaild) — cross-incarnation, so equality-…
metadata:
  type: project
tags: [mxfs, obligation, iflush, P119, measurement]
---

# sess382 — what the natural fence-abandoned publications actually are

Built a **canonical equality oracle** (`mxfs_home_equals_owed`, `xfs_inode.c`)
per the sess382 GPT ruling-2 Q2: compares gen, changecount, mode, nlink, uid,
gid, size, nblocks, extsize, flags, flags2, forkoff, format and the **LOCAL
data/attr fork bytes**, and **fails closed** on anything it cannot compare in
full (EXTENTS and BTREE forks refused outright). Wired to **telemetry only**
(`P383-HOME-VS-OWED`, knob `mxfs.home_equals_owed_probe`) so an oracle bug could
not produce a false durable-close during validation.

## Result — the equality-close design is a dead end for natural cases

Full 32-node board, 0.19.0: **29 of 29** natural fence-abandoned publications
reported `equal=0 why=gen`. Extended probe (0.19.1, dir_reuse_coherency +
dirent_durability + ag_strand_repair): **41 of 41**, one single shape:

```
P383-HOME-VS-OWED ino=12583049 equal=0 why=gen pend=4 dur=2 flush=2
  cc_home=2 iver=4 mode=00 dmode=0
  gen_incore=1295308233 gen_home=1295308232
  hmode=0100600 hnlink=0 unpub=0 selfcr=1 deadgen=0 stale_src=5
  comm=xfsaild/dm-1
```

Read it: our in-core `mode=00` — **the inode was freed here**; our gen is
**exactly one above** the platter's (the free bumped it); the platter still
holds the **prior incarnation** as a live regular file (`hmode=0100600`);
`xfsaild` is destaging the free while this node holds **no grant** (`dmode=0`),
so `P119-NONEX-FLUSH-SKIP` fences it.

**The natural fence population is FREED-INODE DESTAGE AT NL** — not the
stale-shell / behind-disk shapes the defect was opened on. These are *genuine*
owed publications (the platter really does lack our freed image), so equality is
**correctly** refused, and they resolve on their own: board green, only 6
`P382-RELDEFER-RELOAD` firings, zero wedges.

## Why this matters for the design

- Do **not** build out the Q2 equality-close: it would never fire naturally.
  Keep the oracle as telemetry and as the fail-closed gate for any future close
  path, but it is not the fix.
- `i_generation` is `get_random_u32`, so two gens **do not order** — they only
  say "different incarnation". The fields that discriminate which side is stale
  are `i_dlm_unpublished`, `i_mxfs_self_created`, `i_mxfs_dead_incarn_gen`.
  Never infer staleness from gen arithmetic (the +1 here is the free bump, an
  XFS convention, not an ordering guarantee).
- Cross-check this population against `D-CROSSNODE-OPEN-UNLINK-DATA-LOSS` and
  the `P128-INACT-DEFER` machinery before designing anything further.

## Method note

Two probes, two builds, and a measurement that **killed my own next design step**
before I spent a session building it. The first probe (`why=` naming the first
differing field) said "cross-incarnation"; the second (adding the discriminator
fields) said "freed-inode destage". Neither conclusion was reachable by reading
code — the freed-inode shape is invisible in the fence's own source.
