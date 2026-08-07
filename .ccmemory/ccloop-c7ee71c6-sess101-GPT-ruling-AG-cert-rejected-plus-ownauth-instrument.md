---
name: ccloop-c7ee71c6-sess101-GPT-ruling-AG-cert-rejected-plus-ownauth-instrument
description: sess101 RULE-5 ruling: broad AG-class authority for inode images REJECTED (8 blockers); the answer is an AG-minted durable unpublished-child delegati…
metadata:
  type: reference
tags: [sess101, step5.3, RULE-5, D-FOREIGN-REPLAY-UNGATED-IMAGES, authority-token, P239-OWNAUTH, MEASURED]
---

# sess101 — the step-5.3 ruling, and the instrument that decides the fork

Build **0.11.435**, `srcversion CB58C97A17ED23DE0CE4753`, builds clean, **DEPLOYED to
all 32 nodes** (prep_cluster, 72 s). The rig is on it now.

## 1. The RULE-5 ruling on the sess100 question (AG tenure as the gate)

I brought sess100's numbers (13153 unpublished vs 321 installs) and asked whether the AG
tenure should gate the UNPUBLISHED_EX population. The ruling, verbatim in shape:

> Per-inode DLM tenure is **not required** for initial unpublished creation. The
> allocating AG grant **may** authorize a tightly bound initial inode *birth* operation.
> It **cannot** serve as a general certificate for that inode after the allocating tenure
> ends. For that population the durable long-lived solution is an **AG-minted unpublished-child
> authority**, not a broad AG-class token and not an authority-free exception.

Key points:

- **"Inode lies in AG g" is NOT an authority relationship.** Physical containment would let
  an AG holder overwrite any existing inode in that AG. An AG EX grant proves authority over
  allocation metadata, AG btrees/headers, and *selection* of a free inode slot — and, if the
  protocol says so, *initialization* of that exact slot. Nothing more.
- **My "capture birth_ag_epoch and require it still current" idea is necessary but NOT
  sufficient.** It does not prove the slot was allocated under that epoch, that the
  generation was not reused, that the image is the initial init rather than an arbitrary
  later update, that all modified bytes belong to this inode, or that replay stays valid
  after the epoch is released.
- **New general invariant named** (applies beyond inodes): *a grant epoch must not be made
  stale while replay-required log records depending solely on that epoch are still
  outstanding.* If AG release invalidates the epoch without draining/checkpointing records
  certified by it, that is a hole in AG tokens generally.
- **"No peer can name it" is NOT a safe uncertified class.** An inode is reachable by ino
  from another op, an NFS file handle, an open ref, an in-flight rename/link, another
  journal, or a reused ino. A replayer cannot cheaply prove namespace unreachability — it
  may need to replay the very transactions under question. It IS safe if "unpublished" is a
  **durable exclusive ownership claim** (ino+generation, owner incarnation, birth AG
  resource+epoch, claim sequence, permitted scope) minted while holding valid AG allocation
  authority — i.e. delegated authority, not absence of authority. Can be batched (no CAW
  per inode).
- **8 release blockers** for any AG-certified inode replay: no broad containment rule;
  non-ABA identity (ino+generation); exact image scope (must not reach neighbouring dinodes
  in the same cluster buffer); turnover rule (drain or transfer at AG release); publication
  ordering (pre-publication cert unusable after publish/relock/reuse); victim binding;
  later-update classification (birth authority must not authorize subsequent mutations);
  fail-closed on mixed-authority images.
- **It also refuted my sess100 headline**: `13153 vs 321` does **not** establish a 97.6%
  refusal rate. `unpublished_noted` counts *state entries*, not *images*. Many unpublished
  images were forced home by the demote pipeline and should be stale/refused anyway.

## 2. What I built as a result — P239-OWNAUTH (the deciding measurement)

Ranked next step from the ruling: one instrumentation build measuring the matrix. Landed in
`pal/linux/xfs_buf_item.c`:

- **`mxfs_buf_derive_owner()` is finally WIRED** (it had zero callers since sess96). Called
  from the two non-AG-authorized arms of the classification ladder — `mislabel` (`!auth &&
  ge`) and `unknown` (`!auth && !ge`) — which is exactly the step-5.3 population.
- **`mxfs_buf_owner_authority()`** — RCU lookup in `pag_ici_root` (never an iget, per the
  sess95 ruling; the shape is the one sess96 specified), validates ino identity +
  `XFS_IRECLAIM|XFS_IRECLAIMABLE` under `i_flags_lock`, copies out the owner's authority
  state/epoch/resource.
- **10-way outcome histogram**: noowner / badag / nopag / uncached / stale / none / unpub /
  releasing / durable / durnoep, plus a BLFT histogram restricted to the NON-durable
  outcomes (the ruling's "image relationship" axis).
- Reported as `P239-OWNAUTH` + `P239-OWNAUTH-NONDURABLE-blft` every 8192 tokens, beside the
  existing `P228-TOKCLASS`.

Honest limits written into the code comment: authority fields are read WITHOUT `i_dlm_lock`
(taking it at CIL format time inverts the lock order) so it is a sampled distribution and
must never become the gate's own test; it counts per SEGMENT; and reading the owner from
buffer memory does not prove the owner field is inside the LOGGED regions (the sess96 limit).

**What the outcome distribution decides**, per the ruling:
`durable` dominates -> per-inode certificate is the right gate, just wire it.
`unpub` dominates -> these are LATER modifications of an unpublished object, so an
AG-derived *birth* certificate cannot reach them and the unpublished-child delegation is
required. `uncached`/`stale` dominates -> capture must move to the dirty/join seam (the
sess48 ruling item (b), still owed).

## 3. sess100 item 2 — the `novalid` split, ALREADY MEASURED

Split three ways at the refusal point in `mxfs_inode_authority_install_durable_ex_locked`:
`nogres` (no result struct passed) / `notvalid` (result arrived, CAS never marked it valid) /
`noepoch` (valid but `grant_epoch == 0`). Surfaced in the debugfs file; `tests/auth_counters.sh`
updated to read them.

**Fresh 32-node mount, before any workload: judged 62, installs 12 (19%), refused 50 —
`notvalid` = 50 of 50 (100%), `nogres` = 0, `noepoch` = 0.**

So the hypothesis is settled: the acquire path DOES pass a result struct everywhere, and the
epoch is never the problem. **`caw_grant_result_fill` is declining to mark the result valid**
on the cluster-routed acquires. That is one specific function, one specific predicate — a
much smaller target than "novalid".

## 4. Prior facts confirmed by line-reading this session

- Today's foreign-replay containment is **ATOMIC-SKIP of any transaction containing a
  BUF/DQUOT/QUOTAOFF/ICREATE item** (`xfs_log_recover.c` ~2310). INODE items are applied,
  gated by `di_changecount`. So the step-5 campaign's payoff is raising the APPLY rate from
  ~0, not preventing applies.
- Live `P228-TOKCLASS` on the 0.11.434 fleet: `n=16384 ag=15251 sb=7 mislabel=1029
  noepoch=0`, `mis_blft: t4=1026 t10=3`. **t4 = `XFS_BLFT_BTREE_BUF` with `!auth` = bmbt
  (inode-owned bmap btree) blocks**, t10 = DIR_BLOCK_BUF. So the step-5.3 population is
  ~6.3% of images and is **99% bmbt**, and `XFS_BLFT_DINO_BUF` (t8) does not appear at all —
  dinode *contents* travel as inode log items, not buffer images.
  That matters: bmbt blocks are logged on extent-map changes, i.e. LATER modification, and
  the AG containing a bmbt block is the AG the *block* came from, not the AG that birthed
  the inode. Strong prior that the fork lands on the unpublished-child delegation — but
  P239-OWNAUTH must say so, not this reasoning.

## Next, in order

1. **Run the measurement.** Baseline snapshot is saved; run `./run.sh 32 caw rsync_paired`
   (14 s / 60 s budget on 0.11.434), then read `P239-OWNAUTH` from dmesg across the fleet
   (needs 8192 tokens per node to report — check that a single lap reaches it; if not, run
   two laps or lower the report modulus) and `tests/auth_counters.sh 32 <snap>` for the
   delta.
2. **Follow `notvalid` into `caw_grant_result_fill`** — find the predicate that declines to
   set `valid` on cluster-routed acquires. Single function, already localized.
3. Then take the P239 distribution back for the design decision (birth certificate vs
   unpublished-child delegation), with the 8 release blockers as the checklist.
