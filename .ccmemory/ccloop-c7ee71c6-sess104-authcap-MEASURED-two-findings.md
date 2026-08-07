---
name: ccloop-c7ee71c6-sess104-authcap-MEASURED-two-findings
description: sess104: 0.11.436 DEPLOYED + P240 MEASURED — capture plumbing PROVEN sound (nocap=0, noblft=0), no RULE-0 regression, and 2 new producer defects foun…
metadata:
  type: reference
tags: [mxfs, foreign-replay, authority, step5.3, measured, rig]
---

# sess104 — 0.11.436 deployed, P240 read, two new defects

srcversion `17AC8BF7EEB583CC1A36405` on all 32 nodes (prep 72s). The sess103
landing is now MEASURED. Ruling consulted this session:
`ccloop-c7ee71c6-sess104-GPT-ruling-release-hook-and-install-retry` (below).

## The capture plumbing is PROVEN SOUND

    win=112640 relog=250162 mismatch=0 noblft=0 blftchg=655 nocap=0

- **nocap=0** — no dirty path bypasses `xfs_trans_dirty_buf`. The seam is complete.
- **noblft=0** — the design's ONE unproven assumption (that
  `xfs_trans_buf_set_type` always precedes the first dirty) is now proven on
  112640 windows. It does.
- **mismatch=0** — no one-buffer-two-authorities case in this window.

## No RULE 0 regression (the flagged risk did not materialise)

The re-log verify runs a perag_get + RCU radix lookup per re-log; it ran
250162 times and the wall did not move.

| test | baseline | 0.11.436 | budget |
|---|---|---|---|
| rsync_paired | 16s | 14s | 60s |
| cache_coherency | 23s | 23s | 60s |
| dir_reuse_coherency | 103s | 106s (hostload 29.5 vs 22.2) | 120s |
| dirent_durability | 64s | 64s | 240s |

All 4 PASS. The per-mount authority-change sequence counter named in sess103
as the standby fix is NOT needed.

## The decisive cross-tab

220947 captured images: durable 212125 (96.01%), none 8346 (3.78%),
noowner 476 (0.22%), all other outcomes 0.

    outcome   captured  held>=PW    pct
    durable     212125    212125  100.00%   expected
    none          8346      8346  100.00%   RECORDER is broken, NOT unauthorized
    noowner        476         0    0.00%   VACUOUS — see below

**Every NONE was dirtied while the node held a WRITING mode.** So MXFS is not
modifying inodes it lacks authority for; the authority RECORD is incomplete.
That is the good branch of the ruling's discriminator.

BLFT decomposition is EXACT, and splits the population into two causes:
- `none` 8346 == dir_block 7423 + dir_data 539 + dir_leaf1 384 — directory data
- `noowner` 476 == dino 476 — inode-cluster buffers (the ICLUS/#6 territory)

**test1 alone carries 8170 of the 8346 NONE**; every other node has 0 or 8.
Do NOT read that as node-specific yet — GPT: raw image counts are
workload-weighted, one missed transition on one hot directory can generate
thousands of images. Group by owning inode before concluding.

### Trap fixed in the harness

`noowner`'s 0% is VACUOUS, not evidence of unauthorized writes.
`mxfs_buf_owner_authority` sets `*dlm_mode = 0` up front (xfs_buf_item.c:518)
and only writes the real mode at the `i_flags_lock` section that decides the
switch (:557); NOOWNER never calls the function at all (:610). Every arm that
returns before the switch — noowner/badag/nopag/uncached/stale — reports mode 0
BY CONSTRUCTION. `tests/ownauth_counters.sh` now labels those `n/a (vacuous)`
and parses the P240 line (that was sess103's owed step 3).

## FINDING A — the intended release hook is DEAD (new defect)

`mxfs_inode_authority_begin_release_locked` (xfs_mxfs_dlm.c:915) has **ZERO
callers tree-wide**; the `__maybe_unused` on it is the tell. Live counters:
`revoke=2486 backstop=2486 release_begin=0` — 100% of relinquishments go
through the diagnostic backstop in `mxfs_dlmtr_rec`, and MXFS_AUTH_RELEASING
is unreachable.

The backstop fires on `om > ip->i_dlm_mode`, i.e. AFTER the mode is lowered.
Its own comment states the ordering that makes this wrong: release-begin must
be "before the slot is marked releasing, before any unlock/handoff is sent,
before a peer can begin acquiring, and before any routing change. All of those
precede the i_dlm_mode = NL cleanup."

So between "peer may begin acquiring" and "mode lowered → backstop revokes",
`i_mxfs_auth_state` is still DURABLE_EX with a live epoch — a buffer dirtied
in that window is stamped for a tenure already being given up. **This is the
sess102 unsoundness reintroduced from the release side.**

GPT ruled: treat as a real defect. `i_dlm_mode` is a LOCAL summary, not the
distributed release linearization point, and memory ordering on its store
cannot repair ordering against a peer-visible disk update.

## FINDING B — the refusal counter conflates two opposite meanings

test1: `installs 2040, refusals 2863, notvalid 2863`, every other refusal
bucket 0, `no_snapshot 0`, `install_pct 41`.

But `gres->valid` is set in exactly one place (dlm_caw.c:990):

    if ((held == EX || held == PW) && s->ex_grant_epoch != 0) valid = 1; else valid = 0;

So `notvalid` conflates **(a)** held was not a writing mode — benign, a read
grant — with **(b)** held WAS EX/PW but `ex_grant_epoch == 0`, the
tombstone/epoch-restart case, which is a real gap. The counter cannot tell
them apart, so `notvalid=2863` currently proves nothing.

Also: the downstream `shared` bucket is **structurally unreachable** —
`!gres->valid` returns early at :968 before the `mode != EX/PW` test at :982.
Its 0 is not a measurement.

## GPT ruling — what to build next (in order)

1. **Split the refusal at snapshot construction**, where `held` and
   `ex_grant_epoch` are one coherent snapshot. Prefer a tagged status enum
   over another boolean (`MXFS_GAUTH_WRITE_EPOCH / _NONWRITE_MODE /
   _WRITE_ZERO_EPOCH`). Use ONE helper `mxfs_mode_can_write()` everywhere —
   do not mix `>= PW` with exact `EX || PW`.
2. **`i_mxfs_auth_line` is NOT the right probe** — it records the last
   SUCCESSFUL transition, and a failed install does not transition, so it
   would only report where NONE was established (the backstop). This would
   have been a wasted cycle. Record the **last install ATTEMPT** instead:
   reason + line + a monotonic grant/publication sequence, on the inode.
3. Leading hypothesis for the NONE population: **install is attempted during a
   read→write conversion BEFORE the durable write epoch is visible, returns
   notvalid, and nothing retries after epoch publication** — while a prior
   backstop revoke has already left the inode at NONE. Discriminate with a
   rate-limited trace at the first `NONE && write-mode` dirty per inode,
   capturing the contemporaneous DLM slot snapshot (held mode, ex_grant_epoch,
   releasing/routing state) next to the inode's authority state.
4. Correct hook discipline for FINDING A — do NOT enumerate release functions
   (that is why the backstop exists). Rule: *every operation that can make the
   current durable write epoch unavailable to new local mutations, or make
   relinquishment externally observable, must pass through one centralized
   release-publication primitive* which requires state RELEASING/non-durable
   before publication. Order: close local mutation gate → drain in-flight
   protected mutations → set RELEASING under the authority serialization →
   only THEN publish externally → lower i_dlm_mode last. Backstop stays, as a
   diagnostic that warns on late revoke.
   **Hooking too EARLY causes the opposite bug**: an already-authorized
   in-flight mutation dirties after the clear and gets stamped NONE.

## State

0.11.436 deployed and measured. No source edits pending; the only file changed
this session is `tests/ownauth_counters.sh` (P240 parsing + the vacuous-arm
label fix), which is complete.
