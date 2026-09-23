<!-- sess431: D-0351 free-image-never-lands — 5 proven roots (merge overlay, PUB_SKIPPED leak, P55C home misclass, chain-provenance drop, platter-truth),… -->
D-0351 (FREE-PUBLISH / free-image-never-lands) — sess431 closure campaign, 2026-08-28.

## Root chain, as proven

Base defect: a node's free-inode image never lands durably on the platter; the same node
later shows a live (non-free) image at that slot 0.3-35s afterward
(P-DIALLOC-DISKLIVE). Chased across 5 distinct proven root causes in one session, each
fixed in turn on the same lap-and-measure loop
`docs/history/docs/history/docs/history/compiled-d0351-free-publish-closure.md`.

**Root 1 — merge overlay (0.39.1-0.39.4, pre-existing before this session; see
`docs/history/docs/history/compiled-sess429-430-d0351-free-publish-chain-containment.md` for that prior work).**
P55C-FREE-FLUSH copies the free image into the cluster buffer at inode-NL under AG
pubwrite tenure (no RELFLUSH). `mxfs_iflush_cluster_merge_dirs`'s protection mask
(RELFLUSH | (EX && dirty_seq==ex_grant_seq) | (PR dir in AIL)) does not cover the free
slot, so the sess62 restore arm overlays the platter's live predecessor (P239
arm=restore, P-CLMERGE restored bmode=00 dmode=040755); P56-NL-LOGGED-DIR-SKIP then
masks the now-dir slot, or a file slot gets rewritten live. Free never lands; DISKLIVE
fires ~35s later on the same node. 56/123 DISKLIVE instances attributed to this chain via
`scripts/analyze_p_diskslive_p55c.py`
`docs/history/docs/history/docs/history/compiled-d0351-free-publish-closure.md`.

GPT ruling (the design-consult rule): do not infer publication authority from in-core state (freeob/PUBOB/
mode/gen) — not coherent, not epoch-bound, can't distinguish uninterrupted tenure from
lost-and-reacquired. Mint an explicit per-slot FREE-publication CLAIM at P55C under the
pubwrite token: {AG epoch, ino, slot, gen, flush_seq, buffer identity, obligation ref},
valid through merge → final mask → submission → durable completion; AG release refuses
while a claim is outstanding. Same claim gates both the merge (buffer wins) and the
partial-write mask (authorized at NL). A stale claim (epoch moved / buffer differs / seq
rolled back) must never submit the old free image and must not let the restore's write
discharge the obligation — fail closed, hold the AG, force recovery/re-copy. An
unexpected LIVE gen ≠ ours-1 while the obligation is open means tenure loss or local
recycle — trace and fail closed, never infer "older chain"
`docs/rulings/freepub-claim.md`.

Fix landed 0.39.5 (sv C9664916): `i_mxfs_freepub_{bp,epoch,seq,gen}` +
`mxfs_freepub_claim_valid/clear`; mint in xfs_iflush after the stage stamp; merge KEEP arm
before the revoke `continue`; P238 rollback (cls=freepub-stale) clears PUBOB_FLUSHED;
xfs_buf.c logged branch gets a P-FREEPUB-WRITE authority class; clears at durable iodone /
pub-skipped / abort / discharge / recycle. Probes P-FREEPUB-CLAIM/-KEEP/-WRITE/
-CLAIM-STALE/-CLAIM-CLEAR `docs/rulings/freepub-claim.md`. s439 on
0.39.5 confirmed: claim chain clean (freepub_stale=0), restore-chain-attributed DISKLIVE
72→0 (of 72 residual, down from 123) via 0/72 in the restore-chain analysis
`docs/history/docs/history/docs/history/compiled-d0351-free-publish-closure.md`.

**Root 2 — stale PUB_SKIPPED leak (→ 0.39.6).** P235-EX-STALE-SKIP sets PUB_SKIPPED
unconditionally on a re-logged landed slot; that round's iodone `continue`s at
`if (!ili_last_fields)` (xfs_inode_item.c:1188) before PUB_SKIPPED handling, so the flag
leaks into the next (P55C) round, re-arms P187, and durable never advances. 84 leaked
claims on s439. Fix: xfs_iflush's copy-in success clears PUB_SKIPPED (next to the
CLMERGE_HIT clear) `docs/history/docs/history/docs/history/compiled-d0351-free-publish-closure.md`.

**Root 3 — P55C home misclassification (→ 0.39.6, hardened 0.39.9).** P55C
FREE-HOME/FOREIGN/FLUSH classified `dip` off the BUFFER slot, which after our own
copy-in is already our staged image — self-fooling. First fix: when
flush_seq != durable_seq, classify off a platter read
(`mxfs_dbg_disk_di_mode_coherent()`); P55C-HOME-PLATTER on divergence, -HOME-READ-FAIL →
strike + -EAGAIN `docs/history/docs/history/docs/history/compiled-d0351-free-publish-closure.md`.
GPT review (the design-consult rule) found this insufficient: flush!=durable is not a sufficient
detector — every drop path rolls flush back to durable while the buffer still holds the
staged mode-0 bytes, producing a false discharge on re-push. 0.39.9 fix: ALWAYS classify
from a raw platter read via a private bounce buffer
(`mxfs_pal_bdev_read_plain_bdev`, never the xfs buffer cache — the buffer is locked so no
write of that cluster can be in flight); invalid/failed read → DENIED + strike. Also
hardened: handle PUB_SKIPPED before the `!ili_last_fields` early exit in iodone (closes
root 2's residual race) `docs/history/gpt-review-0396-0397-directed-test-required.md`.

**Root 4 — chain provenance dropped at UNLINK discharge (→ 0.39.7).** 41/41 remaining
P55C-FREE-FOREIGN cases: the platter's live gen was created by the SAME node
(P165-AFFINE-STALE child_gen=, P383 selfcr=1) but that life's free gen never appears
fleet-wide — its free never went through P55C. Traced via test1 ino 134
(P-FREEOB-CHAIN-LIVE chain=1→2→1): tmpfile create → linkat (P82-REM →
`xfs_iunlink_remove` → `mxfs_pubob_discharge` "removed") → unlink. The discharge's
generic path called `mxfs_pubob_drop_ino`, losing chain state; the next arm() minted
chain=0; the ifree logged FREE chain=0; P55C's `!(dgen==ogen-1 || ochain)` test then
called it FOREIGN and left the node's own live image on platter, producing DISKLIVE 0.3s
later on the same node. Same mechanism on "flushed" discharges (unlink conversion landing
before its ifree) — the common board shape
`docs/history/docs/history/docs/history/compiled-d0351-free-publish-closure.md`.

Fix (0.39.7, `xfs_mxfs_dlm.c mxfs_pubob_discharge`): an UNLINK-kind discharge with
chain>0 becomes kind=CHAIN_LIVE, gen=0 (P-FREEOB-CHAIN-KEPT why=); arm() already handled
CHAIN_LIVE→UNLINK; free_pending/commit carry chain; the CHAIN_LIVE "SUPERSEDED" recycle
verdict (peer freed our life) is unchanged
`docs/history/docs/history/docs/history/compiled-d0351-free-publish-closure.md`. GPT review
confirmed correctness: chain==0 still drops; CHAIN_LIVE must never drop at eviction
(eviction doesn't end the incarnation); chain>0 is sound across AG tenure changes because
the inobt bit stays allocated to the live life; the CHAIN write binds the LAST ifree's
epoch, replaced by free_commit
`docs/history/gpt-review-0396-0397-directed-test-required.md`.

Trap hit while tracing this: cross-node timestamps are per-VM monotonic stamps, not
wall-clock-comparable directly — use realms=/realns= fields;
`scripts/analyze_p_diskslive_p55c.py` converts via a per-node median offset
`docs/history/docs/history/docs/history/compiled-d0351-free-publish-closure.md`.

## Series (DISKLIVE/FOREIGN pairs per lap)

s437 123/39 → s439 72/41 → s440 57/34 → s442 0/0
`docs/history/docs/history/docs/history/compiled-d0351-free-publish-closure.md`. s440 (0.39.6) confirmed
pub-skipped 84→0 and HOME-PLATTER=0, but the chain-provenance fix wasn't in yet
(FOREIGN 34 / DISKLIVE 57 residual)
`docs/history/docs/history/docs/history/compiled-d0351-free-publish-closure.md`. s441 (0.39.7) aborted at the
usermode formation_test gate — a pre-existing, unrelated flake, opened as new defect
D-TAUTH-FORMATION-RAMP-LEDGER-DENY-EXHAUSTS-RETRIES-EAGAIN-0352 (3/6 local fail rate);
the chain harness (`tests/sess430_containment_chain.sh`) was given a narrow gate
exception that logs "STAGE tauth gate: D-0352 OCCURRENCE" and continues only for that
exact signature, so D-0352 doesn't block D-0351 verification laps
`docs/history/docs/history/docs/history/compiled-d0351-free-publish-closure.md`.

s442 (0.39.7, sv 6116AF0D) was the first fully clean lap: DISKLIVE 0, FOREIGN 0,
XRELEASE/CHAIN-BROKEN/RECYCLE-ANOMALY 0, P237 0, CR62/CR3 0, freepub_stale 0,
HOME-PLATTER 0; 2107 claims → 2101 durable + 6 recycle; board 0 FS FAIL (one unrelated
crash_consistency FAIL at the 90s the derived-budget rule ceiling with 128/128 checks passing, recorded
against open D-401, not this defect)
`docs/history/docs/history/docs/history/compiled-d0351-free-publish-closure.md`. 0.39.8 (sv 023D54C7) added
only P-FREEOB-CHAIN-KEPT printk pacing (200 then 1/500). s443 and s444 (0.39.9, sv
81F9B85C, with the platter-truth hardening from the GPT review) repeated clean
`docs/history/docs/history/docs/history/compiled-d0351-free-publish-closure.md`
`docs/history/docs/history/docs/history/compiled-d0351-free-publish-closure.md`.

## Closure

D-0351 set FIXED AND VERIFIED, closed 2026-08-28, on 0.39.9 (sv 81F9B85CA8D93028BF09F42,
fleet-deployed). Seven proven-and-fixed roots across 0.39.1-0.39.9: chain provenance
(0.39.1, prior session), deferred-release gate (0.39.2, prior session), audit early-return
+ containment (0.39.3, prior session), FREE-publication claim vs merge restore (0.39.5),
stale PUB_SKIPPED (0.39.6), chain kept at UNLINK discharge (0.39.7), platter-truth P55C
home + iodone hardening + `mxfs.freepub_drop_once` fault-injection knob +
`tests/freepub_platter_home_inject.sh` (0.39.9, closing the directed test GPT's review
required — force buffer != media by dropping a claimed sector, observe
P55C-HOME-PLATTER, re-stage, WRITE, durable, discharge, then AG unlock)
`docs/history/gpt-review-0396-0397-directed-test-required.md`
`docs/history/docs/history/docs/history/compiled-d0351-free-publish-closure.md`. Verification: three
consecutive clean boards (s442/s443/s444) with raw-journal counters, all 4 reproducers
(ffr/fhs/dre/injector, plus fph for the directed test) PASS every lap. Full history and
the verification table: `docs/free-publish.md`. Reusable lap harness:
`tests/sess430_containment_chain.sh` (build → tauth gate with D-0352 exception → prep →
injector → ffr → fph → fhs → dre×2 → board → raw-counter sweep; wall ~25min after build).
Analysis scripts: `scripts/freepub_claim_chain.py`,
`scripts/analyze_p_diskslive_p55c.py` — `keep` is optional in the claim-chain script
since merge skips buffers with no foreign allocated slot
`docs/history/docs/history/docs/history/compiled-d0351-free-publish-closure.md`
`docs/history/docs/history/docs/history/compiled-d0351-free-publish-closure.md`.

open_defects count at session end: 69
`docs/history/docs/history/docs/history/compiled-d0351-free-publish-closure.md`.

## Open follow-ups (not closed by this campaign)

- D-401 crash_consistency: intermittently hits the 90s the derived-budget rule ceiling (76-90s observed,
  hostload 21-25) with all functional checks passing — a performance defect, still open.
- D-0352 formation_test: ~50% local fail rate; the chain-gate exception is narrow (exact
  signature match only) and does not fix the underlying flake.
- D-AGIFC-SHARED-AG-DOUBLE-VICTIM-REPLAY-DIVERGENCE-408: `tests/rman_matrix.sh` base_shared
  ×3 launched at session end to capture P-AGIFC-MISMATCH site= lines for this defect's
  next_step (reproduce); any am>0 requires reading the site= lines + agi/pagi/ibt_sum
  triple. Next-in-line after this: D-FOREIGN-REPLAY-UNGATED-IMAGES gate items 1
  (rman snapshot coverage verify), 4 (crash coverage), 5, 6 (fence snapshot race tests), 7
  (vergate mixed_build rerun) — load `docs/rulings/enforcement-default-on-policy-a-gated.md`
  and `docs/history/docs/history/compiled-recovery-manifest-rman-campaign.md` first
  `docs/history/docs/history/docs/history/compiled-d0351-free-publish-closure.md`.
