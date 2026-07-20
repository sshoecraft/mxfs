---
name: AAA-ccloop46ef-sess4-PLATTER-TORN-PROVEN-laundering-hunt
description: sess4 MID2: PLATTER-TORN PROVEN (DISK_MAPS_WANT=0 + refs_into_holes=2, raw FUA reads). bmbt child flaps eras cross-node. Laundering probes P67/P68 in…
metadata:
  type: project
---

# sess4 part 2 — writer-side PLATTER tear PROVEN; stale-base-RMW laundering hunt

## Probe saga resolved
- P-HOLE-DISK btree branch was silent since sess3 because `mp->m_bsize` is FSB-in-BASIC-BLOCKS (=8) not bytes: every raw read asked len=8 → -EINVAL from the (len&511) check. Fixed to `mp->m_sb.sb_blocksize` (7 sites in mxfs_dir_hole_disk_probe) + FUA READ(16) fallback (plain submit_bio_wait EINVALs on this stack anyway — fallback works).

## THE PROOF (run 072239Z, build 1A48257A, ino=12583044 rename dir, daddr=23025584 = its bmbt child)
- DISK_MAPS_WANT=0 for want_bno 19/20/21/23/2 — the RAW platter dinode+bmbt LACKS those extents while the RAW platter LEAF references them: PLATTER-SCAN refs_ok=642 refs_into_holes=2 → **PLATTER-TORN, WRITER-side**. Readers exonerated (P14 iversions MARCH with the chain 662→1264 — every fresh grantee sees the tear at its own era).
- The bmbt child's write movie (P66-LEAFWRITE/P63-LEAFWR + raw reads): content flaps eras — test17 grows nr=23→25 (:46), then test9's RAW read at :47 returns nr=23 lsn=…659 (a LATER-lsn LOGGED write with OLDER content landed between!), test9 re-grows 23→25; :58 test32 writes nr=30 LOGGED (lsn=683) against a 33/34-era cluster then re-grows 30→35. Rename-phase mv-writers republish (lsn=0, per-op FUA) whatever era they adopted.
- Mechanism: **stale-base RMW laundering** — a tenure's first modify of a bmbt child it never re-read this tenure RMWs prior-tenure content; xfs_trans_log_buf→mxfs_dir_bmbt_track then re-stamps b_tenure_id=current → the sess66 gate passes it forever after (gate is content-blind; P61-FUA-SKIP=0 all runs). The manufacture site: mxfs_dir_evict_bmbt_blocks at reload keeps dirty/in-AIL/pinned/undestaged children (by design), so a stale base can survive into a new tenure.
- 45-reap P15H storm fixed earlier in sess4 (threshold 4→280 samples ≈7s; ACQUIRE_WAIT backoff makes ≤6s unconsumed grants legit) — reaps now 0; and grant_meta no-wipe hardening (store/prebump/release_mark won't claim a foreign mid-release bucket) + GRANTMETA 4096→32768 + P6ZC CAW no-anchor release-if-no-tenure (first cut SKIPPED and leaked bits — 213 re-BAST loops; now releases when now_gen==0, defers when live).
- Failure shape evolved: run 065143Z = 3 shutdown victims (in-chain, no dark branch); run 071224Z/072239Z = mass P14 storms + wedge/timeout, few/no shutdowns. Corruption family same (torn platter pair), enablers being peeled.

## Build A0D676737E37D6CCF62D837 (v0.10.12, RUNNING at write time)
1. **P67-STALE-BASE-RMW** (mxfs_dir_bmbt_track): fires when re-stamping a bmbt child whose old stamp != current tenure while dirty/in-AIL — the exact laundering moment (fresh-read bases are excluded because the sess3 read-stamp already made them current).
2. **P67-BMBT-EVICT-SKIP now always-on capped** (was instr-gated) — names kept stale bases at reload (dirty/in_ail/pin/delwri/undestaged only).
3. **Vacuous-durable bail closed** (mxfs_dir_data_durable): BTREE+need_iread now consults the map-independent owner scans (bmbt_scan + data_owner_scan) instead of returning true; P42 print ungated from ino<=256.

## Next steps
- Read P67-STALE-BASE-RMW / P67-BMBT-EVICT-SKIP / P42-VACUOUS-DURABLE from the running run (20260710T073xxx). If laundering proven at the RMW site: fix = at first-modify-per-tenure of a bmbt child with old stamp, FORCE re-read of platter before RMW (or stale the prior-tenure dirty child at reload — xfs_buf_stale semantics — so iread cold-fetches; delicate vs AIL). If P68/evict-skip shows the keeper path: decide keep-vs-stale at reload by superseded-ness (fresh grant ⇒ prior-tenure dirt is superseded BY DEFINITION unless undestaged-this-node-committed... which release-drain should have landed; the vacuous bail was one way out, now closed).
- Runs: `MXFS_DEV=/dev/mapper/mpatha MXFS_EXTRA_MODARGS="caw_fair_handoff=1" timeout 1400 ./run.sh 32 caw cache_coherency` background+poll. ALWAYS window kernlogs to the run's start time; `prep OK ... build <srcv>` confirms deploy.
- After green ×2: trio (crash_consistency@32 floor ON), dir_reuse@16/@32, then `./run.sh N caw` N=1,2,4,8,16,32 ladder → only then the criteria marker.
