---
name: AAA-ccloop46ef-sess3-STATE-corruption-chain-traced-and-3-fixes
description: sess3: victim family = renames die EFSCORRUPTED (P14 hole/i!=1)→dirty trans_cancel→shutdown→EIO. 3 hygiene fixes in FF5E7827. Platter CONSISTENT at r…
metadata:
  type: project
---

# ccloop46ef sess3 — corruption chain fully traced; mechanism cornered to reader-side mixed-era composition

## THE PROVEN CHAIN (every step evidence-cited)
cache_coherency@32 (floor=1 default, caw_fair_handoff=1, fua_disable=1 default, build lineage 6CFAB18E→FF5E7827):
1. 1-4 VICTIM nodes/run die in the rename phase of tests/suite/cache_coherency.sh on the rename_visibility dir (a fresh mkfs each run: ino 4194436/135/52953221/41943172/10485893 across runs).
2. Death = `mv` hits **P14-DABUF-HOLE** (leaf/free references dablk N; in-core map lacks N) or **`i != 1` in xfs_bmap_del_extent_real** (shrink via stale FREE) → EFSCORRUPTED → **xfs_trans_cancel DIRTY → "Corruption of in-memory data (0x8) … Shutting down filesystem"** → per-mount EIO (the sess2 "EIO-dead victims"; ICD -EIO×1500 = downstream of shutdown, `shutdown=1` proven by MIDLOOP probe).
3. The "silent" shutdown was NEVER silent on the nodes — artifact collection greps used `journalctl -k` (rotates ~85s under probe volume). **run.sh now collects `dmesg -T` first** (fixed).
4. Failure reasons "rv content got=(empty) / new exists fail / old gone fail" on healthy nodes = DERIVATIVE of victims' 20 renames never happening (victims EIO mid-phase). Victims report all-640 fails because every stat EIOs (`test ! -e` passes on EIO!).

## RULED OUT / FIXED THIS SESSION (keep all — hygiene, in build FF5E7827 v0.10.7)
- **bmbt FUA-write gate bypass (REAL bug, fixed)**: sess63 routed ALL bmbt writes through mxfs_buf_write_fua at xfs_buf_submit tail, RETURNING BEFORE xfs_buf_submit_bio where the sess66 tenure gate lives → unlogged (tenure=0 lsn=0) stale leaf re-publishes landed freely (96 landed vs 145 fallback-skips, run 045621Z; P66-LEAFWRITE nr flapping 17→16→17 from many nodes/sec). FIX: gate now runs before the FUA write (P61-FUA-SKIP-BMBT) + **read-stamp**: xfs_bmbt_read_verify calls mxfs_dir_bmbt_track (fresh-read image = cluster-current, re-publishable) — without the read-stamp the bare gate STARVED the platter leaf (890 holes run 051505Z).
- **Never-adopt-older guard** (mxfs_dlm_reload_inode, next to P-RELOAD-IDENTICAL): same-gen disk image with di_changecount < in-core i_version → keep fork (reload_identical mechanism). Correct hygiene; fired 0× in failing runs (victims' in-core was already stale/evicted).
- **Dinode write stream verified SOUND**: P-DIRDW (all cluster-write paths except the surgical per-inode FUA block ~pal/linux/xfs_buf.c:7060 — NOT yet instrumented) shows chg monotonic (max 1264, only clock-skew shallow inversions). Partial-iwrite dir-slot protection works.
- **P62-DUALREAD**: buffered imap read == raw bdev read ALWAYS (98-330 samples/run) → no cache-split/multipath incoherence; the LUN itself serves old-but-consistent snapshots mid-tenure (chg=649 at :39 while writers were ~700+; **home-daddr lag is mid-tenure NORMAL** — destage at release).
- **Platter consistent at rest**: chk_mxfs after failing run 054904Z = dir btrees/leaf/free ALL VERIFIED; only 2 nlink=0 leftover file inodes (victim shutdown litter). NOT a durable-torn-platter bug.
- Sabotage: sess1+sess2 claude processes were ALIVE post-relay launching rival runs (killed; see infra-ccloop-leaves-stale-sessions-alive memory; run.sh flock added).

## THE CORNERED REMAINING MECHANISM (next session: verify then fix)
Failure-time P-HOLE-DISK: raw home dinode == in-core (nx=20, gen equal) with holes at 44-48 — while the walker's LEAF content references 44-48. Platter self-consistent at rest ⇒ the walker composed **an OLDER map with NEWER structure blocks**. The only composition that fits all data:
- Dir INODE evicted from icache (tenure-floor evict ring) mid-run; dir-block BUFFERS survive (separate cache).
- Cold re-iget reads home dinode = **lagging era E1** (mid-peer-tenure lag is legal); no in-core history → refuse-older guard can't see it; P62 "disk==incore" (fresh iget adopted it).
- First op walks structure: cached-or-freshly-read leaf = era E2>E1 → P14 hole → dirty-cancel → shutdown.
KEY QUESTION: why does the GRANT-driven read see a lagging home? Either (a) cold-iget dinode read happens BEFORE/without DLM grant ordering, or (b) a grant lands without the previous holder's drain completing (P15-REL-ABORT partial-drain strands, P15H-STRANDED-RELEASE, caw_fair_handoff effects). 
**NEXT PROBE**: at grant-driven reload (post_release=1) and at cold-iget of multinode dirs, log grant metadata (slot gen/seq from P141 machinery) vs home di_changecount; and instrument the surgical per-inode FUA write block (pal/linux/xfs_buf.c ~7060) with P-DIRDW so the write history is complete. Then: if cold-iget-before-grant is the hole, fix = do the dinode read AFTER the first DLM grant (or reload-on-first-grant unconditionally, forward-only).
- P-HOLE-DISK BTREE PLATTER-SCAN block added sess3 (xfs_mxfs_dlm.c ~14100) DIDN'T PRINT (bug in it or condition failed: bb_level!=1/numrecs!=1/dmxr; debug it — prints raw_bmbt + PLATTER-SCAN verdict when working).

## A/B facts (all this session, clean field)
floor=1: 0/32 every run (296/890/506/824 P14s — noisy, 3-4 victims/run). floor=0 (sess2): effectively PASS. fua_disable=1 is DEFAULT (sess6 flip — reads via coherent SCST cache).

## Ladder state
Nothing green yet this session; do NOT write the criteria marker. After victim-death root-fixed: re-run cache_coherency@32 ×2, then trio, then dir_reuse@16/@32, then full 1/2/4/8/16/32 ladder per AAA-ccloop46ef-sess2-END plan.

## Infra
- run.sh: flock /tmp/mxfs_run.lock (kill holder if stuck); dmesg-first kernlog collection; PARALLEL prep power-cycles.
- ALWAYS window kernlog analysis by run start (nodes not power-cycled keep prior runs' lines — burned this session 3×).
- Build FF5E7827 = v0.10.7 deployed on all 32.
