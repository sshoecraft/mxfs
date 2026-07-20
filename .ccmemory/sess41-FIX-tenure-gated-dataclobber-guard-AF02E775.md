---
name: sess41-FIX-tenure-gated-dataclobber-guard-AF02E775
description: sess41 dir_reuse 2/tcp: content/tenure discriminators all fail. Probing Invariant-1 (clobber mode!=EX?). 240 clobbers @daddr=120 block-0 xfsaild. bui…
metadata:
  type: project
---

## sess41 (ccloop 8ddb16a2) — dir_reuse_coherency 2/tcp = ONLY remaining 2/tcp blocker (16/17 pass)

### REFUTED this session (RULE 4 — distinct approaches, do NOT repeat)
1. Write-side content-skip ENFORCE (dataclobber=2) → CATASTROPHIC (rounds 1-6 lookup_fail=150). Cause: rm-rf+recreate REUSES dir ino#131 + daddrs → disk can hold a prior-incarnation GHOST (same owner, MORE dirents) → skip suppresses the FRESH write, keeps ghost. Content comparison can't tell ghost from live peer data. dataclobber DEFAULT now 0.
2. Evict-side content-refresh (dirrefresh=1) → INERT (0×). At modify-time DATA blocks are durable (existing !undurable branch evicts+refetches); only LEAF lingers undurable (P21S 70×). dirrefresh DEFAULT now 0.
3. Tenure discriminators ALL fail: 240 data clobbers have bufgen==dirgen==4 (dir_gen STUCK; bumps only at inode-cache-miss + CAW evict-ring, not per EX handoff) AND tenure==epoch (b_tenure_id re-stamped to current on each modify). So both read "CURRENT" — the clobber is a current-tenure flush of a stale BASE. No write/evict-time tenure token separates it.

### PROVEN facts (production dirwr=0)
- ALL 240 clobbers: daddr=120 (block-0, first data block), comm=xfsaild/sda, disk_cnt=buf_cnt+1 (each is a REAL durable -1 reduction). Durable loss = node1's FIRST-wave dirents (node1_f1..f14) dropped from block-0; later files (in other data blocks) survive → readdir=186.
- Release fence (sess97) PROVEN WORKING: P-SF-DURABLE-FAIL=0, P97-RELFENCE-WEDGE=0 — every release exits with all dir blocks durable/clean (xfs_bwrite + wait in-AIL clear). So NOT a release-flush gap.
- modify-path evict recovers TRYLOCK contention (P36-EVICT-RECOVERED=93).

### CURRENT HYPOTHESIS (testing, build 2A64E9BD, detect run bunguzsvi)
INVARIANT-1: xfsaild flushes a stale block-0 when the node does NOT hold the dir EX (released to peer, peer advanced disk). Added mode=%d to P-DATACLOBBER detector (i_dlm_mode; EX=5, NL=0, PR=3). If clobbers are mode!=5 → FIX = skip async (comm=xfsaild) dir-block writes when mode!=EX (release fence already wrote durable version under EX; late async flush is stale). This sidesteps content-comparison (no ghost) and is the Invariant-1 enforcement. NOTE: existing nl_released arm (mxfs_buf_xfsaild_skip_dir_write, mxfs_dirskip=0 default) is the NL-only version, but sess17 said it "fired 0×" — so clobbers may be mode==EX (then Invariant-1 hypothesis fails → escalate GPT-5.5 per RULE 5; consult was prepared, not yet sent).

### Builds: AF02E775→3CC51B7E→B6E72DF5(REGRESS)→A4D7996F(tenure)→2A64E9BD(+mode). Baseline B9F9326E. All enforce arms OFF by default now.
Supersedes [[sess40-CORRECTION-production-DOES-fail-bugA-real-at-dirwr0]].
