---
name: AAA-ccloop46ef-sess3-END-build-9C813539-next-steps
description: sess3 END: floor=0 on FF5E7827 = PASS 32/32 (fixes safe; A/B confirmed on current build). Build 9C813539 (cold-iget probe) BUILT NOT RUN. Read AAA-se…
metadata:
  type: project
---

# sess3 END — immediate next actions for sess4

READ FIRST: AAA-ccloop46ef-sess3-STATE-corruption-chain-traced-and-3-fixes (the full evidence chain + cornered mechanism).

## Final sess3 result: floor A/B CONFIRMED on current build
- **floor=0 on FF5E7827 (all 3 sess3 fixes): cache_coherency@32 = PASS 32/32** (run 20260710T055755Z). The fixes did NOT regress the passing config.
- floor=1 on the same build: 0/32 (runs 051505Z/052155Z/053633Z/054904Z — victims die renaming: P14 hole / i!=1 → dirty trans_cancel → shutdown → EIO).
- So the tenure floor's mixed-era composition is THE remaining blocker for @32; everything else this session was real-but-not-decisive hygiene.

## Build 9C813539 (v0.10.8) BUILT, NOT deployed/run — the discriminator run
Adds: (1) P14-DABUF-HOLE prints `iget_age_ms` + `iversion` — tiny age at hole = cold-iget-adopts-lagging-home PROVEN; (2) P-DIRDW reason=SURGICAL-fua (pal/linux/xfs_buf.c ~7075) completes the write history (resolves the chg-649-vs-max-610 gap); (3) P-HOLE-DISK btree_decode_skip debug (why PLATTER-SCAN was silent).

## Next session sequence
1. Run floor=1 (MXFS_EXTRA_MODARGS="caw_fair_handoff=1") on 9C813539; read victims' P14 iget_age_ms:
   - tiny (<2000ms) → cold-iget mechanism CONFIRMED → root fix: grant-ordered reload at first DLM grant after iget (don't trust iget-time home read), AND/OR purge all owner dir/bmbt buffers when the dir inode is evicted (extend mxfs_dlm_evict owner-scan) so a cold re-iget has no newer stale structure to mix with.
   - large → refuted → probe grant-without-drain (P15-REL-ABORT strands / caw_fair_handoff): log slot gen/seq vs home di_changecount at post_release=1 reloads.
2. Fix, re-run floor=1 until 32/32 ×2.
3. Then the ladder per AAA-ccloop46ef-sess2-END (trio incl. crash_consistency@32 — the floor exists FOR it, so floor must stay on and be made coherent; then dir_reuse@16/@32; then full 1/2/4/8/16/32).

## Watchouts (burned this session)
- Window ALL kernlog greps by run start (dmesg spans runs on non-cycled nodes — 3 misdiagnoses).
- Kill stale ccloop predecessor claude sessions at start (infra-ccloop-leaves-stale-sessions-alive-KILL-AT-START); run.sh flocks /tmp/mxfs_run.lock now.
- chk_mxfs from a node (umount first) = cheap platter truth (~60s). This session: platter consistent at rest.
- Runs: `MXFS_DEV=/dev/mapper/mpatha MXFS_EXTRA_MODARGS="caw_fair_handoff=1" timeout 1400 ./run.sh 32 caw cache_coherency` (background + poll until '  PASS|  FAIL|ABORT').
