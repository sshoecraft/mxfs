---
name: sess48-progress-ownerscan-flush-cuts-loss-residual-release-drain
description: sess48(ccloop): 8/tcp dir_reuse — owner_scan=1+grant_evict=1 kills P13-COLLIDE multi-loss; +target_flush=1 cuts residual but single-dirent loss persi…
metadata:
  type: project
---

## sess48 (ccloop 4cb2d0a2) — major progress on 8/tcp dir_reuse_coherency

### Reframed the failure (build B887B7E8, keeper 05BC5765 + P48 instrument)
The criterion test is `dir_reuse_coherency` over TCP (drc scripts). Current keeper
05BC5765 FAILS ~50-100% at 8 nodes. Two distinct failure modes proven this session:
1. **P13-COLLIDE multi-loss** (readdir=793, free-slot double-alloc, several entries).
2. **Residual single-dirent loss** (readdir=799/800, all nodes agree, LOOKUP_ENOENT
   REREAD_MISS). Usually a `.md5` sidecar (2nd create wave, large leaf-format dir),
   sometimes a data file. ~2/24 rounds, later rounds (17,19), often node6's own files.

### RULED OUT (RULE 4, instrumented)
- **Double-grant / split-brain REFUTED**: P-DOUBLEGRANT (dg_shadow) fires but is a
  FALSE POSITIVE — MX-DOUBLEGRANT (chain-based, dlm.c:601) = 0 on ALL nodes; P48-DG-CHAIN
  dump shows the master held a SINGLE GRANTED EX holder at the warning instant (prior
  owner absent from chain = stale shadow, not a live 2nd holder). The residual single-loss
  occurs with P-DOUBLEGRANT=0. NOT a DLM serialization bug.
- **Dirty stale-base survivor in owner-evict REFUTED**: P48-OWNEREVICT-DIRTYSKIP fires
  160-280×/node but ALL samples are `done=0` (!XBF_DONE = not-yet-read, benign skip),
  NOT dirty survivors.

### THE FIX SO FAR (module params, currently DEFAULT-OFF in keeper)
- `dir_owner_scan=1` (xfs_mxfs_dlm.c:316, default 0): grant_gen-gated owner-evict of ALL
  cached owned dir blocks on a CONFIRMED cross-node handoff (slow-path acquire, ~15084).
  ELIMINATES P13-COLLIDE multi-loss (10→~1).
- `dir_grant_evict=1` (default 0): grant_gen modify-path evict (sess61 plan, fully plumbed
  now — i_dlm_cached_grant_gen set @14346/15110, b_mxfs_grant_gen stamped in xfs_da_btree.c).
- `dir_modify_target_flush=1` (default 0): reader SYNCHRONIZE-CACHE before dir read. Cuts
  residual single-loss frequency (16 rounds PASSED 8/8; 24 rounds still lost 2).

### REMAINING (residual single-loss, the 130-session core)
node6's OWN committed add is durably reverted on the shared store → the acquiring peer's
cold-read base LACKED it. With EX serialized + owner_scan evict + target_flush coherent
read, the only explanation: node6's RELEASE did not make that specific dir DATA block
durable before the peer was granted EX (release-drain coverage gap on a large multi-block
dir), OR peer granted before drain completed. NEXT: verify the release-side dir flush
FORCE-COMPLETES (xfs_bwrite+WAIT, retire BLI) EVERY dir data block of a large dir (GPT-5.5
consult #1, [[sess47-GPT-consult-leaf-coherence-invariant-and-design]]), not just block0/
extent-map blocks. Repro: `tests/drc_dirtyskip.sh "<modargs>" <rounds>` (reboot+run+correlate).

### RULE 0 caveat
~16s/round (owner_scan full per-AG rhashtable walk per handoff is expensive). Functional
PASS first, then optimize. Build B887B7E8 carries P48 instrumentation (harmless).
</body>
