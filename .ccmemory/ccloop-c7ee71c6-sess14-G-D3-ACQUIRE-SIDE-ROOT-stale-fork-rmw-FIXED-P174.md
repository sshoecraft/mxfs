---
name: ccloop-c7ee71c6-sess14-G-D3-ACQUIRE-SIDE-ROOT-stale-fork-rmw-FIXED-P174
description: sess14 D3 TRUE ROOT: cached-EX fast path RMWs a fork never rebuilt across peer mods (dgen>lgen); authorized drain then publishes it. FIX v0.11.131 P1…
metadata:
  type: project
tags: [d3, root-cause, acquire-side, fixed, p174, cache-coherency, 32-node, gpt-guided]
---

# sess14-G: D3 cv loss — ACQUIRE-SIDE ROOT (the real one) + FIX v0.11.131

## How the write-side hypotheses were eliminated (RULE 4, 3 refuted predicates)
The cv loss (3-5 files erased cluster-wide per hit) looked like a rogue post-release write.
Three write-filter predicates were built, deployed and REFUTED by measurement:
1. `.124` skip every NL logged DIR slot → cc PASSED but REGRESSED: stranded a freshly
   created dir (its landing IS a post-demote write) — platter slot stayed FREE, dir
   invisible cluster-wide, creator poisoned its own inode (P34H) → permanent ESTALE.
2. `.127` gate the skip on dir-epoch supersession → epoch helper returns 0 after release
   (local resource view dropped) ⇒ skip never fired ⇒ loss returned (5 files).
3. `.128/.129` gate on i_mxfs_self_created / on the MXFS_IF_DLM_RELFLUSH publication token
   (GPT's authority design) → **decisive**: the reverting writes carry `relflush=1`, i.e.
   they ARE the sanctioned release drain publishing with the grant still held. No write-side
   filter can be correct; the image itself was already wrong.

## TRUE ROOT (measured, v0.11.130 instrumentation)
Added dgen/lgen to the publish trace. The clobbering publish:
    P56-DIRWRITE ino=44040321 mode=0 relflush=1 **dgen=8 lgen=5** write=[9 names]
i_dlm_dir_gen (peer-modification counter) was 3 generations AHEAD of
i_dlm_dir_loaded_gen (generation our fork was last rebuilt to) — proof the tenure's RMW
base never saw the peers' changes. Sequence: A holds/regains EX on the **cached-EX fast
path**, whose sess50 rule assumes "no peer could have modified while we held it cached"
and therefore SKIPS the shortform adopt (`mxfs_sf_fastpath_adopt` default 0); A adds its
name to the stale base; its release drain publishes the stale+1 image with full authority,
durably erasing every peer entry added since. Invariant violated: *an EX tenure's RMW base
must be the current platter image* (GPT RULE-5 consult, sess14-D/H).

## FIX (v0.11.131, srcver 7B1BE81C057A1A7B59609E5)
xfs_mxfs_dlm.c cached-EX fast path: also adopt when
`mxfs_dir_stalegen_adopt && ip->i_dlm_dir_gen > ip->i_dlm_dir_loaded_gen`
(marker **P174-STALEGEN-ADOPT**, param dir_stalegen_adopt default 1). The sess50
resurrection concern is explicitly excluded — it was argued from peer_mod=0
(dir_gen == loaded_gen), the case this predicate does not touch.
GPT's guidance followed: fix the ACQUIRE side, never union whole shortform images
(union trades lost-adds for resurrected-removes — the ghost-dirent bug fixed at .121).

## Verification
- cache_coherency 32/32 PASS ×3 consecutive (654 checks each) — the run immediately before
  the fix failed with 3-5 files lost, and had failed on 4 of the last 6 attempts.
- **P174 fired 110×** in one cc run: the hazard is pervasive, now corrected at the source.
- Full chain lap: cc PASS, dlm_scaling PASS (drc pace-FAIL + one transient fdw pre-assert
  remain, both known separate items).
- Write-filter skip (P56-NL-LOGGED-DIR-SKIP, .124) is RETAINED with the RELFLUSH-token
  predicate: it is now a defence-in-depth assertion, not the fix.

## Standing lesson
A publish-side filter cannot repair a poisoned base. When a stale image reaches the platter
WITH valid authority, the defect is upstream in the tenure's base — check dgen vs lgen (or
equivalent "what generation is my copy" state) before designing any write-side guard.
