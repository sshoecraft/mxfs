---
name: sess29-GPT-design-tenure-local-poison-purge-at-NL
description: sess29 GPT-5.5 architectural design for dir_reuse 2/tcp: tenure-local dir buffers via epoch + POISON pin-only stale bufs + purge-at-NL + acquire-gate…
metadata:
  type: project
---

## sess29 (ccloop 8ddb16a2) — GPT-5.5 (RULE 5) design to fix dir_reuse_coherency 2/tcp. Implement next session.

### Why consulted: merge class DEAD
The union-merge (mxfs_dir_merge_peer_into_tp, dir_merge=1) FIXES the data face (readdir 187→200) but causes peer PR-acquire 120s TIMEOUT → rc=-110 shutdown (in-EX-hold work delays BAST handling). Confirmed both per-create AND once-per-tenure variants timeout (sess18+sess29). **Any non-trivial work while holding EX risks the peer-acquire timeout.** So the fix must NOT extend the EX hold.

### GPT design = (D) epoch-driven tenure-local invalidation + post-release pin QUARANTINE
Core invariant: **a dir DATA/leaf buffer must NEVER survive from one DLM tenure into a later tenure if a peer could have modified the dir between.** The expensive part (waiting for a pin to drain) happens at **NL (after demote, before next acquire)** — NOT during EX hold → no peer timeout. NEVER clear XBF_DONE on a pinned buffer (corruption, sess64).

Five pieces (much machinery already exists in tree):
1. **Dir content EPOCH** (cluster-shared, e.g. DLM LVB or reuse i_dlm_dir_gen + incarn): bump on EX release AFTER the durable drain. Peer sees newer epoch ⇒ cold-read LUN returns peer's committed image (LIO plain-bio is coherent).
2. **Release-side buffer triage** (extend mxfs_dir_stale_data_blocks @ xfs_mxfs_dlm.c:3005):
   - clean+unpinned (`!pinned !dirty !in_ail !delwri !write_inflight`, DONE) → `xfs_buf_stale()` NOW (drop cache+delwri).
   - dirty/in_ail/delwri → NOT durable yet → keep draining (must finish before demote).
   - **pin-ONLY clean** (`pinned !dirty !in_ail !delwri DONE`) → DO NOT stale (pin owns buffer lifetime). Mark `MXBF_TENURE_POISONED` + queue post-release purge + set purge_pending. Then DEMOTE (don't wait — peer not blocked). This replaces today's P99-STALE-SKIP "leave it usable".
3. **Post-release purge worker @ NL**: `wait_event(!ispinned)` then revalidate + `xfs_buf_stale()` + clear poison; purge_pending=false. Does NOT block peer (we're at NL). (Replaces the in-release bounded log_force loop and the acquire-side bounded 50-iter pin wait @3302 that GIVES UP → leaves stale base.)
4. **Acquire gate** (mxfs_dlm_ilock_begin, BEFORE DLM request): `wait_event(!purge_pending)`. After grant, if epoch/gen changed: stale old clean buffers; if an unsafe pinned/dirty old-epoch buf is found → drop lock to NL, purge, retry (`-EAGAIN`). NO full-dir read in grant path (that was the merge's timeout).
5. **Buffer-lookup enforcement** (xfs_da_read_buf + modify path): a dir buf is usable for RMW only if tag `(ino, i_generation, dir_epoch)` matches AND not poisoned; else if clean/unpinned → stale+cold-read, if pinned-stale → `-EAGAIN` (drop to NL, purge, retry). Never RMW a mismatched/poisoned buf. (ABA: "daddr equality is NOT identity; identity = (daddr,ino,gen,epoch)". Existing b_mxfs_dir_incarn = the gen part.)
6. **xfsaild guard** (chokepoint mxfs_buf_xfsaild_skip_dir_write): a `MXBF_TENURE_POISONED` buf must NEVER be written (return XFS_ITEM_LOCKED/defer); if it's dirty/in_ail when poisoned → shutdown (shouldn't happen). Keep P29-DATAWRITE detector as a debug assert (epoch/poison mismatch → shutdown), NOT the primary fix.

GPT REJECTED: (A naive) stale pin-only at grant (pin owns lifetime — unsafe); (B) forbid all xfsaild writes of held dir bufs (pins log tail, perf); (C) write-side semantic guard (can't soundly distinguish stale-revert from legit-remove). Use C only as a detector.

### Existing machinery to reuse/modify
- mxfs_dir_stale_data_blocks (3005, release stale loop) — add poison branch for pin-only.
- mxfs_dir_drain_evict_data_blocks (3168, acquire drain; 50-iter pin wait @3302 GIVES UP → the bug) — replace give-up with poison+purge-at-NL.
- modify_refresh (2396) uses clean-only mxfs_dir_evict_data_blocks — must honor poison/epoch.
- b_mxfs_dir_incarn / i_dlm_dir_gen / evicted_gen/incarn — the epoch/identity stamps.
- chokepoint mxfs_buf_xfsaild_skip_dir_write (xfs_mxfs_dlm.c:14895) — add poison guard.

### Build state at relay
AB435ACC = baseline + P29 detector + merge-once-per-tenure (DEAD path, but dir_merge default OFF so inert) + datascan cmpresult reset (KEEP — real lookup-skip bug fix). Next session: implement the GPT design (poison+purge-at-NL). Reboot cluster before runs (shutdown leaves /dev/sda busy). See [[sess29-PROVEN-root-xfsaild-stale-dirblock-flush-at-EX]], [[sess29-fix-progression-merge-and-leaf-decision-tree]], [[env-test1-dhcp-reservation-fix-sess29]].
