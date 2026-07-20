---
name: sess23-ROOT-dg-shadow-epoch-unreliable-lru-evicts-hot-dir
description: sess23(ccloop) DEEPEST ROOT: the master dir-handoff epoch (dlm/dlm.c dg_shadow[512] LRU table) occasionally reads 0 for the hot dir_reuse dir — LRU-e…
metadata:
  type: project
---

## sess23 (ccloop) — the dg_shadow epoch is the unreliable foundation

After landing the read-path master-epoch fix (build 7EDF3278, dir_tenure_evict=1 covers the !owned_ex addname RMW read with a master-epoch `tenure_stale` that respects the in-AIL keep-guard), dir_reuse 8/tcp is STILL FLAKY (passed clean once at 351s, failed the next run 0/8 single-entry, no cascade). Traced WHY:

### Root: the master dir epoch (dlm/dlm.c) is the foundation everything rests on, and it's unreliable
- `mxfs_v5_dlm_inode_dir_epoch()` returns the per-resource handoff epoch from `dg_shadow[DG_SHADOW_N=512]` — a file-global **LINEAR-SCAN** table in the DLM master.
- `dg_grant_ex()`: on an EX grant, epoch++ ONLY if the resource's slot is FOUND (mine>=0) AND handoff (last_owner != new owner). If the slot was **LRU-evicted** (recycled for another inode) it's treated as "first grant" → **epoch RESET to 0, handoff=false, epoch_out=0**.
- `dg_release()` only marks active=false (keeps epoch/last_owner), so release alone doesn't reset.
- The dir_reuse workload creates ~800 file inodes/round; they churn the 512-slot table. The hot shared-dir inode is granted ~800×/round so its last_grant_seq is usually near the top (LRU protects it) — but it goes briefly INACTIVE between grants, and in a window where 512 file-inode grants are more recent, the dir's slot becomes the LRU victim → evicted → epoch resets to 0. Next dir grant: epoch_out=0 → cur_ep=0 → my tenure_stale (and P16 epoch_stale, and P-FASTEX-EPOCH) CANNOT fire → stale RMW base → clobber. The rarity of this eviction window == the FLAKINESS.

### Why the obvious fix is REFUTED
Enlarging DG_SHADOW_N is explicitly refuted (dlm.c:2464 comment, sess17): the table is linear-scanned per grant in dg_grant_ex/dg_release, so "enlarging to 16384 caused O(N)-per-grant acquire timeouts" (→ DLM timeouts → shutdown cascades). The sess17 LRU fix reduced but did NOT eliminate the hot-dir eviction.

### NEXT SESSION — make the epoch reliable (the real fix)
Convert dg_shadow from a fixed linear-scan array to an **O(1) hash table** (keyed on resource id) so it can hold the full working set (8k+ entries) WITHOUT the per-grant O(N) cost → the hot dir's epoch is never lost → handoff always detected → epoch advances reliably → dir_tenure_evict's tenure_stale fires every time → stale base always refreshed. Alternative (smaller change): PIN the hot dir's slot (never LRU-evict a slot granted within the last K seqs / mark a "sticky" bit on a resource granted >N times). Then dir_tenure_evict (build 7EDF3278) should pass dir_reuse 8/tcp reliably; then make it default-ON and validate full 8/tcp + 1/2/4 tcp.

### Carry-forward build
**7EDF3278** = B17FED9A (modify-evict + master-epoch sync + GPT-9.1 release undestaged-clear) + read-path `tenure_stale` in the !owned_ex block of xfs_da_read_buf (master-epoch-synced, respects in-AIL keep-guard). dir_tenure_evict DEFAULT-OFF → keeper inert. Flaky-pass (no cascade). The owned_ex read path is INERT here (owned_ex requires dp->i_dlm_unpublished, false for the shared dir — PROVEN P23-OWNEDEX-REFRESH=0).

See [[sess23-BREAKTHROUGH-master-epoch-sync-flaky-pass]] [[sess23-residual-block-bypasses-evict-needs-ownedex-read-coverage]] [[sess23-gpt5.5-grant-generation-coherency-design]].
