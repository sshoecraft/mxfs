---
name: ccloop4dd7-sess5-A-ROOT-srmcount-corpse-reload-dec
description: sess5 ROOT #6 PROVEN+FIXED v0.11.69: suite-soak 833 dmesg hits = s_remove_count underflow; sess40 corpse reuse-reload from_disk 0→1 dec'd unpaired; c…
metadata:
  type: project
tags: [ccloop-4dd7, root-cause, s_remove_count, soak, rcu, drain]
---

# sess5 root #6 — s_remove_count corpse-reload underflow (soak 833 dmesg hits)

## Symptom chain (PROVEN)
- Suite `soak` FAIL 2/tcp v0.11.63: `dmesg_hits=833 == ops=833` — every workload op produced one `Call Trace:` line.
- Storm = `WARN_ON(s_remove_count==0)` in `__destroy_inode` (fs/inode.c:289): once the counter is **-1**, every unlink+destroy pair oscillates -1→0→WARN→-1 → one WARN per op, forever until remount. Also breaks `sb_prepare_remount_readonly` (-EBUSY while counter != 0).
- First WARN in failed run: 19:18:31 test1, 400µs after `P9-NLEDGE from_disk ino=2097284 old=0 new=1 rmcnt=0`.

## Root (RULE-4 chain, b65r2→b67r2)
1. Shadow ledger built: `MXFS_IF_RMC_ACCT` iflag (bit 23) + `mxfs_set_nlink/mxfs_drop_nlink/mxfs_inc_nlink` wrappers (xfs_inode.h) — ALL nlink writes routed through them; unpaired 0→N dec fires `P9-RMC-UNPAIRED-*` + stack; destroy-side verifier in `xfs_fs_destroy_inode`; provenance fields `i_rmc_last0_ra`/`i_rmc_lastclr_ra` (%pS).
2. b67r2 provenance print: `last0=xfs_dir_remove_child lastclr=destroy_inode` + stack `xfs_iget → mxfs_dlm_reload_inode → xfs_inode_from_disk` (comm=rm/bash lookups).
3. **Mechanism**: the sess40 IRECLAIMABLE reuse-reload block in `xfs_iget_cache_hit` (xfs_icache.c ~1377, gated `mxfs_reuse_reload && IRECLAIMABLE && i_dlm_stale && mode==0`) runs `mxfs_dlm_reload_inode` on a **VFS-destroyed corpse** (I_CLEAR; its nlink-0 already dec'd by `__destroy_inode`). Peer reused ino live → from_disk `set_nlink` 0→1 → unpaired dec → permanent -1. Retry then recycles with nlink already 1 → `xfs_reinit_inode` sees nonzero → no re-inc.

## Fix (v0.11.69 = 3A96D5A2)
1. `mxfs_set_nlink` corpse-raw arm: `if (inode->i_state & I_CLEAR) { __i_nlink = nlink; return; }` — destroyed corpses do not touch s_remove_count (their accounting is closed).
2. `xfs_reinit_inode` (xfs_icache.c): `inode->i_state = 0;` BEFORE the nlink restore — reinit re-OPENS accounting (b68r1 regression proof: without this the corpse-raw arm swallowed reinit's re-inc → counter -45 flood in one round; recycle stamps I_NEW only after reinit returns).
3. Verify: b69r1-r3 clean (unpaired=0 warn=0) where b65r2/b66r1/b67r2/b68r1 all fired within ≤2 rounds.

## Companion finding (probe armed, NOT yet observed)
`P9-RMC-DISCARD-LEAK` in `xfs_inode_free`: upstream-inherited +1 leak — cache_miss from_disk(freed dinode) incs, `xfs_iget_check_free_state` fails, out_destroy frees with no `__destroy_inode` dec. Common under MXFS cross-node reuse; masked the deficit (counter rarely at 0 → late storm ignition). Fix ONLY on evidence (RULE 4): close accounting before free via `mxfs_set_nlink(ip, 1)` on accounted-zero (paired dec through official helper), or direct dec.

## Also this session (separate root)
RCU-sleep in `mxfs_dlm_ag_drain_meta_buffers` (v0.11.65 = 88361A45): `rhashtable_walk_start` holds rcu_read_lock; blocking `xfs_buf_lock` + `xfs_bwrite` slept inside → once-per-boot "Voluntary context switch within RCU read-side critical section" WARN (mxfs-ag-bast kworker) + iterator-safety violation. Fixed: `rhashtable_walk_stop` before the blocking section, `walk_start` resume after rele, wrapped in pass-until-quiescent loop (≤8 passes, P-DRAIN-PASSCAP warn) — strictly more drain coverage than the old single pass (Invariant 1 kept). Verified: warn gone b65r1+, P99/P73 drain events still firing, no PASSCAP.

## P58-DIRPIN-NONEX note
b64r1: 23 fires `dlm_mode=0 state=0 ex_h=1` (kworker inactivation commits) — admission HELD (ex_h=1) but mode already 0; probable probe false-positive on the release window (probe checks mode, not holders). Parked; its capped dump_stack (6) can trip soak's dmesg grep if it fires during a soak window — revisit gating if it shows up there.

## State
tests/suite/soak.sh now persists matching lines to /root/soak_hits.$MARKER.txt + prints SOAK-HIT samples (forensics only; threshold unchanged). Suite was 20/20 on v0.11.64 (first all-green board). VMs test1/test2; LIO tcm_loop had to be rebuilt this session (`scripts/lio_tcm_setup.sh setup` — configfs was empty after host-side teardown; disk.img intact).
