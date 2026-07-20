---
name: sess52-FINAL-phantom-is-reacquire-transient-state-ACQUIRING-ino131
description: sess52(ccloop) FINAL: ino=131 storm-dir grant-frees are ALL via mxfs_dlm_unlock (bast-coupled), NOT process_remote_release (that frees PEER grants on…
metadata:
  type: project
---

## sess52 — phantom narrowed to the re-acquire transient (build 2A9ACF1E)

### P52-GRANT-FREE (%pS) decisive result:
- EX inode grant-frees have TWO callers: `mxfs_dlm_unlock+0x165` (181×, the LOCAL bast-coupled release) and `mxfs_dlm_process_remote_release+0x21f` (58×, the MASTER freeing a PEER's grant, owner==sender — NORMAL, not a phantom).
- **For the storm dir ino=131 specifically, ALL grant-frees are via `mxfs_dlm_unlock` (120× on test2, owner=3936235405=local).** process_remote_release frees were for OTHER inodes (test2 as their master). So the phantom is NOT an uncoupled remote-release free.

### So the phantom is the state=1 (ACQUIRING) RE-ACQUIRE TRANSIENT:
- test2's P51-PHANTOM ino=131: `daddr=120 name=[node2_f5] state=1 (ACQUIRING) bastacq=0 demoter_self=0 comm=dd`.
- Sequence: node releases ino=131 EX via mxfs_dlm_unlock (i_dlm_mode→NL, coupled, correct). A create then RE-ACQUIRES (slow-path, state=ACQUIRING). The create modifies (addname → xfs_dir2_data_log_entry) while state=ACQUIRING and held<EX — i.e. BEFORE the re-acquire's grant is confirmed. mxfs_v5_dlm_inode_lock @14932 loops until rc==0 then publishes; the modify should be AFTER. So either (a) a SECOND create thread modifies under the cached EX while the first is re-acquiring (state shared across threads on the inode), or (b) the acquiring thread proceeds to addname before held==EX is true (the post-acquire reload/evict @15140 runs while the grant isn't fully GRANTED).

### NEXT SESSION — implement + test the fix:
The cleanest correct fix: gate the dir-block MODIFY commit on the grant being actually held. Either:
1. In ilock_begin, for a dir EX-modify, after the acquire path, do NOT publish i_dlm_mode=EX / serve until `mxfs_dlm_held_mode(...)>=EX` is TRUE (loop the slow-path acquire until held==EX, not just rc==0). The state=1 phantom = a serve/modify before held==EX.
2. AND ensure a 2nd create thread cannot fast-path-serve while another thread holds state=ACQUIRING with held<EX (the dir fast-path gates on state==CACHED — verify a create can't slip through during the ACQUIRING→CACHED transition before held==EX).
Validate: P51-PHANTOM count==0 AND dir_reuse 8/tcp PASS (perf RULE 0 — keep MHT for perf; mht=0 worsens phantoms).

### RULED OUT this session: partial-grant (P52-PARTIAL-GRANT 0×), lock_convert (dead code), process_remote_release-of-own-grant (it frees peer grants), bast_process uncoupling (it's coupled + ex_holders re-check @9345). 
Build 2A9ACF1E = baseline + gated P51 + always-on P52-GRANT-FREE(EX,ino<=256)/P52-PARTIAL-GRANT. Marker NOT written. Chain: [[sess52-NEXT-probe-find-local-dlm-downgrade-without-bastprocess]] [[sess52-ROOT-PROVEN-phantom-EX-bast-during-acq-modify-without-grant]].
