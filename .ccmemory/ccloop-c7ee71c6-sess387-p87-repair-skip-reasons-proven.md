---
name: ccloop-c7ee71c6-sess387-p87-repair-skip-reasons-proven
description: sess387 PROVEN: P87 publish-repair fails because iflush trylock loses to a local rm ILOCK hold / PINNED; conversion lands ms later, after unlock. cac…
metadata:
  type: project
tags: [sess387, agi-unlinked, 361, p87-repair, iflush, ilock, rule4]
---

## sess387 (build 0.19.25 sv 29CC32F136428320C674214) — the #361/AGI chain, measured to the line

### Setup
Post-reset bring-up: stale PR clear at the SCST target (58 registrants, type-7 WE-AR, zero sessions — close_dev -force + rm /var/lib/scst/pr/mxfs* + scst_setup re-add → "No registrants"), mpath_up 32/32, FORCE_PREP 0.19.24 then 0.19.25.

### New instrumentation (0.19.25)
The lap-2 droplink rc=-117 previously escaped ALL named probes because P82-ADD's
300-event module-global cap suppressed the failing add's rc line (proven: test4 had
exactly 300 P82-ADD lines, failure at +10s past cap). Added, in
xfs/libxfs/xfs_inode_util.c:
- P82-ADD-FAIL: unconditional error-exit log in xfs_iunlink with stage= (dlm_lock/read_agi/insert)
- P-IUNL-INSFAIL: the backref/reload error exit in xfs_iunlink_insert_inode
- P-IUNL-LOGSAME: xfs_iunlink_log_inode's silent -EFSCORRUPTED (i_next_unlinked==next_agino)
- P-IUNL-BUCKETSAME: xfs_iunlink_update_bucket's silent -EFSCORRUPTED (old==new)

### The measured chain (test3, one incident, all lines adjacent)
P83-UNL-RELOAD agno=18 prev=0xb21 next=0x11d → **P84-UNL-RELOAD-LIVE cached=0
nlink=1** → P-IUNL-INSFAIL rc=-117 → P82-ADD-FAIL stage=insert → P217 droplink_tgt
→ trans_cancel shutdown. The sess384 open question is ANSWERED: **cached=0** — not
a stale local cache; the LUN home dinode genuinely reads LINKED. Release-side
visibility defect confirmed. The dead head 0x11d was test3's OWN slot-18 bucket
(self-poisoning after inode eviction), so acquirer-side FUA-retry heals cannot
cover it: the evicted split NEVER converts.

### Why the P87 publisher repair fails (P129-CLSKIP correlation, ailstuck_probe=1)
- test1 ino=8396097: 3/3 tries ILOCK_NOWAIT_FAIL owner ocomm=rm opid=4719 —
  a LOCAL workload thread held the ILOCK across the whole 2/4/8ms backoff window;
  IFLUSH_RAN err=0 arrived ~14ms after the third failure (post-unlock).
- test32 ino=12583375: why=PINNED ipin=1 despite the preceding log_force(SYNC);
  flush landed ~6s later.
- Repair conversion rate: 0/3, 0/3, 0/4 across the three sess387 laps (sess386: 1/3).

### Fix direction (GPT consult in flight at session time)
Order-correct waiting repair: igrab target → BLOCKING xfs_ilock(SHARED) (before
any buffer lock) → xfs_iunpin_wait → buf_incore → iflush_cluster (recursive read
trylock succeeds) → bwrite+flush → FUA verify; deadline-bounded; on failure
publish_refuse_unlock (currently = self force_shutdown at xfs_mxfs_dlm.c:44635).
Key deadlock tension: ILOCK holder may be in a CAW poll for a peer-held AG (120s).

### Repro protocol (reusable)
tests/d385_publication_verify.sh stepwise, TREATMENT arm, 32/caw: lap 1 always
passes, lap 2 reproduces (rsync_paired 0/32 + 1-3 node shutdowns) in 3/3 attempts
this session. ailstuck_probe=1 must be re-armed after every prep (module param
resets on reload).
