---
name: ccloop-c7ee71c6-sess47-REAP-IFREE-117-ROOT-PROVEN
description: sess47: D-REAP-IFREE-117 ROOT PROVEN via deterministic repro (tests/reap_midlist_repro.sh, 40s): reap-after-reclaim mid-list remove with prev=0
metadata:
  type: project
---

# D-REAP-IFREE-EFSCORRUPTED-SHUTDOWN-372 — ROOT PROVEN (sess47, 0.11.374)

## Mechanism (probe-proven, deterministic)
1. Node A unlinks N files while node B holds them open → B6 defers (P87-OPEN-DEFER), zombies parked on A's SLOT bucket (depth-N chain). In-core prev/next chain state correct at this point.
2. Memory pressure reclaims A's shells (P140-RECLAIM-COMMIT) → i_prev_unlinked/i_next_unlinked/i_unlinked_bucket destroyed.
3. B closes → A's reap worker igets fresh shells (prev=0, next=disk, bucket=-1), restores ONLY bucket+authority-flag from reap entry (xfs_mxfs_dlm.c:31339-31343). NOTE: the authority flag gets stripped AGAIN by the inactive-side DLM EX acquire's reload (lu=0 au=0 at remove time); i_unlinked_bucket SURVIVES → fix must key off bucket.
4. Worker reaps in defer order = insertion order = FIRST-deferred = chain TAIL → xfs_iunlink_remove_inode mid-list branch → xfs_iunlink_lookup(pag, prev=0)=NULL → silent -EFSCORRUPTED (the ONLY printless exit; now named P-UNLREM-NOPREV) → xfs_ifree -117 → META_IO shutdown → withdrawal. difree SUCCEEDED before (P150s; tx dirty at cancel).

## Ring decode (run2, test2:/root/ifree117_run2_1785703032.dmesg)
-117 at line 100474 t=1950.53; inos 67108993(agino 0x81, tail)+67108995 deferred 1915-1925, BOTH reclaimed t=1925.4349, reap t=1950.52 → no P82-REM, no P71-INSTR, no corruption print = silent exit fingerprint.

## Probes added (0.11.374, xfs/libxfs/xfs_inode_util.c remove_inode)
P-UNLREM-INCOMPLETE (entry, prev==0), P-UNLREM-NOPREV (silent exit), P-UNLREM-LOGSELF, P-UNLREM-BACKREF.

## Repro
tests/reap_midlist_repro.sh UNL OPN NF — REPRODUCED first run (40s): P-UNLREM-INCOMPLETE=1, NOPREV fired, -117 shutdown. Exit 0=CLEAN when fixed (all P89-REAP-DONE, no -117).

## Fix design (GPT consult in flight at save)
Choke-point C: xfs_inactive_ifree, after AG DLM + revalidation guards, before xfs_ifree: if xfs_inode_unlinked_incomplete(ip) → xfs_inode_reload_unlinked_bucket(tp, ip) (honors i_unlinked_bucket≥0; P85 foreign-guard passes since bucket≥0). Reload error → treat as revalidation-skip (fail closed, zombie durable, reap retries). Members igot by reload can't be reclaimed before our remove: their igc inactivation blocks on the AG DLM we hold. Upstream never needed this: its 3 unlinked-iget surfaces (bulkstat/quotacheck/NFS-fh) reload at iget; mxfs's reap worker is a 4th surface with no reload.
