<!-- sess473 RULE-5 (GPT) review of the D-0533 dirshard probe revalidation: STOP-SHIP, 12 findings; 4 actioned in 0.64.20 (convergence test, short wait in… -->
# sess473 GPT review — D-0533 fix (mxfs_dirshard_probe_revalidate)

Verdict: STOP-SHIP on the first cut. Findings (numbered as returned):
1. In-place reload of a REFERENCED shell into another incarnation is unsafe in principle (fds/dentries of {X,G1} silently become {X,G2}); wants reuse quarantine or {ino,gen}-keyed objects. NOT actioned: tree-wide discipline (xfs_lookup P95-SAMETYPE-RELOAD / typeflip reload); documented hazard.
2. Convergence bug: success on igen==gen even with i_dlm_stale still set. ACTIONED: require !stale && igen==gen && ftype==expect.
3. Reload state not serialized (polling flag writes). NOT actioned: the trylock+bail contract is what every reload caller uses; documented.
4. Parent->member order safe only if no peer waits for the parent while holding member EX (even cached). Audit note: member BAST/release drain never takes the parent. Documented.
5. Never run the wait under an allocated transaction. ACTIONED: current->journal_info -> 20-round bound (manifest load always runs tp=NULL; the bound covers any other caller).
6. 2 s under parent ILOCK_EXCL in inactivation is operationally unsafe. ACTIONED: teardown callers (free_container / inactivation holder probe) get the 20-round bound; -EBUSY leaves the set for the next pass.
7. -EBUSY must not escape getdents. ACTIONED: mxfs_dirshard_iget maps -EBUSY -> -ESTALE; deletion path keeps the set.
8. FUA read authoritative only if the DLM flush protocol makes it so. Invariant 1 (releaser drains inode buffers before unlock) after mxfs_dlm_force_peer_flush; errors of the FUA read still fold to 'no data' (dmode=0 -> gone) — WATCH: a failed FUA read reads as free. (Follow-up candidate: distinguish read failure from mode 0.)
9. Deletion must fail closed on a different nonzero disk gen. ACTIONED: P-DIRSHARD-STRANGER-LIVE -> -EFSCORRUPTED (deletion: any other error keeps the set).
10. Matching gen insufficient: check type too. ACTIONED (convergence test); nlink/flags checks remain in the caller.
11. Right-gen-but-older image OK only if every caller ILOCKs the member before reading contents. Documented (readdir/lookup do; shard_settle).
12. mode-0 / IRECLAIMABLE shells: xfs_iget resolves them before the probe sees the inode (mode 0 -> -ENOENT). Documented.

Open follow-up from item 8: mxfs_inode_disk_di_size returns dmode=0 on a READ FAILURE too, and the revalidate reads dmode==0 as 'platter free -> gone'. On the deletion path that could clear a bit over a live container after an I/O error. Make the helper distinguish (return value (u64)-1 == error) before relying on it for teardown.
