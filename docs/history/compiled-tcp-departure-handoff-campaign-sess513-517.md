<!-- TCP 2-node departure/hand-off/umount campaign sess513-517 (0.75.14-0.75.27): D-0905-D-0911 chain, root causes, fixes, rig traps. -->
# TCP 2-node departure/hand-off/umount campaign, sess513-517 (2026-09-05, 0.75.14 -> 0.75.27)

Continuation of `docs/history/docs/history/compiled-tcp-ledger-takeover-campaign-sess506-513.md` on the QNAP 2-node
TCP rig (test1/test2, `tests/sess507_chain_0750.sh` / `tests/sess511_chain_0756.sh`). Central
thread: a clean departure or a fenced/refused victim leaves stale DLM state (leftover PR
grants, a hand-off prepared to a node that already left, a dead node that keeps mastership)
that the survivor or a rejoin has to walk into before it's caught.

## D-0905/0906/0907 — closed sess514 MID
Closed F&V on three consecutive clean `sess511_chain_0756.sh` laps on 0.75.14
(s513m/n/o, fails=0, zero PAGE-PARKED)
(`docs/history/docs/history/docs/history/compiled-tcp-departure-handoff-campaign-sess513-517.md`,
`docs/history/docs/history/docs/history/compiled-tcp-departure-handoff-campaign-sess513-517.md`).
Also closed the same session: D-TCP-CLEAN-DEPART-LEDGER-TAKEOVER-HB-THREAD-48S (conformance
arm A x5 laps, zero HB-STALL/MONSLOW) and D-TCP-LAST-NODE-SAMEBOOT-REMOUNT-...-0904 (sameboot
arms 1-2, x5 laps)
(`docs/history/docs/history/docs/history/compiled-tcp-departure-handoff-campaign-sess513-517.md`).

## P142-BWORK-STALE — attributed, not a defect
Every joiner mount fires `P11-ACQSTALE-SELFBAST src=7` -> `P142-BWORK-STALE` exactly once on
the root inode: the slow-path acquire in `xfs_iget_cache_miss` sets `i_dlm_stale src=7`
(`xfs_mxfs_dlm.c:34724`) before a fresh inode is reloaded (gate at 34743), arming a
self-BAST that the sess60 backstop honors (`P70-BP ... EXIT=full`) — cost is one extra
release+reacquire of ino=128 per joiner mount, no waiter, zero redrive. Harness
(`tests/rejoin_residue.sh`) updated to assert `P142<=1` followed by the honor line rather
than asserting zero
(`docs/history/docs/history/docs/history/compiled-tcp-departure-handoff-campaign-sess513-517.md`).

## D-0908 — clean departure leaves PR grants un-wire-released
Root: `dlm/dlm.c mxfs_dlm_release_all` (~5663) frees a departing node's remaining table
entries locally with no wire release — AG grants are force-released
(`xfs_super.c:2246`) but inode grants (root PR at least) are not, because the DLM tears down
(`xfs_super.c:2295`) before `xfs_unmountfs` reclaims inodes. Every clean leave freed exactly
2 PR grants this way (ino=128 + ino=131). Re-import vector: `ledger_gen` derives from the
view hash, so any view change re-imports every page on first touch
(`docs/history/docs/history/docs/history/compiled-tcp-departure-handoff-campaign-sess513-517.md`).

Fix: 0.75.16 (sv 7C84BC1D) runs `dlm_wire_release_all()` + a second 3s ack wait at clean
departure (`P-RELALL-WIRED released=2 held_after=0` on every leave), gated by DEBUG knob
`depart_wire_release=0` to restore the old shape for planted arms. Side effect: `ack_rc=1`
on every leave — `RELEASE_ACK` was dropped by `v5_peer_msg_cb_tcp`'s teardown quiesce
(`!mounted` drops everything but `NODE_LEAVE`), costing +3s per clean unmount (the derived-budget rule). 0.75.17
lets `LOCK_RELEASE_ACK` through the quiesce, fixing it
(`docs/history/docs/history/docs/history/compiled-tcp-departure-handoff-campaign-sess513-517.md`).
Verified: 3 laps zero residue/zero P109; closed F&V alongside
D-TCP-SLOT-SUCCESSOR-...-0904 and D-EDEADLK-SELF-DEMOTE-...-0904
(`docs/history/docs/history/docs/history/compiled-tcp-departure-handoff-campaign-sess513-517.md`).

Planted-arm redesign for the "held" shape (`tests/rejoin_residue.sh` arm 4,
`RR_HELD_ARM=1`): runs both id parities with `depart_wire_release=0` on leave; whichever
node masters ino=128's page shows `RESIDUE-HELD`/refusal/one lap of P109 vs. a bounded
BAST-fire-until-purge on the other parity — harness now accepts either shape
(`docs/history/docs/history/docs/history/compiled-tcp-departure-handoff-campaign-sess513-517.md`).

## D-0909 — hand-off prepared to a node that just said goodbye
Two distinct windows under the same defect id.

**Window 1 (relay-to-departer).** `dlm_page_owner` still names the departing node B under
the pre-goodbye 2-member view; the FROZEN receiver treats a hand-off from the page's
view-owner as a RELAY and the eager 500ms tick hands the page onward to B — landing right
after B's goodbye lands. Window is hand-off..goodbye (tens of ms) vs. the 500ms tick, ~1 in
12 armed departures. 0.75.18 (sv 985A3B98) added a re-check in `dlm_page_hand_to`:
re-read `dlm_page_owner` + `dlm_node_in_view` after the drain and refuse a stale target
(`docs/history/docs/history/docs/history/compiled-tcp-departure-handoff-campaign-sess513-517.md`).

**The 0.75.18 guard broke every depart hand-off** — the caller-mapping trap: the new guard
used the helper's own view (`dlm_page_owner` = `active_nodes[page % N]`), but
`mxfs_dlm_handoff_depart` computes its target from the view *without* the departing node
(`others[page % (N-1)]`), since the departer still names itself in its own active list.
Every clean-leave hand-off was refused (`P-TAUTH-HANDOFF-STALE-TARGET why=depart`), the
root inode's page stayed ACTIVE under the departed authority, the successor's mount parked
on it until the departure worker's takeover, and 17 of 24 armed rejoins took 14s instead of
1s. The guard's own probe on the wrong node (the survivor, not the departing node) read
zero, masking it through one smoke lap. Fix: `bool departing` — a departing node only
requires the target be a live member; owner equality applies to the view-change pass alone
(0.75.19). Rules extracted: before adding a recompute-and-compare guard inside a shared
helper, enumerate every caller and confirm they compute the compared value the same way,
or pass the caller's expectation in explicitly; a guard that can refuse work needs a probe
on every node it can fire on, and the first lap after it lands must grep all journals, not
just the expected one — a zero on the wrong node is not a zero
([[trap-a-re-validation-guard-must-use-the-callers-mapping-depart-handoff-maps-the-view-without-self]]).

**Window 2 (TOCTOU across the view swap).** Root, from evidence: A activates B's
depart-handoff page (relay-activated because `dlm_page_owner` still names B under the
2-member view), processes GOODBYE (`active_count=1`), then PREPARES the same page back to
the departed incarnation under the NEW cfg — the tick computed the owner before the
goodbye, `dlm_page_freeze_drain` can wait 3s, and `update_active_nodes` swaps the list
then sets cfg. Successor's AG0 EX parks (`why[prepare=60]` x2,
`P-IMAP-UNTRUSTED-AGLOCK-FAIL`), mount takes 14s, self-heals via purge-driven
`P-TAUTH-RETARGET` ~13s later (natural purge latency)
(`docs/history/docs/history/docs/history/compiled-tcp-departure-handoff-campaign-sess513-517.md`).
Final fix landed as 0.75.20 (sv 230DEB5D): `MXFS_HANDOFF_F_DEPARTING` flag on the wire
(no proto-gen bump — spare pad byte reused), `departing_nodes[]`/`departing_count` under
the ctx active-nodes lock, `dlm_page_handoff_owner` = view minus departing nodes; the tick
and `dlm_page_hand_to`'s re-check both switch to this owner and refuse a departing target
(`docs/history/docs/history/docs/history/compiled-tcp-departure-handoff-campaign-sess513-517.md`).
Closed F&V after 3 clean laps of steps 9-11
(`docs/history/docs/history/docs/history/compiled-tcp-departure-handoff-campaign-sess513-517.md`,
`docs/history/docs/history/docs/history/compiled-tcp-departure-handoff-campaign-sess513-517.md`).

## D-TCP-UMOUNT-HANGS — dead/blocked/refused master keeps mastering
A dead member stays in the view until recovery completes, so it still masters `page%N`
resources; requests to it park (`P240-QUAR-PARK`) unless the master is classified blocked.
Chain of fixes: 0.75.19 `P-RBLK-DENY-DEAD-MASTER` fail-fasts a path op to EIO instead of
hanging (umount SIGKILL at 60s -> rc=0 at 8s)
(`docs/history/docs/history/docs/history/compiled-tcp-departure-handoff-campaign-sess513-517.md`).
Residual: `stat` still returned rc=0 despite the EIO-abort line — `mxfs_dlm_ilock_begin`'s
EHOSTDOWN arm returns void with no latch, and `mxfs_recovery_blocked_covers_ino` only
checked LOCALLY-mastered resources, missing ino=128/ino=131 mastered by the dead node.
0.75.21 (sv CCA2686A) added `mxfs_dlm_resource_held_by_blocked` answering 1 for a
dead-mastered resource (`P-RBLK-COVERS-DEAD-MASTER`); stat EIO wall dropped to 0s, umount
still 8s
(`docs/history/docs/history/docs/history/compiled-tcp-departure-handoff-campaign-sess513-517.md`).
0.75.22 (sv 79DB321C) made `mxfs_dlm_unlock_gen`'s remote path skip send+pending when
`recovery_blocked_cb(master)` (`P-RBLK-RELEASE-SKIP-DEAD-MASTER`) — umount rc=0 wall=3s, 8
releases skipped, arm PASS
(`docs/history/docs/history/docs/history/compiled-tcp-departure-handoff-campaign-sess513-517.md`).

Residual widened to a **sealed** (terminally refused, not just blocked) dead master:
umount under a fswide quarantine after a refused replay took 44s — stack samples showed
`mxfs_dlm_lock_retries <- mxfs_v5_dlm_inode_lock <- mxfs_sb_summary_lock <-
xfs_fs_put_super`, 120 "lock request ... failed, retrying" lines to the sealed dead master
over 60 rounds, then P-SB-SUMMARY-LOCK rc=-107, dirty departure (designed fail-closed
outcome, but slow). Root: `dlm_lock_impl`'s pre-send gate only asks
`recovery_blocked_cb(master)` = RECOVERY_BLOCKED (fence unproven); a terminally REFUSED
victim keeps membership/mastership until remount, because `v5_refresh_active_nodes` keeps
dead nodes and the refusal path never unregisters/remasters. A sealed-only predicate would
wrongly regress replay-in-progress parks, so it needs its own flag. 0.75.25 (sv
06DAB121F2) added `refused_victim[slot]`/`recovery_refused_n`, called from every survivor's
import chokepoint (`mxfs_quarantine_import_oc`); `mxfs_v5_dlm_node_recovery_blocked`
answers 1 for a refused victim before the send (`P-RBLK-DENY-DEAD-MASTER`,
`P-RBLK-TERMINAL`)
(`docs/history/docs/history/docs/history/compiled-tcp-departure-handoff-campaign-sess513-517.md`).
Closed F&V (0.75.25: refused-victim fail-fast, vfy umount 2s rc=-112, blocked arm 2s,
plain lap zero P-RBLK)
(`docs/history/docs/history/docs/history/compiled-tcp-departure-handoff-campaign-sess513-517.md`).

Side finding, unattributed to a specific fix: the *~38s before* the sealed-master release
skips fire (10 skips) on 0.75.23 is unaccounted for — candidates `xfs_ail_push_all_sync`,
`mxfs_sb_summary_final_sync` (cluster SB EX lock), `mxfs_dlm_ag_force_release_all` drains
(`pal/linux/xfs_super.c` 2220-2246); instrumented with 2s stack samples in
`tests/tcp_death_replay.sh` but not fully explained before the sealed-master fix
superseded the symptom
(`docs/history/docs/history/docs/history/compiled-tcp-departure-handoff-campaign-sess513-517.md`).

## D-0910 — refused victim + AG-mask, OPEN
Same root as the umount hang (a refused victim keeps mastership) but the consequence in the
AG-mask case is worse than slow: out-of-mask resources return EIO (was park-forever
pre-0.75.25) rather than being servable. Needs an AG-mask injector + a remaster design that
proceeds with the frozen blockers still present. Filed high severity
(`docs/history/docs/history/docs/history/compiled-tcp-departure-handoff-campaign-sess513-517.md`).
0.75.27 built `TDR_AGMASK_INJECT=1` arm in `tests/tcp_death_replay.sh` to measure it (writer
pre-creates in AG D via `dbg_fr_taint_items_over`, 8x post-verdict probe under alarms,
IN_MASK/OUT_MASK summary) — the harness check "every op outside the quarantined AGs
succeeds" is EXPECTED TO FAIL until D-0910 is fixed
(`docs/history/docs/history/docs/history/compiled-tcp-departure-handoff-campaign-sess513-517.md`).
Still OPEN at end of campaign.

## D-0911 — elected replayer keeps stale slot tracking, found + fixed sess516-517
Root: the ELECTED replayer never runs the monitor's `P163-RECOVERED` tracking reset (it
clears its own pending marker first), so `node_track[slot].last_epoch`/`slot_node_id` stay
pinned to the dead incarnation. The next claimant of that slot in the same generation is
then misread as "node in slot N has restarted (epoch change)" -> spurious second death
(`NO_VICTIM_KEY` refused), the live successor's goodbye is ignored
(`P-GOODBYE-DEAD-IGNORED`), 40s of view skew (`active_count=3` on 2 nodes), and a
REMASTER-VIEW storm — one rejoin mount hit 60 REMASTER retries on ino=128 and shut down
rc=32. Production shape (die -> recovered -> reboot -> remount) had never been exercised
because every prior lap re-mkfs'd
(`docs/history/docs/history/docs/history/compiled-tcp-departure-handoff-campaign-sess513-517.md`).
Fix 0.75.26: `dlm/disklock.c mxfs_disklock_slot_tenancy_retire()`
(`P-SLOT-TENANCY-RETIRED`/`P-SLOT-TENANCY-KEPT`) called from `v5_recovery_complete` after a
clean `clear_recovery_pending`; new `TDR_REJOIN=1` arm in `tests/tcp_death_replay.sh`
exercises same-generation rejoin. Closed F&V: rejoin arm 3/3 PASS (retired=1 restarted=0),
regression chain steps 1-6,11 fails=0, matrix-after-death x3
(`docs/history/docs/history/docs/history/compiled-tcp-departure-handoff-campaign-sess513-517.md`,
`docs/history/docs/history/docs/history/compiled-tcp-departure-handoff-campaign-sess513-517.md`).

## Other records closed this campaign
- D-JOINER-TRANSPORT-NOT-CONFORMED-...-0904: fix = 0.75.0 `MXFS_HB_FEAT_TCP` scan/adopt/refuse;
  closed on conformance + matrix R6/R8 evidence spanning s515-s517
  (`docs/history/docs/history/docs/history/compiled-tcp-departure-handoff-campaign-sess513-517.md`).
- D-0344 (`tauth_slot_reuse.sh` on mpatha, 4 nodes): closed, purge sweep names only victims
  (`docs/history/docs/history/docs/history/compiled-tcp-departure-handoff-campaign-sess513-517.md`).
- D-0350 (goodbye incarnation) closed
  (`docs/history/docs/history/docs/history/compiled-tcp-departure-handoff-campaign-sess513-517.md`).

Ledger open count through the campaign: 99 -> 92 (sess514) -> 91 -> 90 (sess515) -> 89 -> 88
(sess516) -> 86 (sess517, critical count 57 at that point).

## Rig / harness traps

- **Reused node id in a harness = a retired identity.** A `node_id_override` value that
  already departed once in the peer's mount lifetime is RETIRED
  (`P164-DEAD-NOTE`/`P164-DEAD-REJECT`); its announces/heartbeats are ignored forever, the
  view never advances, the mount parks to the 40s bound and gets killed, and the survivor
  then fences+foreign-replays the slot. Not a filesystem defect — real node ids are random
  32-bit per incarnation. Rule: never rejoin with an id that already departed in the same
  run; harness now uses `ID_LOW+1`/`ID_HIGH-1` (same parity as the import id)
  ([[trap-reused-node-id-override-is-a-retired-identity-p164-dead-reject-peer-never-admitted]]).

- **Bare `run.sh prep_cluster` on the QNAP rig needs `MXFS_DEV`+`MXFS_NODE_LIST` exported.**
  Without them it picks the fleet default `/dev/sda`, fails "claimed by dm-1" in 13-20s,
  and leaves nodes unmounted, cascading into 1s INFRA failures downstream. Never call
  `run.sh` prep by hand on this rig; drive through the chain scripts, which export both
  ([[trap-bare-run-sh-prep-on-the-qnap-2node-rig-needs-mxfs-dev-and-node-list-exported]]).
  Same root recurred twice more: `tests/domain_admission_matrix.sh` defaults
  `MXFS_DEV=/dev/mapper/mpatha` when run standalone outside
  `sess507_chain_0750.sh`, producing 9 uniform rc=32/WALL=0 fails against the wrong LUN
  (signature: ALL rows fail including refusal rows, zero kernel lines — a real admission
  bug fails only one or two rows). Matrix header now prints `dev=`
  ([[trap-domain-admission-matrix-defaults-to-mpatha-run-standalone-on-qnap-rig-needs-mxfs-dev-exported]],
  [[trap-node-journals-are-volatile-a-failed-rejoin-mounts-evidence-survives-only-in-the-libvirt-serial-log]]).

- **mkfs `zero_region verify FAIL` on the QNAP LUN, transient, unresolved.** One occurrence
  immediately after a fleet unmount (test1 clean unmount, test2 had just EDEADLK-NL'd);
  `sg_persist` showed no stale PR key/reservation, ruling out the known stale-PR-blocks-mkfs
  shape. Offset landed inside the tauth ledger's `zero_region` (`mkfs_mxfs.c:732`), one 4KiB
  page past a 64MiB boundary — looks like a ledger entry landing after the zero, or a stale
  read of another node's just-written page from the QNAP target's cache. Rerun prepped fine.
  Not root-caused; a second occurrence is a ledger-worthy data-integrity defect (capture mkfs
  timestamps against the last teardown and dump the 4KiB page before any rerun overwrites it)
  ([[trap-qnap-mkfs-zero-region-verify-fail-transient-right-after-fleet-unmount]]).

- **Node kernel logs do not survive the next lap.** Test VM journald is volatile and dmesg
  wraps within ~15 minutes of chain activity; a `virsh destroy` (every death lap) discards
  the previous boot's journal outright. What survives: `/var/log/libvirt/qemu/<node>-serial.log`
  on clyde (root-only), monotonic timestamps, console-level lines only — anchor to wallclock
  via a harness-stamped copy of the same line. Rule: every harness step that can fail must
  capture both nodes' kernel windows into its evidence dir at the time it runs, filtered to
  drop only known ledger-page noise, never a positive filter naming expected lines
  ([[trap-node-journals-are-volatile-a-failed-rejoin-mounts-evidence-survives-only-in-the-libvirt-serial-log]]).

- **fio's `:` filename split survives one level of ssh escaping.** `raw_fio_ceiling.sh`'s
  existing single-backslash escape (`DEV="${DEV//:/\\:}"`, a prior lesson) was stripped by
  the remote shell before fio saw it, so fio split the QNAP by-path device name on `:` and
  created a fragment file per piece in the ssh cwd (`/root`), filling the node's root disk
  (22GB+ of junk) and producing a bogus 5000 MiB/s "ceiling" reading. Root disk exhaustion
  then broke unrelated preps with a misleading "mxfs.ko md5 never matched (NFS staleness)"
  signature. Fix: double-backslash the colon so one survives the remote shell, plus a
  post-run check for fragment files on every node. Rule: any `:`-bearing device path handed
  to fio through ssh needs the double escape, or resolve it on the node first; a recurring
  "md5 never matched" prep failure should check `df -h /` on the node before suspecting NFS
  ([[trap-fio-by-path-filename-colon-split-survives-one-escape-level-ssh-eats-backslash-fills-node-root-disk]]).

- **32 idle VMs exhaust clyde's RAM and the harness kills background work.** Leftover idle
  VMs from prior 32-node boards (~1.3GB RSS each) drove clyde to 0 free / 20 of 23GB swap,
  and Claude Code killed an 80-minute background rig chain for low memory. The chain script
  itself survived as an orphan. Fix: `virsh destroy` (ACPI shutdown did not complete in 60s)
  the unneeded VMs; delegate the 30-call cleanup to a rig-runner in one Agent call. Rules:
  check `free -g` before a long background job on the 2-node rig and shut VMs it doesn't
  need (test1-4 stay); scaling back up to 32 needs staged `virsh start` in batches of ~8 plus
  `mpath_up.sh up 32` as the readiness gate; a killed background wrapper does not kill the
  chain it launched — check for the orphan before assuming the rig is idle
  ([[trap-32-idle-vms-running-exhausts-clyde-ram-harness-kills-background-tasks-shut-idle-vms]]).

- Rig facts re-learned: never `make` while a chain is running (every prep step redeploys
  `mxfs.ko` from the tree, mid-lap); never edit a harness `.sh` while bash is executing it
  (`docs/history/docs/history/docs/history/compiled-tcp-departure-handoff-campaign-sess513-517.md`).
