# Per-criterion time budgets

`budget = infra (measured: boot/mkfs/mount/ssh fan-out) + workload
(native-XFS equivalent × 2)`.

The budget IS the command timeout.  Exceeding it = criterion FAIL,
even with zero errors — kill, record, diagnose the slowness.  Never
widen a budget to make a run pass.  After each healthy PASS, record
the actual wall in this table and tighten the budget toward it.

Reference hardware facts (measured):
- native XFS rsync of ~700MB tree: 3-4 s
- mkfs_mxfs: 0.6 s            - first cluster mount: 2.7 s
- subsequent mounts: 4.8 s    - umount: 0.4 s
- VM power-cycle to ssh-up: ~40-50 s
- 4-node fresh_cluster_mount (teardown+mkfs+mount): ~60 s
- ssh round-trip per node: ~1-2 s

## Mount-path recovery barrier (0.11.401, sess57) — a CONDITIONAL mount cost

`mxfs_dlm_mount_recovery_barrier()` runs inside `xfs_mountfs()` right after
`xfs_log_mount()`.  When — and only when — this node finds a peer whose
heartbeat was ALREADY frozen at mount time and which still holds CAW grants,
the barrier blocks the mount thread for the dead-confirmation window before
it may fence that peer and replay its slice:

    confirm window = dead_threshold × HB interval
                   = 31 × 2000 ms = **62 s**   (shipped defaults)

then one foreign-slice replay per confirmed slot (0.2 s each, measured at
crash_consistency 2/4-node).  A clean cluster pays **0 s** — there are no
frozen-slot grants to confirm.  A crash-recovery mount pays 62 s ONCE for the
whole cohort (the confirmation is a single batched window over the mask, not
per slot).

This is NOT slack: it is the price of not fencing a node that is merely slow.
The pre-0.11.401 code paid the same 62 s off an async worker AFTER the mount
returned — which is exactly the bootstrap deadlock this build fixes, because
the grants being confirmed can block the mount's own recovery.

**Who pays it.**  Only a node MOUNTING while ANOTHER slot is frozen AND still
holds CAW grants.  It is not paid by a survivor that watches a peer die while
already mounted (that is the heartbeat monitor's async path, unchanged), and
it is not paid for the mounting node's OWN previous incarnation (mount step 4
handles that slot).  In practice it fires on: remount after a mass crash with
no survivor to replay, and a node rejoining a cluster whose dead peer nobody
has recovered yet.

Criteria that can hit it — verify a healthy wall on each before tightening:
crash_consistency, fence_during_write, fault_netpartition,
withdraw_recovery_test, ag_strand_repair.  crash_consistency's 90 s budget has
the thinnest margin on the board (86-88 s actual); if it starts timing out at
0.11.401, grep the mount's kmsg for `P225-SETTLE-VERIFY` / `MXFS mount
recovery barrier complete` to tell a paid confirm window from a real
regression — a paid window is a correctness cost to budget for, not slack to
absorb.

| Criterion | Infra | Workload (native×2) | BUDGET | Last healthy wall |
|---|---|---|---|---|
| d0980_barrier_killable.sh (2/tcp; SIGTERM into a barrier holding on a frozen record, then the control mount and the retry) | VM destroy+start+boot ~150 s + deploy ~20 s + K: KILL_AT_S 20 s + slack + captures ~25 s + C: dead window 62 s + one takeover/fence/replay round 18 s (s65g) + unwind ~10 s + R: ~10 s + captures ~30 s ≈ 325 s | — | **480s** (≈325 s × 1.5); JOIN_BOUND 300 s per unsignalled mount | 282 s PASS fails=0 (0.89.2 A11292AE, s66g: K returned 376 ms after the 20 s signal, C mounted in 88 s with an 80.6 s barrier wait, R in 2.8 s) |
| d0981_pending_victim_sweep.sh (2/tcp; A builds the unowned FENCED descriptor under mxfs.dbg_barrier_refuse_after_claim=1, then B mounts onto it, then A) | VM destroy+start+boot ~150 s + deploy ~20 s + A's knob mount: dead window 62 s + fence, seal, claim ~10 s + B's mount: claim + 6 s stability proof + replay + the second ghost's window and fence ~90 s + A's mount ~10 s + captures ~40 s ≈ 380 s | — | **570s** (≈380 s × 1.5); JOIN_BOUND 300 s per mount | 258 s PASS fails=0 (0.89.3 82222A48, s66i: knob mount refused at 71 s, B mounted in 14 s over two unowned descriptors, A in 2.8 s); 307 s PASS (0.89.4 9FE0EA9A, s67i, first lap with the O_DIRECT platter dump) |
| prep_heartbeat_writer_guard.sh (2/tcp; the format script on A while B heartbeats; must refuse) | two dumps 3 s apart ~8 s + the script's own two dumps ~8 s + captures ~10 s ≈ 26 s | — | **60s** (≈26 s × 2, the floor for a lap that restarts nothing) | 11 s PASS fails=0 (0.89.4 tools on module 82222A48, s67g, tests/evidence/20260919T140725Z_prepguard_s67g-*: refused on slot 1 ts 517167->519215, no mkfs, B writable after; s67a/s67c/s67e aborted before the arm — the fleet prep refused under the foreign writer serv, the fsid capture used findmnt/blkid, the buffered platter dump was stale on the mounted node) |
| fence_crash_cuts.sh (2/tcp; one prover crash cut per lap, cuts 1-6: A parks at the cut fencing the destroyed B, is destroyed there, B's host returns and reads the quiescent platter before it mounts, then mounts, then A's host returns) | prep ~60 s (bound 300) + B's 64 fsynced creates ~5 s + the 62 s dead window + the fence to the cut ~5 s + three captures at the cut ~10 s (inside the 30 s hold) + B boot ~60-150 s + NFS and module copy ~30 s + B's mount (bound 300; the sibling shapes' judge mounts measured 22-89 s) + captures ~20 s + A boot ~150 s + A's mount (bound 300; measured 3-14 s on the siblings) + captures ~20 s ≈ 450-900 s | — (the hold is the measurement) | **1200s** (≈900 s × 1.33; the two mount bounds alone are 600 s) | (record per cut) |
| fence_rejoin_barrier.sh (2/tcp; is a rejoining node admitted on the SEAL or on the slice being RECOVERED?  dbg_replay_hold_ms parks the foreign-replay worker after the execution lease is claimed and before the slice is replayed, so the returning peer meets a sealed-but-unreplayed window that is otherwise ~8.6 s wide) | prep <=240 (measured 55-62) + B's 32 fsynced files 30 + the arm 10 + the dead window 62 + the fence to the seal ~90 | the HOLD itself is the measurement (hold_ms, default 200000); B's boot and its refused mount attempt run INSIDE it, so they are not added; then the release, the replay ~15, B's decisive remount ~90 and the final captures 40 | **800s** | 345s and 349s PASS fails=0 (0.89.14 5F0E00F2… and A61384738B9AFD449E985DD, 2026-09-20) — hold released after 28-30 s, slice replayed 6 s later, peer refused during the hold (MOUNT_RC=32) and admitted after (MOUNT_RC=0, 32/32 byte-identical) |
| fence_cert_publish.sh (2/tcp; the certificate PUBLICATION path, one arm per invocation: retry = injected CAS failures inside the window, lost = the CAS completes and its result is withheld, spent = the whole window is consumed and the injected fault is then CLEARED because it models a transient) | prep <=240 (measured 55-62) + B's 32 fsynced files 30 + the injector arm 10 + the dead window 62 + the registration purge and the fence ~90 | the certificate window (five tries, ~6 s) + the replay 40 + B's boot 150 + its re-prep and mount 200 + final captures 60 | **560s** spent / **420s** retry, lost | 294s / 294s / 293s PASS fails=0 (0.89.14 A61384738B9AFD449E985DD, 2026-09-20) |
| fence_retire_basis.sh (2/tcp; boot succession must refuse to certify without a retirement basis — arms: qualified / no contract / contract naming another firmware) | prep <=240 (measured 55-62) + B's 32 fsynced files 30 + the contract arm and its read-back 10 + the dead window 62 + the purge ~90 | the refusal or certificate ~10 + B's boot 150 + re-prep and mount 200 (the refusing arms spend the full mount bound before rc=32) + captures 60 | **560s** | 328s qualified / 446s none / 445s wrongfw, all PASS fails=0 (0.89.14 A61384738B9AFD449E985DD, 2026-09-20) |
| fence_gate_basis.sh (2/tcp; the sole-survivor exclusive-write gate must not certify without a retirement basis, and the deployment clause must cover the transition that was observed — arms: qualified / no contract / another firmware / the withdrawn clause / a replacement observed from the same boot / from a different boot) | prep <=240 (measured 56-68) + B's 32 fsynced files 30 + the contract and observation arm with its read-back 10 + the dead window 62 + the purge and the decision ~70 | the certificate or the refusal ~10 + B's boot 150 + re-prep and mount 200 (every refusing arm spends the full mount bound before rc=32) + captures 60 | **560s** | 290s qualified / 443s none / 450s wrongfw / 450s oldclause / 453s sameboot / 452s diffboot, all PASS fails=0 (0.89.15, 2026-09-20). A lap that exits early between the power cut and the restart leaves the victim off and the NEXT lap burns its whole budget on boot-wait plus a power-cycling prep — measured 578s to reach the files stage having graded nothing; the harness now restores the node on an exit trap. |
| fence_lost_response.sh (2/tcp; the fence matrix's lost-response entry: a real PREEMPT AND ABORT acts on the alive-but-silent victim, its successful result is withheld from the fencing caller, and the prover KEEPS RUNNING) | prep ~60 s (bound 300) + identities, READ KEYS and B's 64 fsynced creates ~30 s + arm and heartbeat park ~10 s + the 62 s dead window and the fence to the P&A ~10 s + the non-vacuity and ambiguity captures ~60 s + the latched observation OBSERVE_S 75 s (one 60 s re-drive sweep, inside the 120 s fence_blocked_after_ms transition) + the three bounded fail-fast probes 45 s worst case (one acquire round trip each) + the released path to a certificate and P163-RECOVERY-COMPLETE ~240 s + B's destroy, boot and mount ~280 s + final captures ~40 s ≈ 925 s | — (the observation window is the measurement) | **1000s** | (record per lap) |
| fence_late_detection.sh (2/tcp; a fenced-but-undetecting node meets a LUN that has stopped refusing anyone — the victim runs NO workload and its detectors are held off, so containment can only come from the local authority lease) | boot-wait ~2 s when the previous lap cleaned up after itself, 152 s when it did not + prep ~60 s (bound 300) + the probe target, its FIEMAP extent and the baseline platter read ~30 s + the control probe on a healthy B ~20 s + the arm ~10 s + the 62 s dead window and the fence (bound 120; measured 25-55 s) + captures ~20 s + destroy ~10 s + the registration purge (bound 120; measured 30-40 s) + captures ~20 s + the two write arms 30 + the decisive platter read 40 | the metadata arm waits out the DLM's membership-change retry budget when the gate does not catch it first — bound 260, measured 260 s STALLED pre-fix and 0 ms post-fix | **1200s** | 176 s PASS fails=0 (0.89.20 B65B76C6, s87h, AUTHPUMP=600000 — periodic evaluator parked, so only a submission could find the expiry); 262 s PASS fails=0 (s87l, AUTHPUMP=0 — periodic evaluator live); 584 s and 440 s FAIL fails=4 on the pre-fix build (s87e, s87f: all three writes accepted, `fenced-direct-wr` read back off the raw LUN). The lap power-cycles BOTH nodes at the end — its heartbeat park is an injected sleep no knob can shorten, and one that outlives the lap stalls the next prep on an unmount waiting for a sleeping thread (measured s87i: the whole 300 s prep budget spent on "test2 did not release mxfs"). |
| auth_lease_resurrection.sh (2/tcp; once an authority lease has CLOSED, can anything bring it back? arms: resume = the heartbeat thread comes back from a stall; staleanchor = a renewal whose beat was ISSUED after authority had already lapsed, reached by removing the pre-issue check for one cycle) | prep <= 300 (measured 44-46) + the healthy control 20 + the arm 10 + the park, lease 30 + 15 = 45 + waiting out the park 50 + the resume captures 30 | the refusal probe after the resume 30 + final captures 40 + the node restart 10 | **660s** resume/staleanchor/latecompletion, **900s** resvgone (it adds the 62 s dead window, the fence, the prover's death and the 30-40 s purge, all inside a 180 s park) | 342 s PASS fails=0 resvgone (0.89.20 E9DD2E48, s87r, tests/evidence/20260920T163848Z_authres_resvgone_s87r: registrants 2 -> 1 at the fence, prover destroyed, purge to zero registrants and no reservation in 35 s, then the returning heartbeat found the lease closed and STOPPED with no LUN-dependent detector having fired); 124 s PASS fails=0 latecompletion (s87t, tests/evidence/20260920T164812Z_authres_latecompletion_s87t: issued_ms=265959, delivered_ms=312039, deadline_ms=295959 = issued + 30000 exactly); 119 s PASS fails=0 resume (0.89.20 E9DD2E48, s87m, tests/evidence/20260920T162402Z_authres_resume_s87m: closed 240 ms past the deadline, P290-AUTH-HB-STOP on resume, a write after the resume still EIO); 116 s PASS fails=0 staleanchor (s87n, ...T162610Z_authres_staleanchor_s87n: the beat landed — last_ok_ms == now_ms — and the renewal was refused anyway at overdue_ms=18129). The lap power-cycles the victim at the end: a closed lease plus a parked withdrawal pump means nothing drives the shutdown, and leaving it costs the NEXT lap its whole prep budget on "test2 did not release mxfs" (measured twice, s87i and s87p). That combination is an injection artifact, not a product state — with the pump live a closed-authority mount unmounts in 1 s (auth_lease_unmount.sh). |
| auth_lease_unmount.sh (2/tcp; can a mount whose authority lease has CLOSED still be unmounted and its module removed? the lease refuses the journal too, so a withdrawn mount cannot write its own unmount record) | prep ~60 s (bound 300) + the pre-check that B is writable ~10 s + the park, lease 30 + 10 = 40 s + closure observation (bound 60; measured 25 s) + waiting out the rest of the park 40 s | umount bound 60 (a native unmount of an idle mxfs mount measures 2-4 s and a shut-down one has nothing to flush) + rmmod bound 60 + liveness 20 | **540s** | 136 s PASS fails=0 (0.89.20 B65B76C6, s87j, tests/evidence/20260920T160332Z_authum_s87j: lease closed 232 ms past its deadline, umount rc=0 in 1 s, rmmod rc=0 in 0 s, node still serving, zero BUG/Oops) |
| pr_retirement_probe.sh (2/tcp; after the target has lost a node's I_T nexus, can a write it already ACCEPTED from that nexus still land?  The premise every fence kind rests on and none of them witnesses) | device resolution and PR setup ~20 s + writer warmup and the advance control 20 s + the power cut 5 s + the observation OBS_S 150 s (covering the ~34 s registration purge this target is declared to do, plus margin) + the victim's boot ~90 s + the re-format ~30 s ≈ 315 s | — (the observation window is the measurement) | **400s** | (record per lap) |
| chk_oracle_calibration.sh (host-local, no rig: a 512 MiB image behind a loop device; the clean control, five corrupted fixtures, five execution results) | 7 formats ~3 s each + 12 checks ~2 s each + loop setup ~2 s ≈ 50 s | — | **150s** (≈50 s × 3; the checks are sub-second, the formats dominate) | 78 s PASS fails=0 (0.89.7 tools, s70i, tests/evidence/20260919T163021Z_chkcalib_s70i); 84 s / 56 s FAIL fails=1 on the crash fixture's own delivery (s70g: a 50 ms SIGSEGV bound outlived the check; s70h: an unprivileged kill of the root-owned checker was refused) |
| chk_mounted_node_reads_platter.sh (2/tcp; the checker refused on a mounted node, then run on an unmounted node whose device a plain process holds open) | device resolve ~5 s + the refused check ~3 s + B's unmount ~10 s + four superblock reads ~8 s + 200 creates at ~14 ms ~3 s + A's unmount ~10 s + the checker on a ~20k-inode filesystem ~3 s (bounded 120 s) + two remounts ~30 s ≈ 190 s | — | **380s** (≈190 s × 2) | 52 s PASS fails=0 (0.89.7 tools on module 9FE0EA9A, s70a, tests/evidence/20260919T154808Z_chkmounted_s70a-*: refused rc 4 in 8 ms, buffered 20288 against platter 20480 before the check, checker rc 0 in 2.2 s, buffered 20480 after; fault lap ABORT at the injection); 58 s PASS fails=0 on the harness's own assertions (0.89.6 tools, s69a) while the checker printed ten errors from its interior-node pointer defect — the harness now asserts the checker's rc as well |
| recov_bmbt_reuse.sh (2/tcp; re-lap for the harness records, through the capture gate) | the harness header's own derivation; the gate manifest's healthy bound is 900 s | — | **900s** (manifest) | 198 s PASS fails=0 (0.89.3 82222A48, s67d, tests/evidence/20260919T134859Z_capture_gate_s67d-recov_bmbt_reuse: recovery populated 175 extent-tree images, none served from cache after the rebuild) |
| sole_survivor_gate_probe.sh (2/tcp; B held 100 s post-register, A fences under the injected proof refusal) | VM restart ~150 s + deploy ~20 s + B's hold 100 s + A's bounded park (122 s bound + one round) + captures ~30 s ≈ 430 s | — | **600s** (the gate manifest's healthy bound); JOIN_BOUND 300 s per mount | 327-332 s PASS (0.89.1, s65g/s66a-c: B refused at 30 s or completed at 164 s; A refused at 137-152 s); 340 s PASS (0.89.4 9FE0EA9A, s67j) |
| cluster_reset_n.sh 16 (infra, not a criterion) | parallel destroy/start ~5s + boot-to-ssh ~25s + prep ~5s + parallel verify ~2s | n/a | **75s** | 35s (sess17 run14d) |
| net2_gate1 (clyde user-mode; tests/net2/gate1_wire.sh) | harness clean build ~1s; kernel `make modules` compile-check 262s incremental (recorded, not budgeted in-gate) | 4 scenarios (goldens+1e5 fuzz+tlv+fault) <1s ⇒ ×2 | **30s** | 1s harness (0.11.0, 2026-07-17) |
| net2_gate2 user-mode (clyde; tests/net2/gate2_midcomms.sh) | 2 harness clean builds (normal+ASan) ~10s; kernel compile-check 262s (recorded, not budgeted in-gate) | 19-scenario §13.1 matrix ×3 seeds + real-time subset + ASan sweep, 27s measured ⇒ tightened from provisional 60 | **45s** (scenario phase) | 29s scen / 4s build (0.11.2, 2026-07-17); 27s at 0.11.1; 39s at 0.11.5 (matrix re-pinned to `run midcomms` after steps 4-5 grew `run all` to 38 scenarios) |
| net2_gate2 kernel smoke (test1+test2; gate2_midcomms.sh --kernel-smoke) | reset ×2 fast path ~7s (umount+rmmod+NFS-ensure; power-cycle fallback +~50s/node is a diagnosable FAIL, smoke nodes are idle) + insmod ×2 ~4s | 16-msg echo both ways + PONG-from-cb + full ACK coverage + 3s linger ×2 + marker harvest (3s poll); native LAN RTT sub-second ⇒ provisional was 180 | **60s** | 13s 2-node PASS (0.11.2 EAE6D695, 2026-07-17; run-1 FAIL was the pre-linger teardown race, test-driver bug) |
| first clean kernel build (clyde; make clean+modules) | full-tree compile+link (recorded reference, not a criterion) | n/a | **525s** (2× the 262s near-full incremental) | 267s (0.11.2 tree, 2026-07-17) |
| net2_gate3 CAW sanity (test1+test2; tests/net2/gate3_cawsanity.sh) | run.sh 2/caw forced prep 18s measured (incl. parallel extras teardown; MXFS_DEV=/dev/mapper/mpatha) | posix_multi + dlm_fairness manifest budgets 30s each (measured 3s/2s) | **120s** (provisional 300 tightened toward 32s actual; power-cycle-escalation variance retained) | 32s PASS (0.11.3 9D2672E5, 2026-07-17) |
| net2_gate4 (clyde user-mode; tests/net2/gate4_shard.sh) | 2 harness clean builds (normal+ASan) ~10s | 11-scenario §13.2 shard group ×(default+3 seeds), scenarios carry multi-second settle sleeps (~45s/group), + ASan full-suite sweep; 199s measured ⇒ tightened from provisional 620 (success.md said "provisional build + 900") | **300s** (scenario phase) | 199s scen / 7s build (0.11.4, 2026-07-17); 210s at 0.11.5 (ASan full suite grew to 38 scenarios with the mepoch group) |
| net2_gate5 (clyde user-mode; tests/net2/gate5_mepoch.sh) | 2 harness clean builds (normal+ASan) ~10s | 8-scenario §7.C mepoch group ×(default+3 seeds) + N2_DEBUG pass + ASan full-suite sweep; 108s measured ⇒ success.md provisional 120 pins with ~11% headroom | **120s** (scenario phase) | 108s scen / 8-9s build (0.11.5, 2026-07-18) |
| mkfs_timing (1) | 10s ssh+open | 1.2s | **30s** | (record) |
| crash_audit (2/tcp and 2/cawd, host row, terminal; tests/death/crash_audit.sh; on CAW the oracle's plain arm, the same death-detection and replay shape — measured 134 s PASS on 2/cawd, 0.90.7 07C5251E, run 20260926T184907Z, replay 71 s from the kill in the run before) | the tcp_death_replay.sh plain lap (setup ~10 s + 6 s writing + ~62 s death detection + fence/seal/replay ~15-25 s + verify ~10 s + victim restart ~60 s; measured 167-169 s) + stat of the replayed files ~3 s + the survivor's lone unmount typ 3 s (bound 120) + chk_mxfs -v cold 10-35 s (bound 120) + geometry ~2 s | — (the replay is the measurement) | **300s** (the oracle's own 240 s bound + the measured tail; was a derived 440) | 131s PASS (0.89.10 9DEAC25C, run 20260919T195545Z: oracle 124 s acked=354 replay 74 s, unmount 1.9 s, chk 2.1 s) |
| alloc_witness (2) | 6 barriers ~12 s + clock exchange 3 s + NFS record ~5 s | phase 1 burst 25 s (fixed window) + phase 2-3 creates/unlinks ~7 s + phase 4 cohort create+stat ~4 s, unlink ~3 s, per-target empty wait ≤ 30 s (measured 0 s: sync had already inactivated the cohort), bounded reuse creates ~2 s + settle 3 s | **120s** (≈ 58 s × 2, the 30 s empty wait being a bound and not an expectation; measured 38 s and 38 s at 2/tcp on 0.89.10, runs 20260919T185101Z and 185343Z; 36 s at 2/cawd on 0.90.7, run 20260926T184907Z) | 38s |
| chk_clean (2) | 30s mounts | 10s | **60s** | (record) |
| cluster_ops_timing (4) | 30s | 30s mount cycles | **90s** | (record) |
| dkms_install (1) | 30s | 120s module compile | **240s** | (record) |
| dmesg_clean (4) | 20s ssh | 5s grep | **45s** | (record) |
| online_membership (3) | 45s | 15s | **90s** | (record) |
| online_resize (1) | 30s | 20s resize+md5 | **75s** | (record) |
| cache_caps (1) | 30s | 30s | **75s** | (record) |
| wedged_unmount (4) | 60s | 30s cycles | **120s** | (record) |
| posix_semantics (1) | 60s mount | 45s (12 tests, 22s measured) | **120s** | 22s tests (sess129) |
| posix_semantics (16) | 150s 16-node mount | 240s suite | **420s** | (record; tighten) |
| cache_coherency (4) | 110s (power-cycle+mount) | 120s (4 sub-tests) | **300s** | (record; passed <590s sess130) |
| strong_consistency (4) | 70s | 60s (3 sub-tests, writes are ~3s) | **180s** | (record; passed <590s sess130) |
| zero_silent_loss (16, 3 iters) | 3× per-iter full remount (umount+rmmod+mkfs+16 joins, ~40s/iter) | 3× storm+verify (~90s/iter measured; SUCCESS_CRITERIA per-iter ceiling = 5 min structural break) | **480s** | 355s total, iters 107/119/119s, PASS 0 loss (sess17 run14d, build 9C2D4FA6) |
| crash_consistency (2 and 4) | 95s (mount ~25s + writes ~15s + fixed sleep-60 in script + writer reboot ~20s overlaps) | 30s (detect 16s + purge ~13s + replay 0.2s + read) | **150s** | 106-108s at 2 and 4 nodes ×3 PASS (sess18, build CB1C5FEF, v0.5.0 foreign replay + lease_timeout_ms=16000) |
| fence_during_write (4) | 150s (fence + recover) | 30s | **210s** | (record) |
| tcp_death_replay.sh plain lap (2/tcp, tests/tcp_2node_death_chain.sh) | setup ~10s + write 6s + death detection ~62s + fence/seal/replay ~25s + verify ~10s + victim restart ~60s | replay wait 150s from the kill | **240s** (TDR_LAP_BOUND) | 167-169s PASS (0.73.2 E6082040, s505b; 0.73.0 B516, s505a) |
| tcp_death_replay.sh released-tenure image arms (TDR_FALSE_APPLY=1, =2 re-hold, =3 pinned tail) | plain lap without its KILL_AFTER window (the victim's PRE adds are its last transactions, the kill follows W's writes at once) + the =3 pin handshake on V (pin file create, knob set over ssh, re-dirty: ≤ 5s, two 20s waits) + W's four creates in the victim-logged directory (~1s, waited on the victim's PRE acks ≤ 20s) + the re-hold create on V (≤ 60s bound, ~1s) + a cold remount of W as the last member (umount ≤ 120s, remount ≤ 180s: its own pages are taken over, measured 2.7s + 1.6s s593g) + one verify ≤ 90s | replay wait 150s from the kill (measured 74s s593g, 73s s593h, 78s s594a) | **540s** | 170s s593h (=1, 17/17 cold), 213s s594a (=2, 18/18 cold; the three gate-restore assertions fail on the D-0962 takeover pace: recovery-complete landed 104s after the replay, past the 60s restore wait) |
| tcp_death_replay.sh RECOVERY_BLOCKED arm (TDR_BLOCK_INJECT=1, TDR_BLOCK_AFTER_MS=20000) | plain lap + block bound 120s from the kill (death ~62s + 20s series + backoff/jitter) + one 30s re-drive after the clear | replay wait 150s from the injection clear | **400s** (TDR_LAP_BOUND=400) | (record on 0.74.0) |
| tcp_2node_death_chain.sh lap (prep + plain oracle), 0.74.1 s507b | prep 2/tcp 47-50s + oracle 168-171s | as above | 555s per lap (300 prep + 240 oracle + 15) | 3/3 PASS 216-221s per lap; a lap that overruns the oracle bound leaves the victim VM OFF (the restart is the oracle's last step) |
| transport_conformance.sh (0.75.0) | 9 mount/umount cycles: TCP join 5-15s, CAW form ~10s, refused mount <1s, umount ~5s, rmmod/insmod ~3s + 26s of settle sleeps | — | **240s** | (record on first PASS) |
| d513_write_eio_containment.sh D513_ARM=verify D513_SKIP_CONTROL=1 (2/tcp) | load 20s + kill + TCP death ~40-62s + fence/replay/publish | RECOVERY_WAIT 150s | **230s** (arm 2 skipped) | (record on first PASS) |
| tcp_lockreq_blackhole.sh (2/tcp, one wait: WORKLOAD=open, held_fd_read or held_fd_write, ARMED_S=300) | candidate search ≤ 8 × 13s + rewrite/arm ~10s + recovery ≤ 60s + captures ~20s | one acquire budget = 3 × 60 × 1s = 180s, inside the 300s armed window | **560s** (search 104 + 300 + 60 + 20 = 484, +slack) | 389-403s, 4 laps PASS (0.84.2 4AF63181, s586a/b/c/e; candidate found first try, 13s) |
| tcp_lockreq_blackhole.sh (2/tcp, two serial waits: WORKLOAD=held_fd — md5sum fstats then reads, each a fallible acquire, ARMED_S=420) | as above | 2 × 180s inside the 420s window | **640s** (104 + 420 + 60 + 20 = 604, +slack) | 528s PASS (0.84.2 4AF63181, s586h) |
| tcp_lockreq_blackhole.sh (2/tcp, WORKLOAD=dir_lookup or held_fd_dio_unaligned, ARMED_S=300; D-0958) | as the directory row (dir_lookup) / as the one-wait file row plus a 4 × 1 MiB fallocate per candidate (held_fd_dio_unaligned) | one acquire budget = 180s inside the 300s window | **560s** | 435s PASS (0.84.13 C91D38D9, s596c dir_lookup, refused at stage=refresh 185s after the first drop); 412s fails=4 (s596d held_fd_dio_unaligned: harness opened inside the armed command, refusal landed on open; arm rewired in 0.84.14) |
| tcp_lockreq_blackhole.sh (2/tcp, one wait on a DIRECTORY: WORKLOAD=dir_create, dir_unlink, dir_rename, dir_link or dir_symlink, ARMED_S=300; D-0958) | directory candidates: 8 × 400 creates on H ~45s + search ≤ 8 × 13s + revoke/re-cache/arm ~10s + recovery ≤ 60s + four cold name checks ~15s + captures ~20s | one acquire budget = 180s inside the 300s window | **560s** (45 + 104 + 300 + 60 + 35 = 544, +slack; the second candidate was the remote one: 98s search) | 495s PASS (0.84.11 340A625F, s595a create); 494s / 446s / 454s / 444s PASS (0.84.12 1FD01072, s595d unlink, s595e rename, s595f link, s595g symlink) |
| depart_takeover_unmount.sh (2/tcp, DEATH=ghost EXPECT=clean NFILES=16000) | B unmount ≤ 40s + 16000 lone-node creates ~5-8s + A unmount <1s + A lone mount ~2s + in-flight detection ~12s + unmount poll ~22s + re-form (settle takeover ~13s + sweep of ~15k pages ~157s + join) ~180s + reads ~1s | the takeover-only pass (~15k pages × ~9 ms) is what the unmount cuts short; the sweep of its remainder is the workload of the re-form | **420s** (measured 277s × 1.5) | 239-283s, s588b/c/d/e (0.84.3 F8FE750A); s588e 0-fail 277s — those laps' ~15k pages were an aged ledger's residue, not the creates: a lone mount records no grant, and on a freshly prepared filesystem the same ordering gave the pass 10 pages (s67l ABORT, 0.89.4 9FE0EA9A: P-TAUTH-TAKEOVER cand=10 in 2.7 s) |
| depart_takeover_unmount.sh (2/tcp, DEATH=ghost EXPECT=clean, NFILES=8000 through the capture gate; 0.89.5 ordering: creates under two members, then B leaves) | creates 8000 × 14 ms under grants ~115s (bound 380) + B unmount handing ~500 pages ~20s (bound 120) + A unmount ~10s + A lone mount ~2s + in-flight detection ~12s (two 5 s samples past 50 activations) + unmount poll ~22s + re-form (settle takeover + sweep of the ~500 remaining pages ~5s + join) ~120s + reads ~2s | the takeover-only pass of ~1000 pages × ~30 ms ≈ 30 s is what the unmount cuts short at ~12 s | **1000s** (measured 664s × 1.5; the manifest carries the header's per-step sum, 1930 s, because the re-form alone is bounded at 480 s) | 523s s68a EXPECT=observe, 664s s68b EXPECT=clean, both PASS fails=0 (0.89.5 harness on module 9FE0EA9A; s68a: 300 activations still arriving 12 s after the remount, the unmount interrupted the pass with pages remaining, no stuck worker, both nodes read every file) |
| depart_takeover_unmount.sh (2/tcp, DEATH=destroy, NFILES=16000) | creates ~172s + death detection ~62s + fence/replay ~25s + pass 117s (runs inside the recovery; put_super waits for it) + B boot ~30s + re-form ~30s | — | **700s** (measured 505s × 1.4) | 505s s588a (0.84.3 F8FE750A): the fix's path is unreachable in this shape (the interruption assertions fail by design; the arm records the ordering) |
| join_during_takeover.sh (2/tcp, EXPECT=clean ARM=ondemand, NFILES=32000) | per iteration: the authority under two members (a stat of all 32000 entries, one grant each at ~7-12 ms: measured 233s and 370s, s592b; creates on a fresh directory ~10s; bound NFILES/25+60) + B unmount ≤ 120s (measured 44-47s handing ~18.5k pages back) + A unmount ~3-4s + A lone mount ~2s + in-flight detection ~11s + B's join mount (bound 90s, measured 3s) + captures ~10s; the lap repeats up to ITER_MAX (6) iterations until the wanted master locality (a per-incarnation coin flip) is met | the bootstrap serves the requested page on demand, ahead of an ~18.5k-page × ~18 ms pass (measured 327-350s) | **700s per iteration** (400 + 60 + 5 + 12 + 90 + 60 reads + captures); wrap a lap at 6 × 700 = 4200s | 45s s590h (1 iteration, directory reused on an aged ledger), 384s s590d (1 iteration, fresh directory) — 0.84.5 496F48F8; the authority step was added after those; 282s PASS s593c (1 iteration, shape A: stat 200s, B unmount 42s, B mount 3.0s) — 0.84.8 7166251E; 103 s PASS s67m (NFILES=4000 through the capture gate, 1 iteration: creates 57.7 s, B unmount 9.3 s, pass in flight at B's mount, activations 333 at issue / 407 at return / 496 total, B mount 3.0 s) — 0.89.4 9FE0EA9A |
| d0932_platter_fallback.sh (2/tcp, HOLD_MS=120000; the platter-judge leg of D-0932) | prep ~50s (bound 300) + A parks on its intent inside the 31 × 2s dead window ~120s (bound 180) + B destroy/start/boot ~150s + NFS + module copy ~30s + the STAGING mount, which must ABORT at the barrier's 122s bound (bound 200: a staging mount that succeeds is a FAIL of the arm) + dumps ~10s + the JUDGE mount (siblings measured 86-89s; bound 300) + A boot ~150s + A join (bound 300) + captures ~30s | the judge's own fence, replay and publish of the victim, ~90s | **1300s** (≈1000s + slack) | 613s PASS (0.84.23 F1BFDAC2, s608c: park at +114s, staging abort 152s, judge mount 21.8s, A join 2.7s); 618s fails=2 on harness rows (s608b, 175B4482) |
| d0950_fence_guard.sh test1 test2 (2/tcp; the live-member fence guard, both arms) | 4 READ FULL STATUS captures ~1s each + 2 injected fence probes (one 5s settle each) + 2 writes | — | **240s** | ~20s PASS fails=0 (0.84.23 F1BFDAC2, s609a: live arm KEY_HELD_BY_LIVE_MEMBER(22), control arm KEY_ABSENT_UNPROVEN(6)); 0.78.1 C5EA9B6B (sess576) |
| tcp_2node_death_chain.sh lap, RECOVERY_BLOCKED arm (TDR_BLOCK_INJECT=1 TDR_LAP_BOUND=400) | prep 2/tcp ~150s + oracle: death ~62s + 20s series + backoff to the blocked verdict (measured 89s from the kill) + one 30s re-drive after the clear + replay ≤150s + verify + victim restart | as the plain lap | **750s** (300 prep + 400 oracle + 50) | 330s PASS fails=0 (0.84.23 F1BFDAC2, s609b: prep 156s, oracle 174s, blocked at +89s, replay 39s after the clear, 318 files) |
| d_intents_2tcp_open_efi.sh MODE=complete (2/tcp; the victim dies inside an EFD hold so its slice carries an open EFI; the survivor completes the case and the consequence on both nodes is measured; CHURN=0 or 1) | file build ~3 s + publish ~3 s + hold wait <=30 s + heartbeat expiry ~62 s + fence/replay ~15-25 s + engine <=5 s + probes <=40 s + victim restart ~60 s + victim mount <=60 s + captures ~10 s | — | **240s** (measured 136-139 s × 1.75; the election wait after the kill is 63-66 s of it) | 142s CHURN=1 / 145s CHURN=0 PASS fails=0 (0.85.1 8330C6DF, s614f/s614e, run back-to-back after a custodian-kill lap on the same prep: 2/2 freed, platter FREE, 458 churn rounds 0 errors, victim rejoined in ~5 s); 136s CHURN=1 / 139s CHURN=0 PASS fails=0 (0.85.0 F2428B3F, s613a/s613b); on the aliasing build 3A5A2BD7 the CHURN=1 arm never completed (s612c) |
| d_intents_2tcp_open_efi.sh MODE=custodian_kill (2/tcp; the custodian is destroyed inside the engine hold after entry 0 commits; both nodes restart and the case must be taken over) | ~100 s to the custodian's death + V restart ~15 s + V mount (dead-gate window ~64 s + fence, replay and takeover; measured 150 s) + W restart ~15 s + W mount (5 s once the gate is restored, up to ~90 s when W is the first node back) + engine <1 s + free-query 1 s + probes ~40 s + captures ~10 s | — | **480s** (measured 319-323 s × 1.5; the harness's own bound is 600 s) | 323s PASS fails=0 (0.85.1 8330C6DF, s614d: V remounted in 151 s after proving the dead gate holder over a 64 s window, took its case over, successor read entry 0 FULL and freed 13/13 remaining of 14, platter FREE, W remounted in 7.6 s). Before it: 319s (B0ADC2E2, s614c: same path, fails=1 on the entry-0 FULL assertion — the custodian's commit had not been forced to its log before the kill; the knob forces it since 8330C6DF). Earlier on this row: 601s FAIL rc=124 (0.85.0 F2428B3F, s613c: neither node remounted — V refused under the dead custodian's WE(1) in 2.7 s, W's barrier expired at 158 s); 601s FAIL (s614a, fix B only: W's predecessor recheck lapsed under the re-proved gate); 601s FAIL (s614b: V's preempt misreported a reservation conflict as rc=280, W mounted but the barrier's OPEN-case handoff was zeroed after mountfs so the engine never ran) |
| d0346_reuse_dir_mkdir.sh (2/tcp, 10 rounds; a peer's mkdir under a directory the other node just recreated on a reused inode number; the creator's destage of the new dinode is held PAUSE_MS=3000 by the iflush-pause knob so the reader deterministically reads the free image) | per round 7 ssh round trips ~0.4s + mkdir/touch x3/rm -rf/mkdir/stat on the creator + stat x4/ls/mkdir on the reader (native XFS < 100 ms) + the 3 s hold the reader's coordination waits out + a dmesg capture ~1s; bound 20s per round | — | **240s** (10 × 20 + precondition + captures) | ~60s: s610d control on 0.84.23 F1BFDAC2 FAIL 10/10 rounds (poison=1 refuse=1 each, wall 5-6 s); s610e on 0.84.24 5891B234 PASS 10/10 (coord=1 x2, defer=1 x8, wall 5-6 s) |
| join_during_takeover.sh (2/tcp, EXPECT=clean ARM=nodemand) | as above; from 0.84.8 B's mount is held at the settle gate until the incumbent installs the two-node view, which under the knob waits for the pass to reach the SB summary lock's page (~16k pages at ~13 ms: install 214s s593b; the gate refuses at its 60s backstop up to three times, the untrusted iget retries) — bound NFILES/50+60 = 700s at NFILES=32000; measured 220s, 215s | the pass itself | **1100s per iteration** (400 + 700); wrap a lap at 6 × 1100 = 6600s | 395s s590i (0.84.5, before the authority step); 0.84.8 7166251E s593b: two iterations at ~520s each (stat 220-255s, B mount 215-220s), lap stopped by hand before its verdict; 510s PASS s593f (1 iteration, shape B: stat 207s, B mount 221s) |
| join_during_takeover.sh (2/tcp, EXPECT=clean ARM=stall, 0.84.8) | as above; B is held at the gate (the incumbent's install waits on the paused pass), so each of the untrusted iget's 5 budgets is a 60s gate refusal of the non-blocking AG probe plus one of the blocking acquire: refusal ≤ 5 × 120 = 600s (MB=660), then the unwind ≤ 30s, the pass remainder after the knobs clear ≤ NFILES/50+120, the second mount ≤ 90s | the gate's backstop | **1400s per iteration** (400 + 660 + 30 + 220 + 90); wrap a lap at 6 × 1400 = 8400s | 1192s PASS s593d (1 iteration, shape gate: stat 219s, refusal at 628s, pass remainder ~260s, second mount 3.1s) — 0.84.8 7166251E |
| join_during_takeover.sh (2/tcp, EXPECT=clean ARM=stall) | as above + pass held 45s/page from in-flight + refused mount ≤ 120s (refusal logged 53-76s after issue, the command back 1s later) + pass remainder after the knobs clear (≤ NFILES/50+120 = 440s; measured ~255s) + second mount ≤ 90s (measured 3-7s) | 30s no-progress watchdog | **1200s per iteration** (measured 782s × 1.5); wrap a lap at 6 × 1200 = 7200s | 1424s PASS s592b (2 iterations: A then the wanted B; 782s + 642s) — 0.84.6 3A1CA4F0 |
| scripts/module_swap_deploy.sh 2 tcp (infra: re-form the 2-node TCP fleet on the tree's build, fs preserved) | teardown of both nodes ≤ 90s each in parallel + module unload (74s measured s593 when the unmount had a takeover in flight) + test1 prep ≤ 180s + the join wait for test1's orphan sweep (its takeover of its predecessor's pages first: 91s for 9.7k pages, then the sweep; the pattern was seen 180s and ~220s after formation) + test2 prep ≤ 180s | — | **720s** (90 + 90 + 180 + 240 wait measured×1.1 + 120); the script's own bounds sum to ~1000s and cap it | 236s (s592), 416s (s593 probe build); a 480s wrapper cut the next one at the join wait (s593, deploy_0848_s593.log: rc=124, test2 left unloaded) |
| join_during_takeover.sh (2/tcp, EXPECT=death, the control on a pre-0.84.5 build) | as ondemand + B's shutdown/withdraw ~20s + re-form via module_swap_deploy.sh (join waits for the sweep, ≤ 480s) | — | **2460s** (creates bound 700 on a fresh directory + 120 + 180 + 180 + 240 + 380 + 480 + 180) | (record on first PASS) |
| tcp_lockreq_blackhole.sh (2/tcp, one wait through a held fd: WORKLOAD=held_fd_chmod, held_fd_fallocate, held_fd_getxattr, held_fd_listxattr, held_fd_setxattr or held_fd_removexattr, ARMED_S=300; D-0958) | as the one-wait file row; the driver (tests/held_fd_op.py) opens O_RDWR before the fault and, for getxattr/listxattr/removexattr, sets user.d958 first (one EX, landed before H's rewrite) | one acquire budget = 180s inside the 300s window | **560s** | 0.84.15 5C4B9279: s601a chmod, s601b fallocate PASS (refused inside the window); 0.84.19 A089BB5F: s606b getxattr 442s, refused at +277s, fails=2 on the harness's own getfattr capture (fixed); 0.84.20 0B489997: s606g getxattr, s606h listxattr, s606j removexattr PASS; 0.84.21 EC736FCE: s607b setxattr PASS (stage=set), s607k held_fd_setxattr_nofork 396s PASS (refused at stage=addfork between +162s and +231s, has_af=0 on the kernel's path line) |
| tcp_lockreq_blackhole.sh (2/tcp, one page fault through a held mapping: WORKLOAD=held_fd_mmap_read or held_fd_mmap_write, ARMED_S=300; D-0958) | as the one-wait file row; the driver maps the file before the fault and forks the faulting child; the write arm adds one re-cache read on W (< 1 s) and one cold head on H | one acquire budget = 180s inside the 300s window | **560s** | 0.84.21 EC736FCE: s607c mmap_read PASS (stage=read-hold, child SIGBUS), s607d mmap_write PASS (refused at the read half's read-hold; the write-side stages are reached only when the read half is a cached fast path) |
| tcp_lockreq_blackhole.sh (2/tcp, WORKLOAD=held_fd_truncate EXPECT=degraded, ARMED_S=300; the residual class) | as above | the wait is KEPT for the whole window by design; the truncate lands after the disarm | **560s** | 0.84.15 5C4B9279: s601g PASS (parked 300s, DEGRADED at 45s, landed after the disarm) |
| live_holder_wait.sh (2/tcp, PAUSE_MS=240000, MASTER=remote, with or without KILL_AFTER_S) | setup ~5s + candidate search ≤ 8 × 7s + captures ~10s | PAUSE_MS + drain < 10s | **480s** (56 + 240 + 10 + 10 = 316, ×1.5) | 264-274s PASS (0.84.0-0.84.2: s585b/f, s586f/g) |
| live_holder_wait.sh TCP-fault arm (TCP_FAULT_S=25 at TCP_FAULT_AT_S=60, PAUSE_MS=240000; D-0958) | the plain lap + three bounded ssh calls for the rules (≤ 45s) + the detached reader's collection poll (≤ the read bound) | PAUSE_MS + drain < 10s; the fault must end ≥ 30s before the pause | **480s** (the fault sits inside the wait it does not lengthen) | 284s (s594c, 0.84.9 5A0C7F40; fails=1 on a bounced pre-wait grant, the wait itself clean) |
| live_holder_wait.sh RW=write (PAUSE_MS=240000; the write control for D-0958) | the plain lap + one md5 read on H after W's return (≤ 30s) | PAUSE_MS + drain < 10s | **480s** | 278s PASS (s594e, 0.84.10 FF25B785) |
| live_holder_wait.sh RW=chmod, fallocate, getxattr, listxattr, setxattr, removexattr, setxattr_nofork, mmap_read or mmap_write (PAUSE_MS=240000; the held-fd attribute and fault controls for D-0958) | the plain lap + the parked driver's open (and the xattr set) before the re-dirty + one cold stat/getfattr and md5 on H after W's return (≤ 30s); the pause knob is cleared on H at W's return, before that cold pass | PAUSE_MS + drain < 10s | **480s** | 0.84.15 5C4B9279: 245s PASS (s601e chmod), 243s PASS (s601f fallocate); 0.84.21 EC736FCE: 272s PASS (s607l getxattr), 269s PASS (s607m setxattr), 270s PASS (s607n mmap_read), 273s PASS (s607o mmap_write, H's first bytes cold = W's store), 270s PASS (s607p setxattr_nofork), s607f listxattr and s607h removexattr PASS; s606k-n and s607e/g/i/j landed but scored the harness's own cold capture (walls 311-320s: the still-armed pause knob parked H's re-release inside the capture) |
| live_holder_wait.sh RW=lookup TARGET=dir / RW=dio_unaligned (PAUSE_MS=240000; the 0.84.13 controls for D-0958) | the plain lap (directory candidates for lookup; fallocated file candidates and a 1-block re-dirty for dio_unaligned) + one md5/listing on H after W's return (≤ 30s) | PAUSE_MS + drain < 10s | **480s** | 268s PASS (s596e lookup, waited 245s), 276s PASS (s596f dio_unaligned, waited 241s, 4096 bytes landed) — 0.84.13 C91D38D9 |
| d0963_sf_lagging_flush.sh (2/tcp, LAPS=3 N=64 PAUSE_MS=3000, MODE=fix or control; D-0963) | per lap: setup ~3s + 64 creates ~1s + ~57 removals to shortform ~2s (a platter read each under sf_fastpath_adopt) + the held write PAUSE_MS + 1s landing + two removals + sync ~1s + cold verify on both nodes ~3s + ssh ~4s ≈ 18s | — (the pause is the measurement) | **180s** (3 × 18 = 54, ×3 for the rig's ssh jitter) | 71s control (s605d, 3/3 reproduced), 53s / 56s fix (s605e, s605f, 3/3 clean) — 0.84.18 6BAF3685 |
| d0964_chk_dangling_dirent.sh (2/tcp; D-0964, the chk_mxfs directory-entry walk) | identity + srcgate ~6s; phase 1: 1903 creates ~10s + sync + two unmounts ~2s + chk offline ~15s + two mounts ~10s; phase 2: one control lap of d0963_sf_lagging_flush ~18s + two unmounts + three chk runs ~45s ≈ 125s | the checker's dinode reads (1903 × 512 B, ≤ 2s native) | **300s** | 103s PASS (s62c, 0.88.1 tools, module 9A5DB6C7; leaves the fleet unmounted — prep after) |
| d0977_open_unlink_tcp.sh (2/tcp; D-0977, open-holder marks on the ledger) | arm A: victim create ~5s + holder launch 2s + unlink and 20 creates ~10s + held-fd read/write ~2s + 20 creates ~8s + the reap poll after the last close ≤ 70s (first retry 5s, then every 30s) + integrity sweep ~5s ≈ 105s; arm B (both master faces): ≤ 8 short victims × ~16s = 128s (victims 1-2 reuse the number, victim 3+ take a spacer while a face is missing; each victim also reads B's ring for the eviction-ring poison check); arm D (a fresh open on the number the peer reused): creates until reuse ≤ 40s + open/read 5s = 45s; arm C (registry off): ~25s; two dmesg windows ~6s ≈ 310s | the creates and 4 KiB reads (≤ 3s native) | **340s** | s171a-c (0.89.76, arm B with the ring checks and spacers, 2-3 victims): 83-84s wall each; s172a-c (4 victims): 90-92s; s65c (all four arms, 0.89.1): PASS, 82s wall; s65b (arms A+B+C): 68s |
| d0977_opener_death.sh (2/tcp; D-0977, the fence-strip face: the opener is destroyed holding the unlinked file) | create + hold 8s + unlink and 20 creates 10s + kill 2s + recovery ≤ RECOVERY_BOUND 240s + reap poll ≤ REUSE_BOUND 90s (first retry 5s, then every 30s, after the purge) + VM boot to ssh ≤ BOOT_BOUND 180s + re-prep ≤ 150s + checks 15s ≈ 700s; every bound is the harness's own, so it self-terminates — run it under nohup and wait with a ≤ 590s tail --pid, never inside one Bash call (600s cap) | the creates and 4 KiB reads (≤ 3s native); the rest is recovery and a VM boot | **700s** | s65d (0.89.1): PASS, recovery 52s, reuse 5s after it, B's ssh up 26s after start, whole lap under 590s |
| d0963_cc_laps.sh (2/tcp, LAPS=20, MODE=fix or control; D-0963) | per lap: run.sh preflight + marker + one cache_coherency (8-16s) + two dmesg windows ≈ 33s | run.sh enforces the criterion's own 60s | **900s** (20 × 33 = 660, +slack); never wrap run.sh in a timeout | 666s control (s605b, 0/20 reproduced on the quiet rig), 668s fix (s605g, 20/20 PASS, own-image arm not reached) — 0.84.18 |
| live_holder_wait.sh RW=create|unlink|rename|link|symlink TARGET=dir (PAUSE_MS=240000; the namespace controls for D-0958) | the plain lap with directory candidates (mkdir + entry, probe = an entry added on H and a listing on W) + one cold listing and two name checks on H after W's return (≤ 40s) | PAUSE_MS + drain < 10s | **480s** | 266s PASS (s595c create, 0.84.11 340A625F); 269s / 269s / 269s / 270s PASS (s595h unlink, s595i rename, s595j link, s595k symlink, 0.84.12 1FD01072); s595b aborted at setup with the pause armed before H's re-dirty (fixed in the harness) |
| tcp_stale_resend.sh (2/tcp, CONTROL=0 the fix / CONTROL=1 the bounce on the same build; D-0958) | preflight ~10s + 8 candidates ~5s + search ≤ 8 × 13s + read/rewrite ~5s + settle 8s + captures ~10s | the stale copy follows W's release within one re-send cadence (1s) | **140s** | 51s / 51s PASS (0.84.13 C91D38D9, s596a fix: refused by name, 0 bounces; s596b control: 0 refusals, 1 bounce; the second candidate was the remote one, 28s search) |
| d0946_recycle_platter_assert.sh (2/tcp, MXFS_D0946_ARM=fix, ROUNDS=6 FILES=400; D-0946) | preflight ~10s + priming 400 fallocates ~5s + 6 rounds × (800 free+create pairs: 3.9-4.7s measured tight on 0.75.121, +1 plain platter read per create ≈ +2.5s) ≤ 6 × 8s + cold listing on the peer ~5s + captures ~10s | the assertion is a read per create, never a wait | **180s** (10 + 5 + 48 + 5 + 10 = 78, ×2 for ssh dispatch) | 62s PASS, rounds 5.9-6.4s (0.84.17 22D9C2BB, s603c) |
| d0946_recycle_platter_assert.sh (2/tcp, MXFS_D0946_ARM=control; D-0946) | as above, but the chain fires on the first re-pick of round 1 and the round then runs its remaining creates against the dead filesystem (~2s) | — | **120s** (preflight + priming + one round + captures, ×2) | 14s PASS (s603d: fired at the first re-pick, 2.2s round); the fleet must be re-prepped afterwards (prep 43-137s) |
| d0949_sole_survivor_chunkfree.sh (2/tcp, NFILES=12000, carving ~62 new chunks per lap on a volume the previous laps left at 4032/8064 inodes; D-0949, D-0957's cold check) | preflight ~5s + creates 61-90s (4000/8000/12000 files, 62 chunks carved each lap; 12000 files with the chunks already carved measured 85.5s) + B umount ~5s + rm 18-21s + 15s settle + A umount, cold chk_mxfs and two remounts ~30s + across-mount arm (A umount/mount, 4000 creates ~30s, rm, 15s settle, B remount) ~60s | a create-heavy lap with no waits; chunk carving is the cost | **414s** (276s × 1.5) | 206s / 241s / 276s PASS, chk_mxfs clean, 0 P-ALLOC-FREE-CORE (0.85.1 8330C6DF, s615a/b/c, fresh mkfs, three consecutive laps) |
| d0946_disklive_knob_vs_aging.sh (2/tcp, MXFS_D0946_SOLE=umount MXFS_D0946_KNOB=partial_iwrite_sole, 8 × 400 tight, A/B alternation or MXFS_D0946_ARM=1; D-0955, D-0957's cold check from 0.85.2) | preflight ~10s + aging 600+600 fallocates 15-28s + B umount ~5s + sole wait ≤ 5s + 8 rounds × 3-5s + B remount ~5s + cold readback ~5s + cold check: A umount (measured 35-80s with a live peer: the per-page authority handoff, D-A-CLEAN-UNMOUNT-OF-ONE-NODE-WHILE-ITS-PEER) + B umount ~4s + chk_mxfs ~10s + two mounts ~20s | the rounds are create/remove pairs with no waits | **360s** (238s × 1.5) | 203s (A/B, s615d) / 238s (ARM=1, s615e) PASS, chk_mxfs clean, 0 P-ALLOC-FREE-CORE, NLDIRSKIP=0, 8/8 cold (0.85.1 8330C6DF); 107s on 0.75.128 without the cold check (s574iwr) |
| d0946_disklive_knob_vs_aging.sh (2/tcp, `<label> 8|14|4 300 tight`, dbg_force_sparse_carve=2 on the fixed walk, =0 natural, =2 + dbg_dialloc_pick_holes=1 control; D-0948's sparse-hole A/B, cold check at the end) | as above with 300 files: rounds 3-5s on the fixed walk; under the control walk every pick visits up to 32 hole offsets and each first visit costs a validator read and a NOMAGIC refusal, so a round runs 5-20s | the rounds are create/remove pairs with no waits | **330s** (the 14-round natural lap: 185s × 1.5, rounded to the 300-file shape) | 114s fixed 8 rounds (s615i: 6690 masked records, 0 hole picks) / 185s natural 14 rounds (s615k: 276 masked, 0 hole picks) / 155s control 4 rounds (s615j: 597920 hole visits, 72 NOMAGIC refusals, no shutdown); all three chk_mxfs clean (0.85.3 414769E4, fresh mkfs, one volume) |
| d0952_sole_create_rejoin_coherency.sh (2/tcp, `<label> control|sole|lone 200`; D-0952's publication gap, D-0956's lone remount) | preflight ~5s + (sole: B umount with A live ≤ 80s, the per-page authority handoff; lone: B umount ≤ 80s + A umount ~3s + A mount ~5s) + 200 creates ~3s + 100 recycles ~1s + 200 links, 200 symlinks, 100 rename pairs ~4s + B mount ~5s + three 200-file read passes and two write passes ~10s + (lone only) cold check: B umount ≤ 80s, A umount ~3s, chk_mxfs ~10s, two mounts ~10s | the reads are the measurement; nothing waits | **300s** control and sole (≈110s worst × 2 + ssh), **420s** lone (≈210s worst × 2) | 0.85.5 45B8EB0F (D-0966 fix, every arm ends in the cold check): sole 61/53/70/89s (s617a/b/c/g, all reads 200/200, P-TAUTH-ADOPT-LOCAL=1 each, cold clean), lone 75s (s617d), control 47s (s617e). Before: 31s control (s616a) / 70s lone (s616b, s616c) on 0.85.3 414769E4; **sole s616d FAIL at 300s**: B rejoined in 6s and its listing of A's directory then hung on a PR acquire of that inode (P36-STACK ino=2133 five times at 62s intervals) |
| single_node_paired (1) | 60s (2 mkfs+mounts) | 20s (2 rsyncs ≤5s + verify) | **90s** | (record) |
| rsync_paired (4) | 90s | 45s (ref + 4 paired rsyncs) | **150s** | (record) |
| scaling_curve (16) | 180s | 120s (rsync rounds at 1..16) | **330s** | (record) |
| dir_reuse_coherency (<=4) | shared mount ~5s | 24 rounds x N*NFILES concurrent same-dir create + cold verify + rm/recreate | **300s** | 4-node=144s 4/4 PASS (sess21, build 8D9D586E) |
| dir_reuse_coherency (>4) | shared mount | workload is O(N): every node creates DRC_NFILES into ONE shared dir/round so wall ~linear with N. NO native-XFS equivalent (XFS is not clustered); cost is NECESSARY coherent FUA I/O for concurrent same-dir adds (must read fresh leaf+data to avoid bestfree double-alloc) not waste -- see ccmemory sess21-dir_reuse-8node-speed-is-fundamental. Budget=60*N gives the 8-node case LESS relative headroom than 300s gives 4-node (144s actual). | **tcp: 100*N (8->800s); caw: 140*N (8->1120s)** | sess13(a9a03929) build 3D4A350E: 8-node=~530s standalone 8/8 PASS (round pace 10.5-25s, create wave ~15s = ~19ms/create-handoff; +30-60% vs sess21's 332s from the sess8-13 coherency pipeline [publish-before-notify, per-commit durable signal, FIX-C/D/E] — load-bearing correctness work, perf debt tracked via P131/P138 stage probes). Prior: 332s standalone (sess21). sess6(186320ae) 8/CAW build 57773CBD: steady 40s/round (create 9-16s, verify 4-14s, rm ~21s = ~26ms/unlink) -> ~1000s projected for 24 rounds. PROVEN BY INSTRUMENT structural: dirop_durable_caw=0 A/B halved the create wave but round 17 durably lost a dirent cluster-wide (799/800 on all 8 nodes) — CAW coherency is FUA-read (platter) based, so the per-op platter publish IS the pace. caw 140*N = floor x ~1.12; record the healthy PASS wall and tighten. |
| soak (4) | exempt | duration test (SOAK_HOURS by design) | 1h+5m | n/a |

verify_ship.sh end-to-end (no soak): sum ≈ **55 min**.  Run it with
that budget, not "unlimited".

Internal-timeout debt (these mask slowness and violate the same
principle; reduce as they are exercised):
- `tests/lib/common.sh` barrier_wait: 120s.  Healthy barrier
  convergence is ms; ssh launch skew is seconds.  Should be ≤15s.
- MXFS_CAW_WAIT_TIMEOUT_MS=120000: a lock wait near this value is a
  structural failure long before the timeout fires.

## 2026-07-18 (ccloop 72513a13) — condition-ladder budget derivations

| Criterion | Derivation | BUDGET | Measured basis |
|---|---|---|---|
| fio_perf (N nodes, any CAW rig) | fixed per-node byte load through ONE fixed-bandwidth target ⇒ wall ~ N | **30×N s** (manifest scale=linear) | 1n=14s; 32n dm-multipath=328s; 32n single-path direct: 26/32 done at 600s, projected ~650-900s |
| dlm_scaling per-node rate floor | collapse detector, NOT exact pace; structural CAW publish ~19-21 ms/op ⇒ ~50/s at N=32 | floor **50** (N≤16) / **30** (N>16) | 32-node healthy bands: direct 48-58 (median 54, all 32 nodes), mpath ~50-58 |

Rig-switch overhead (scripts/rig.sh, measured 2026-07-18): direct 32-node
transition ~3-4 min clean, ~7 min with mass power-cycle escalation.

## 2026-07-18 (ccloop 72513a13 sess2) — BUDGET BAR RESET (user directive)

**Directive (verbatim intent):** no test may take an hour or two, ever.  32
nodes of users reading/writing files must see their operations complete in
seconds-to-minutes or "they will never use it."  This is the budget rule
restated as the product requirement; budgets below are ENFORCED, and the
product must be fixed to meet them — budgets are never widened toward a
measured wall again (the dir_reuse 60*N→90*N→140*N history is the named
anti-pattern; the 140*N override in run.sh is DELETED, manifest authoritative).

| Test | New budget | Derivation |
|---|---|---|
| dir_reuse_coherency | 120s flat | clean EX handoff = 13ms (P138); rounds × N handoffs × 13ms × slop ⇒ rounds ~1s; 24 rounds ≤ 60s + barriers/margin |
| fio_perf | 120s flat | aggregate volume now N-independent (~16GB, per-node 2048/N MB clamped [64,1024]); LUN ~2GB/s ⇒ ~60-90s steady-state |
| cache_coherency | 60s flat | fixed per-node check count; wall was handoff tax, not work |
| zero_silent_loss | 60s flat | same |
| rsync_paired | 60s | 23s measured healthy; ×2 margin |
| whole 32-rung | ≤20 min | sum of the above + prep |
| whole ladder | <1 hour | |

Known product debt these budgets EXPOSE (task list, instrument-first sequence):
1. Per-op CAW dir durable-publish (~7-10ms × 800 ops/round = Road B pace
   tax).  A/B pending: newer guards (P25 window, P17B epoch, P22 torn-SF,
   sess61 merge, P150 read-preserve) may have made it redundant since the
   sess6 round-17 loss.  Release-path durable (per handoff) stays.
2. AG tenure starvation under write load (Phase-2 claim needs holders==0
   instant; bounded admission barrier designed, not landed).
3. Host-pressure sensitivity: LUN is vdisk_fileio in clyde page cache; swap
   full ⇒ guest I/O collapses.  Health-gate boards: swap used <1G, load <8
   before perf-sensitive chunks (hygiene: drop_caches + swapoff/swapon).

## dir_reuse_coherency — sess8 (ccloop 72513a13) calibration ledger, 120s-flat era
The 2026-07-18 sess2 reset made the manifest's 120s flat authoritative at
every N.  Measured 24-round calibrate walls on 0.11.31 (all functionally
145/145 green): 1-node **112s PASS**, 2-node 253s, 4-node 319s, 8-node
501s (sess6 record), 16-node (sess8 bg run — see criteria.json), 32-node
~32min projected (2-round run: 156s; steady round ~80s: create 26-39s /
verify 13-27s client-md5-bound / rm 28-34s rank1-solo at 8.75ms/unlink
file-inode teardown).  Analysis: per-round client work is O(N) (verify
md5s 2·N·NFILES files); a native-XFS 32-process equivalent of ONE round's
work is ~8s ⇒ 24 rounds ≈ 190s native > the 120s bar — i.e., at N≥2 the
flat bar is below the 2x-native-XFS ceiling formula.  The recorded
calibrate walls above are the honest product number; whether the bar
moves is a user decision (the budget rule forbids widening toward a wall, but the
native×2 formula is the budget rule's own ceiling standard).  FS-side debt that
remains real regardless: the 8.75ms/unlink teardown and the create-wave
rotation (both tracked in state.md SESS8).

## 32-node CAW budgets (sess30) — derived, not round numbers

Written down BEFORE the run, per the budget rule.  The criterion carries its own
internal budget (printed by run.sh as `[wall/budget]`); the COMMAND timeout is
that budget plus the 32-node harness fan-out, nothing more.

| Step | Criterion budget | Harness fan-out | COMMAND timeout | Measured wall (0.11.262-265) |
|---|---|---|---|---|
| `./run.sh 32 caw prep_cluster` | n/a | mkfs+mount+converge | **240s** | 72s, 73s clean; 132s / 201s when a node needed a power-cycle (VM boot ~40-50s) |
| `cache_coherency` | 60s | ~30s | **90s** | 25s, 26s, 25s |
| `dir_reuse_coherency` | 120s | ~30s | **150s** | 105s, 106s, 108s |
| `dirent_durability` | 240s | ~30s | **270s** | 65s, 66s, 65s |

sess30 correction: earlier calls in this session used 500-540s blanket timeouts
on these same steps — up to 7x the derived budget on a 72s prep.  The budget rule names
that a rule violation in itself, not merely wasteful: a blanket timeout cannot
FAIL a run for being slow, which is the whole point of the assertion.

### sess30 correction #2 — do not let the COMMAND timeout compete with run.sh

`run.sh` is itself the budget enforcer: it measures each criterion and prints
`[wall/budget]`, FAILing on overrun.  A command timeout set AT the criterion
budget therefore duplicates the assertion at a tighter value and kills the
harness mid-criterion — which leaves nodes unmounted and cascades into the next
run.  Measured: a 90s cap on `cache_coherency` (60s criterion budget + a GUESSED
30s fan-out) killed run.sh and left test6/test30/test32 without mxfs, so the
next run pre-asserted before it could measure anything.

Command timeout = criterion budget + measured 32-node fan-out (~30s) + one
power-cycle escalation (~50s, run.sh:433 destroy+start, parallel across nodes):

| Criterion | Criterion budget | COMMAND timeout |
|---|---|---|
| cache_coherency | 60s | **140s** |
| dir_reuse_coherency | 120s | **200s** |
| dirent_durability | 240s | **320s** |
| prep_cluster | n/a | **240s** |

The criterion budget stays the performance assertion.  The command timeout is a
BACKSTOP against an infinite hang, and must never be the thing that fails a run.

## Healthy-wall record — 2026-08-01, 0.11.317 board @ 32/caw (sess37)

Full 20/21 board (dir_reuse the only FAIL at 117s/120s — pace defect, open).
Actual walls vs budgets, for the budget rule tightening pass once a second healthy
board confirms them (do not tighten from one sample):

precond 1/10 · fio_perf 36/120 · cache_coherency 35/60 · strong 5/30 ·
posix_multi 8/30 · mmap 6/30 · zero_silent_loss 34/60 · dlm_fairness 22/30 ·
dlm_membership 6/30 · scaling_curve 42/90 · dlm_scaling 19/90 ·
rsync_paired 32/60 · crash_consistency 86/90 (thin — watch, do NOT widen) ·
fence_during_write 21/60 · fault_netpartition 10/60 · soak 31/60 ·
dirent_durability 67/240 · node_responsive 11/90 · kernel_health 3/120 ·
ag_strand_repair 81/240 · sustained_load 7/180 ·
dirent_publish_integrity 3/60 · dirent_type_integrity 4/60.

Candidates for tightening after confirmation: dirent_durability 240→120,
ag_strand_repair 240→160, sustained_load 180→60, kernel_health 120→30,
dlm_scaling 90→45, node_responsive 90→30.  crash_consistency runs 86-88s of
its 90s budget every board — its margin is the thinnest on the board and any
regression lands there first.

## D-513 forged-record probes (sess383, 2026-08-20) — MEASURED

`tests/d513_forged_record_checks.sh <shape>` forges an adversarial recovery
outcome record into an unused heartbeat slot, cycles ONE node's mount, and
asserts the disposition.  It is non-destructive: the other N-1 nodes stay
mounted, so it needs no re-prep.

Measured walls at 32/caw, 0.19.5 and 0.19.6:

- umount: ~1 s · forge/dump/restore (SG_IO round trip): ~1 s each
- mount that ABORTS on its first classification: **5-7 s**
- mount that ADMITS with an AG-scoped quarantine: **6-7 s**
- whole shape, end to end including the ssh fan-out: **13-20 s**

Budget: **60 s per shape** (`PER_SHAPE` in `tests/d513_forged_matrix.sh`).
That is ~3x the measured wall, and the failure it guards against is a wedged
mount, not a slow one — a shape that takes 60 s has not "nearly passed".

The two staged probes pay the dead-confirm window and are budgeted from it,
not from a round number:

- `tests/d513_lone_mount_refusal.sh` — the mount confirms a peer that was
  ALREADY frozen when we mounted, which costs dead_threshold heartbeat samples
  (~62 s at 31 x 2 s) by design, plus fence + the replay it refuses + the
  publish.  Budget **150 s**; the 62 s confirm dominates.
- `tests/d513_fswide_abort_preserves_death.sh` — two such mounts, each with
  the same ~62 s floor; the second also replays the victim's slice.
  Budget **150 s per mount**.

## 25-AG (agcount<nodes) acceptance lap — sess392/393, 0.23.0-0.23.1 @ 32/caw

`tests/ag_handoff_lap_sweep.sh LAP` = `d385 arm_lap TREATMENT LAP` (posix_multi +
rsync_paired + dir_reuse_coherency + dirent_durability) + a 32-node counter sweep.

| Step | Measured wall | Budget / timeout |
|---|---|---|
| `arm_prep TREATMENT` (MXFS_MKFS_OPTS="-d 50G", MXFS_FORCE_PREP=1, module redeploy) | 81, 81, 81, 84, 84 s (sess392); 119 s (sess393, new module) | PREP_TIMEOUT **170** (2× measured), outer 180 |
| d385 lap chunk (4 rows) | 273-334 s (rows: posix 6-9 s, rsync 19-41 s, drc 105-108 s, dd 64-66 s) | CHUNK_TIMEOUT **330**, outer 340 (never widen; a 334 s lap on 0.23.0 carried a test7 shutdown) |
| lap + sweep (the tool call) | ~440 s | **520 s** (lap cap 340 + 32-node sweep ~130 s + RESV per-node loop ~32 s) |
| rsync_paired row @ 25 AGs | 19-41 s (0.23.x) | 60 s board budget; acceptance = every node within 2× of the exclusive-node median |

## 2026-08-23 (sess401): run.sh per-invocation overhead MEASURED — 33 s + ~9 s/row

The "12 s × n_tests + 15 s startup" wrapper model under-counts today's rig.
Measured on 32/caw, 0.23.13, clean broker:

| invocation | test wall | total wall | overhead |
|---|---|---|---|
| `./run.sh 32 caw precond_readiness` | 2 s | 35 s | **33 s** per invocation (preflight ~8 s + broker hygiene probe 4 s + marker/PENDING/record fan-out) |
| `./run.sh 32 caw dirent_durability` | 64 s | 106 s | 42 s = 33 + **~9 s per row** |

Consequence: the d385 4-row chunk (posix_multi 7-17 s, rsync_paired 16-32 s,
dir_reuse_coherency 102-109 s, dirent_durability 64-67 s = 225 s worst case)
needs 225 + 33 + 4×9 = 294 s; its old 280 s bound killed every lap of the
sess401 board with the 4th row in flight and no row FAIL.  Re-derived to 295
in `tests/d385_publication_verify.sh`.

Broker hygiene trap (fixed in run.sh the same day): retained coord records grow
~64 per 2-row barrier lap; crossing the 200 threshold paid a FULL `-W 60`
absolute sweep (measured: 60 s even for 70 records; neither `-C` nor
`--retained-only` exits early).  Now `-W 5` per round (the loop re-probes).
Lap logs show which laps paid it: `grep sweeping lap.TREATMENT.*.log`.

Wrapper formula going forward: `sum(measured row walls) + 33 + 9 × n_rows`.
Re-measure the 33 s if preflight or hygiene changes.

## 2026-08-23 (sess402): A3-shape board chunk overran a 420 s bound — harness, not rows

`./run.sh 32 caw crash_consistency dir_reuse_coherency fence_during_write
fault_netpartition soak dirent_durability` on 0.23.15, fresh prep: rows
83 + 104 + 21 + 10 + 31 = 249 s, yet the 420 s wrapper expired BEFORE
dirent_durability started (cell ABORTED; the row itself PASSed 6x inside the
d385 laps the same hour, 64-66 s).  Overhead therefore >= 171 s for 5 rows:
33 s invocation + 5 x 9 s = 78 s, plus the three post-fault reconverge waits
(13 + 12 + 13 s) = 116 s, leaving >= 55 s unexplained.  Rule: chunks that
contain fault rows (fence_during_write, fault_netpartition, crash_consistency)
carry a reconverge term the "33 + 9/row" model omits; until the residue is
measured with per-row timestamps, do not put more than 4 rows in a fault
chunk, and derive = rows + 33 + 9/row + 15/fault-row + the measured residue.
crash_consistency FIRST run after a fresh prep is 80-88 s (creates 3200
dirents through one shared dir EX — D-401 / D-32NODE-SHARED-DIR-CREATE-PACE);
re-runs on a populated fs are 16 s.  Its 90 s budget is a budget assertion
the pace defect currently fails by a hair; do NOT widen it.

## 2026-08-23 (sess404): full 32/caw board in 5 chunks on 0.24.2 — measured walls

Derivation used: `rows(measured, or the enforced budget for rows near their
ceiling) + 33 + 9/row + 15/fault-row + 55 residue for the fault chunk`.
All five chunks completed inside their bounds (tests/evidence/sess404_v0242/board/):

| chunk | rows | bound | ACTUAL |
|---|---|---|---|
| prep | prep_cluster (fleet left unmounted by the kill harness) | 150 | **65** |
| c1 | precond_readiness fio_perf fio_perf_vs_xfs cache_coherency strong_consistency posix_multi mmap_coherency zero_silent_loss | 210 | **190** |
| c2 | dlm_fairness dlm_membership scaling_curve dlm_scaling rsync_paired | 160 | **148** |
| c3 | crash_consistency dir_reuse_coherency fence_during_write fault_netpartition (3 fault rows) | 410 | **341** |
| c4 | soak dirent_durability node_responsive kernel_health ag_strand_repair sustained_load | 295 | **273** |
| c5 | dirent_publish_integrity dirent_type_integrity open_defects dlm_lock_correctness (must follow c4, no re-prep) | 80 | **55** |

crash_consistency on the fresh prep again ran 86/90 s and rank 1 lost its
final barrier (D-401 shape, ledgered); dir_reuse_coherency 110/120 s.

## 2026-08-23 (sess409): kill-harness laps, rman matrix, A/B rows — measured walls

`tests/tmpfile_churn_kill.sh <label> test3,test4 0 2000 32` (instr=1, 2 victims),
0.26.5-0.26.7 (tests/evidence/sess409_cc/lap{2,3,4}.log): total **243 / 268 / 243 s**
= prep 89-97 s + post-prep 150-180 s (kills at +5/+11 s or +13/+19 s; recovery
wait 72-97 s after the last kill; umount 1-2 s; chk+restart ~15 s).  The 268 s
lap carried a 64 s survivor stall on a dead victim's parent-dir PR bit (the HB
expiry recovery window) — that is the lap's budget shape, not slack.  Bound
used: 560 s = prep bound 335 s (must exceed d385's PREP_TIMEOUT 320 s: a 200 s
outer bound orphaned a power-cycling prep and contaminated the next lap) +
post-prep 200 s + restart 25 s.  When prep takes the fast path (~90 s) a lap is
~245 s; the rman matrix wraps (260 s base arms) are therefore tight but held:
0.26.9 matrix arms measured **210 / 216 / 272 / 284 / 216 / 219 / 206 / 242 / 300 s**
(base_single, base_shared, inject1, inject2, inject3, mutate1, mutate2, busy,
takeover; tests/evidence/sess409_v0269/matrix.txt), whole matrix **36 min**.

`./run.sh 32 caw prep_cluster` alone: 63-79 s (fleet left unmounted).
`./run.sh 32 caw rsync_paired` (single row, prepped fleet): 16-18 s wall, 17-18 s
row (recorded 13 s on 0.26.4 the same day; the delta is present with
ccprev_enable=0 too — rig conditions, not the 0.26.5 create-path read).
`tests/tmpfile_churn.sh 32 200` pernode: 0.42-1.25 s/node mxfs (first run after
a prep 1.2-2.5 s), native 0.02 s — the D-400 budget failure unchanged.

## 2026-08-23 (sess409/410): `tests/fence_live_node.sh` arms — measured walls

Measured totals (tests/evidence/sess409_fln*.log): preempt idle **199 s**, preempt
churn **220 / 241 s**, hbpause churn **254 s** (withdraw at +68 s, recovery wait
expired at 95 s).  Prep inside the harness ranged **71-265 s** (fast path ~70-100 s;
power-cycle path 256 s) and is bounded at 335 s (d385 PREP_TIMEOUT 320 s — an
outer bound below it orphans the prep and contaminates the next lap).  Derived
outer bounds = prep bound 335 s + post-prep:
- hbpause: inject ack poll 12 s + withdraw wait 90 s + 6 s settle + recovery
  wait 95 s + sweeps/ssh ~30 s = **570 s**;
- logioerr (0.26.12): inject poll 12 s + withdraw wait 10 s + 6 s + recovery
  wait 95 s + ~30 s = **490 s**;
- preempt: 12 s + 75 s + 6 s + 95 s + 30 s = **555 s**.
A fast-prep run lands at 200-260 s; the extra is the prep's power-cycle path,
not slack (the sess409 360 s bound would have killed a 265 s-prep hbpause arm
mid-recovery-wait).

## sess411 (0.27.0): foreign-replay stabilization latency

D-527 fix adds a slice snapshot + stabilization gate in front of EVERY
foreign-slice replay: full 64MB slice read (~1-2s over iSCSI) + 
`fr_stab_passes`(2) compare passes at `fr_stab_interval_ms`(2000) spacing
= **~8-12s added between recovery election and "Starting recovery"** in
the good (already-quiet) case; a genuinely still-landing slice adds one
extra pass per landing burst; hard bound `fr_stab_deadline_ms`(45000)
after which the attempt aborts retryable (verdict NONE, re-election).
Consequence for harnesses: any window that starts at victim
withdraw/death and asserts "survivor recovery/release line" must carry
the +12s good-case (fence_live_node's 95s WAIT still fits) and must NOT
treat a P-FRSTAB-NOT-QUIESCED abort + re-election as a replay failure —
read the replayer capture before scoring. tmpfile_churn_kill's recovery
window bound (~120s) also still fits.

## Whole-cluster restart (bootstrap_full_restart.sh, 32/caw) — measured 2026-08-29

| build | mount wall | of which foreign replays | per-victim completion | notes |
|---|---|---|---|---|
| 0.51.0 (chain 32) | 545 s | 31 x ~4.5 s proof + replay | ~8.5 s purge scan (65536 x 512 B reads) | first end-to-end restart |
| 0.52.0 (chain 36) | **298 s** | 143 s (proofs still serial: single-entry prefetch never engaged) | 0.17 s (P-PURGE-DONE scan_ms p50 175) | D-0511 purge batch |
| 0.53.0 (chain 43) | **203 s** | ~41 s waited (depth-3 proof ring: 30/31 prefetched, waited_ms p50 462) | 0.17 s | D-0511 ring; also 206 s (chain 41) and 154 s-to-refusal (chain 46 negative arm) |

Bound derivation for 0.53.0 (sess446): two dead-window scans 129 s (fixed)
+ K own-log replay ~10 s + 31 slices x ~2 s (0.46 s proof wait + replay)
~62 s = ~200 s measured 203; the budget rule = fixed + 2x the variable part = 129 +
2 x 74 = **277 s → MOUNT_BOUND 300 s** (was 540), wrapper 840 s (was 1080).
A mount over 300 s is a budget failure to diagnose.  node_death_replay:
350 s (0.51.0) → 327 s (0.52.0) → shared lap 106 s / single lap FAILED
(D-0514, second victim's replay never started) on 0.53.0; the 470 s row
budget stands until chain 49 measures a PASS wall.

## domain_admission_matrix (sess447, 0.54.0)
Per row: rmmod (≤ 12 s retries) + insmod (~2 s) + mount attempt (refused < 1 s;
admitted join 5-15 s) + umount.  7 rows + leave + rejoin: harness bound 240 s.
Record the measured wall after the first clean PASS and tighten.

## domain_admission_matrix — measured (sess448, 0.54.0 production defaults)
Chain 55/56: 35 s and 34 s for 7/7.  Bound 240 → **120 s** is justified
(2 × 34 + rmmod-retry slack); chain 56 still ran 240.

## node_death_replay — measured (sess448, 0.54.0)
Chain 55 laps: 355 / 376 / 373 s of the 470 s row budget (both victims'
replays at +64…+72 s after the last kill).  Keep 470 until ten consecutive
PASS walls exist (chain 56 adds 7); then tighten toward 2 × the variable part.

## unlinker_death (tests/openunlink_deaths.sh) — measured (sess448)
Chain 56 lap 1: 186 s (bound 400).  Tighten after the ×10 streak.

## sess448 chain 58 (phase-5 remainder): rman_matrix 2500 s bound (measured
2217 s for 9 arms on 0.41.2), vergate LUN 300, bootstrap_full_restart 1080
(+ negative arm 1080, measured 189 s).

## ICLUS clean-release certificate LAB chains (sess448, 0.55.0)
chain 59 (tests/sess448_chain59_iclus_relmark_lab.sh): LAB build 300,
prep 300, NDR ×3 at 500 each, OUD ×2 at 400, production rebuild 300 + prep.
chain 60 (tests/iclus_relmark_faults.sh, 4 arms): crash arms 420 s wrap
(tmpfile_churn_kill 188-325 s measured + 60 s fault delay), no-crash arms
360 s; matrix bound 2000 s.  Record measured walls after the first clean run.

## Full 32/caw board — re-derived from the last conditions (sess449, 0.54.0)
`./showstat.sh 32 caw` ELAPSED column summed over the 29 rows (prep 111,
precond 2, fio 43, fio_vs_xfs 1, cache_coherency 27, strong 5, posix 7,
mmap 5, zsl 35, dlm_fairness 14, dlm_membership 4, scaling_curve 9,
dlm_scaling 14, rsync_paired 13, crash_consistency 88, dir_reuse 104,
fence_during_write 20, fault_netpartition 10, soak 31, dirent_durability 65,
node_responsive 12, kernel_health 3, ag_strand_repair 78, sustained_load 4,
dirent_publish 4, dirent_type 5, open_defects 1, dlm_lock_correctness 2,
node_death_replay 360) = **1077 s of row walls**.  Whole-board derivation
with the sess401/402 model: 1077 + 33 + 9×29 + 15×4 fault rows + 55 residue
= **1486 s** if run as one invocation — never do that; chunk it (≤4 rows per
fault chunk) and derive each chunk from its own rows.  The CLAUDE.md
figure "~690 s summed walls / ~12 min board" predates node_death_replay
(360 s) and ag_strand_repair (78 s) joining the board.

## relgate_fault_inject.sh inode mode (sess449 chain 65, 0.55.1)
Per stage: arm ~2 s + 15 s churn + 5 s settle + dmesg dump ~5 s ≈ 30 s;
3 stages × ≤2 cycles = 180 s + counters/liveness ≈ 20 s → **260 s** bound.
Record the measured wall after the first PASS.

## caw_samenode_selftest.sh (sess449 chain 66, 0.56.0)
Per arm: 2 s peer stagger + 8 s kernel hold (MXFS_SAMENODE_HOLD_MS) + owed
discharge ≤ 8 s + ssh ≈ 20 s; two arms + harvest ≈ 45 s → **90 s** bound.
Record the measured wall after the first PASS.

## d513_write_eio_containment.sh (sess449 chain 67, 0.57.0)
Arm 1 = 20 s inode load + kill + HB confirm ~62 s + fence + replay (injected
write failure) + publish + import inside a 150 s RECOVERY_WAIT + harvest;
arm 2 (live control) ≈ 30 s → **300 s** bound; chain adds victim restart
45 s + prep 300 per lap.  Record the measured wall after the first PASS.

## pr_unregister_fail_restamp.sh (sess449 chain 68, 0.58.0)
umount ≤ 15 s + WITHDRAWN first sight ≤ 5 s + fence + clean replay + purge
≈ 30 s (FENCE_WAIT 90) + prep_node remount ≈ 40 s + control umount/remount
≈ 60 s → **300 s** bound.  Measured 2026-09-18 on 2 nodes / TCP, 0.87.14
(`MXFS_TRANSPORT=tcp`, chain s53a): restamp mode 36 s, crash mode 81 s (the
30 s retirement grace is inside it).  Tightened: **restamp 90 s, crash 180 s**.

## depart_crash_cuts.sh (sess460 chain 86, 0.61.6; 2/tcp measured sess53)
Arm + umount-to-cut ≤ 20 s; cut 1 peers 62 s stale + fence + recovery; cuts
2/3 the 30 s RETIRE_PENDING grace + monitor lap + fence + recovery; cut 5 one
settle lap; then VM restart + ssh + prep_node.  Measured 2026-09-18 on
2 nodes / TCP, 0.87.14 (chain s53a): cut 1 115 s, cut 2 81 s, cut 3 81 s,
cut 5 39 s.  Bounds: **cut 1 240 s, cuts 2/3 170 s, cut 5 90 s**.

## d0356_stranded_prover_return.sh (sess53, 0.87.15)
prep 50 s + witnesses 10 s + the 62 s dead window until the intent and the
gate refusal + the departing node's unmount, which waits on the dead
victim's grants until the recovery-blocked cutoff (fence_blocked_after_ms,
120 s) answers EIO + victim boot ~140 s + lone mount (62 s stale window on
the departer + two fences + two replays) + rejoin + captures.  Measured
2026-09-18 on 2 nodes / TCP, 0.87.14 (s53d): unmount 115 s, lone mount
93.4 s, rejoin 2.8 s, whole lap 506 s.  Inner bounds: unmount 120 s (the
cutoff plus slack; a wall past it is the unmount waiting on something other
than the cutoff), lone mount 300 s, rejoin 300 s.  Whole lap **900 s**.
Measured 2026-09-19 on 0.89.3 / 0.89.4 (s67f, s67h, s67k): unmount
109-110 s, lone mount 27-29 s (one takeover of the relinquished attempt,
one boot-succession certificate, one replay), rejoin 2.7-3.8 s, whole lap
442-446 s (s67k PASS fails=0 on module 9FE0EA9A); the gate manifest's
healthy bound of 1420 s is tightened to **900 s** (this section's own
derivation, ≈2× the measured wall).

## lone_dir_block_authority.sh (sess54, 0.87.16)
Per arm: both nodes unmounted (typ 3 s, bound 90 s each) + mkfs 32 slices +
module reload + lone mount ~25 s (+ the peer's prep ~10 s) + mkdir + 40
creates + sync < 1 s + two journal captures ~5 s + unmount(s) ~3 s.  No
crash.  Measured 2026-09-18 on 2 nodes / TCP: lone arm 26-30 s, peer arm
35-40 s, both arms 70 s (s54c, 0.87.16).  Bound **200 s per arm, 400 s
both**.

## lone_mount_crash_replay.sh (sess54, 0.87.16)
Pre-unmounts (typ 3 s) + mkfs + lone mount ~24 s + witnesses (mkdir + 40
creates + 48 fallocates + sync) ~2 s + platter probes ~10 s + VM boot
~120-150 s (same-node arm only) + the recoverer's mount with the dead slice's
replay (62 s stale window + fence + replay; bound 180 s) + checks ~10 s +
the cold reader's boot (peer arm) or join ~10 s + unmounts ~6 s + chk_mxfs
~15 s.  Measured 2026-09-18 on 2 nodes / TCP, 0.87.16: same-node arm
272-288 s (s54d, s54o, s54t), peer arm 271 s (s54p).  Bound **560 s** either
arm.

## rig_lib_contract.sh (sess54, 0.87.17)
~14 short ssh round-trips (~1 s each) + two deliberate 3 s timeouts + one
unreachable-host name failure.  Measured 2026-09-18: 12 s (s54u, s54v).
Bound **90 s**.

## d0531_stale_slice_recovery.sh (sess53/54)
Per its header: prep U1 ~50 s + fill ~60 s + two unmounts + per arm mkfs +
lone mount ~25 s + witness ~2 s + dumps ~40 s + boot ~150 s + recovery
mount (bound 180 s) + unmount, ×2 + final prep.  Measured 2026-09-18,
0.87.16 (s54z): U1 through the control arm's ROW 438 s (the variant arm
aborted at its planted-image load, see the record).  Measured 2026-09-19,
0.88.0: two full laps, both arms through the final prep, 766 s (s61a, FAIL
on the variant) and 759 s (s61b, PASS); each arm's claim-time slice zero
adds ~4.3 s (P-SLIFE zero_ms) and each recovery's ~2.5 s.  Bound tightened
from 1400 s to **1000 s** (759 s plus the two VM boots' variance); an
injected-fault lap (MXFS_FAULT_UMOUNT_SRC) aborts at ~176 s and leaves the
victim destroyed — boot it before the next lap.

## sess470 harnesses (derived, to be tightened after the first healthy PASS)

| harness | budget | derivation |
|---|---|---|
| `tests/dirshard_stage1_selftest.sh N1 N2` | 240 s | 2 mkdir ioctls + ~1600 creates/lookups over ssh (native ≈ 20 s) ×2 + ~40 ssh round-trips × 2 s; the 0.64.6 lap hit rc=124 only because every op failed and the N=64 stage retried for 90 s — a healthy wall is expected well under 120 s; record it from chain 109 and tighten |
| `tests/d0527_untrusted_iget_peer.sh C P` | 60 s | 200 creates on C (≈1 s) + 8 handle opens on P with 2 s / 1 s pacing (≈13 s) + 8 ssh round-trips |
| `tests/d488_unlock_exit_arms.sh X Y arm` | 240 s | setup 8 creates + arm + Y 4 creates (healthy ≈1 s; REARM cadence bounded seconds; strand arm's readopt ≤ 3 s pending floor + 30 s latch watchdog) + 12 s re-verify settle + 16 + 2 creates + 4 dmesg captures + 2 slot dumps ≈ 90 s healthy; 240 s is the wedge bound, and any create past its own 70 s inner bound is the FAIL |
| chain 109 cc `sharded16` lap | 160 s | the crash_consistency row's 90 s manifest budget + prep-free harness overhead (12 s) + ssh fan-out; measured 62-77 s on 0.64.6 |

---

## Deriving a wrapper timeout for a `run.sh` chunk (moved out of CLAUDE.md, 2026-09-10)

MEASURED 2026-08-20 at 32 nodes:

    wrapper = sum(measured test walls) + 12s × n_tests + 15s startup

The `12s × n_tests` term is real harness overhead — ssh fan-out to 32 nodes,
coord-broker retained sweep, the criteria record — and it is exactly what a
"sum the walls" estimate misses. Verified both ways in one session: omitting it
made a 193s-of-tests chunk overrun a 254s wrapper; including it predicted 88s
for a chunk that ran 61s.

Get the measured walls from `tools/criteria.py <N> <dlm>` — it prints
`elapsed/budget` per row. **Sum the ELAPSED column, never the BUDGET column.**
Budgets are ceilings that already carry slack; summing ceilings and then padding
compounds the slack twice.

Reference point for scale: the whole 28-row 32/caw board is a ~12-minute job
(~690s of summed walls). A 10-minute wrapper on ONE chunk of it is off by
roughly 30×.

`run.sh` already enforces each test's budget from `tests/suite/manifest` as that
test's hard timeout, and already flips PASS→FAIL on `elapsed_s > budget_s`. An
outer `timeout` around it adds nothing except how long you sit on a wedge.

Padding is not free. A wedge is the normal failure mode on this rig, and the
padded number is exactly how long the session does nothing. A run that takes 8
minutes under a 10-minute wrapper also reads as success when it is a budget
failure.
