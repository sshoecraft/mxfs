---
name: ccloop-c7ee71c6-sess41-END-349-deaths-pass-multiopener-eio-open
description: sess41 END: 0.11.349 board 22/22 + both death cases PASS (C8+purge-fix+atomic-skip verified); OPEN: multi_opener/mmap_only B-side EIO undiagnosed
metadata:
  type: project
---

# sess41 (ccloop session 23) END — 0.11.349

## Verified this session (all with RULE-4 proof chains)
- 0.11.342/343: C1 (publish rides release CAS), C2 (recovery EX-fail ⇒ skip), C3 (open-at-NL
  closed via mxfs_dlm_open_protect), C4 (eager clear P91), C5 (B6 fail-closed), C10 (iclus
  mount gate), D-PEER-TRUNCATE **FIXED-VERIFIED** (post_release gates RELOAD-SIZE-DROP-SKIP;
  P96 adopt; trunc_legal/trunc_partial in matrix).
- 344-347: C8 survivor sweep through THREE proven leak roots → unlinker_death PASS
  (α-outcome: P89 free ~6s after close). Roots: dentry pin (retire entries + d_prune),
  flag-strip-by-reload (ADOPTED reap kind re-restores per retry; new MXFS_IF_ADOPTED_UNLINK
  bit 28 = B3/B4 authority WITHOUT P2L-OWNFREE), stale cached nlink (sweep enqueues every
  chained inode; worker coherence-ilock before checks).
- 348: opener_death root — purge skip predicates (3 sites in mxfs_dlm_caw_purge_node) missed
  open_holders&dead_mask → dead opener's bit never stripped → eternal defer. Fixed; case
  PASSES in 93s.
- 349: transaction-atomic untrusted replay (P227-FR-ATOMIC-SKIP; GPT-approved containment
  for the PROVEN half-applied-unlink tear). crash_consistency 204/204 still green with it.
  unlinker_death accepts α (swept+freed) / β (evaporated atomically) outcomes.
- Board 22/22 green on 349 (dir_reuse one-shot 7r pace jitter on HEALTHY host — noted under
  D-32NODE-SHARED-DIR-CREATE-PACE; immediate rerun 58/58). agi REPRO=NONE. openunlink_probe PASS.
- Infra: run.sh self-prunes /tmp/run_* (root fs hit 100%, freed 744GiB via
  tests/host_tmp_clean.sh). tests/openunlink_deaths.sh restart_node does full /src+iSCSI
  restore + prep_node rejoin (WORKS).

## OPEN INVESTIGATION (first thing next session)
openunlink_matrix multi_opener (ino=141) + mmap_only (ino=143) FAIL on 349: B(test2)'s rm
never happened — B's view of the case subtree returns EIO; A+C sides behaved perfectly
(P90/P91). B has ZERO dmesg lines for the victims. Suspect: parent-dir (ino=133)
P95-SAMETYPE-RELOAD with incore_gen!=disk_gen in the window (wrong-incarnation dir adoption
poisoning B's subtree). NOTE basic/reopen_nl/eager_clear/trunc PASSED same run; these two
cases were NEW-green on 343, so this may be a 344-349 regression OR a latent dir-incarnation
bug the longer matrix run exposes. Later probes were contaminated by concurrent
agi_bucket_repro (it resets mounts — never probe while it runs). NEXT: fresh prep → run
multi_opener ALONE → if B EIOs, catch first EIO producer (strace rm on B + dmesg watch;
inspect ino=133 adoption). Full ledger note under D-CROSSNODE-OPEN-UNLINK.

## Remaining program (8 OPEN)
C7 version gate (GPT: protocol-generation equality at slot claim + hello, envelope version
old code validates; design in transcript). C9 TCP open tracking (GPT-validated hybrid:
ensure-grant-at-open + publish-on-release + explicit last-close CLEAR + reconcile re-assert;
functional-testable on this rig via force_transport without recording matrix cells).
Foreign-replay authority protocol (atomic-skip is containment only; multi-trans ops still
tear at op granularity — ledgered). Then: INODE-CLUSTER-PUBLISH, READDIR-PACE (1.2s),
SHARED-DIR-PACE (42x), DIRVIEW-NONCONVERGE, MATRIX (cawd/cawp/tcp rig-blocked).
GPT rulings in memories: sess41-gpt-openunlink-audit-ruling + session transcript (Q1-Q3).
