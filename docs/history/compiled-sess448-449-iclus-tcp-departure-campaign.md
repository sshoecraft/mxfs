<!-- sess448-449: ICLUS RELMARK certificate landed+ruled, TCP transport refusal, INODE ticket-defer, same-node exerciser, 0.58.0 departure re-stamp ruled… -->
# sess448-449: ICLUS RELMARK certificate, TCP transport refusal, departure re-stamp campaign

Continuation of `docs/history/docs/history/compiled-sess445-447-defect-campaign.md`. Tree moved
0.54.0 (rig baseline, sv 2E283B58) -> 0.55.0 -> 0.55.1 -> 0.56.0 -> 0.57.0
-> 0.58.0, all landed UNBUILT and staged together, built once by the LAB
chain step. Discipline held throughout: chains 55-68 run under `setsid`,
each gated on the previous chain log printing `DONE`; no hand `make` in
`/src/mxfs` until the full queue finished. Chain liveness must be checked
via a `/proc/*/comm` scan for `sess44x_chainNN` — `mxfs_pgrep` pattern
counts self-match the calling shell and mean nothing
(`docs/history/docs/history/docs/history/compiled-sess448-449-iclus-tcp-departure-campaign.md`).

## ICLUS clean-release certificate (D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY)

GPT RULE-5 ruling (`docs/rulings/iclus-relmark-certificate-and-sequencing.md`)
set the shape: marker identity must equal token identity (full tuple
`{class,resource,lineage,grant_epoch,owner_slot,owner_epoch}` unique;
zero lineage fails closed). Land immediately in parallel with phase-5,
production `READY=0`, verified only via a compile-time LAB enable — never
a runtime bypass — with the validator's icluster arm dropped in a later
reviewed change. Irrevocability: no reinstall of an already-marked tuple
via any path (fast-admit, CAS, covered-inode authority install,
re-admission after the closing barrier); a failed/stale install must
never clear closing state. Listed 7 STOP-SHIP conditions for
`icluster_dlm=1` production (lineage-less tokens, INODE+base alias
without invariant, writes admitted after proof begins, any proof-failure
reaching unlock, reinstall of a marked tuple, marker not durably before
unlock, mixed-version activation).

Landed in 0.55.0
(`docs/history/docs/history/docs/history/compiled-sess448-449-iclus-tcp-departure-campaign.md`):
`ic->auth_lineage`/`relmark_*`, snapshot-lineage + reinstall refusal,
marker publish in `mxfs_iclus_disk_release` before the unlock CAS,
counters `iclus_marked`/`failed`/`reinst_ref`, `xfs_super.c
MXFS_ICLUS_RELMARK_READY` (0) gating the validator's icluster arm, plus
`MODULE_INFO(mxfs_iclus_relmark_lab)` in LAB builds — required because
srcversion hashes source, so a `-D` build is otherwise indistinguishable
from production. Scratch-compiled clean for both prod and
`KCFLAGS=-DMXFS_ICLUS_RELMARK_READY=1`
(`docs/history/docs/history/docs/history/compiled-sess448-449-iclus-tcp-departure-campaign.md`); build
trap hit and fixed en route: `b_hold` is a plain `unsigned int` in this
fork, not an atomic — no `atomic_read`. Fault-injection stages 19-21
(premark_crash/publish_fail/postmark_crash/cas_fail) added, exercised by
chain 60 (`docs/history/docs/history/docs/history/compiled-sess448-449-iclus-tcp-departure-campaign.md`).
Alongside it, a `P285-F4-BLI-FREED-OPEN` probe went into
`xfs_buf_item_relse` (`pal/linux/xfs_buf_item.c`) to chase the
GEN-OPEN-NOT-DIRTY f4truth residue (95 records, submit_gen=0, bli=0
clean); confirmed the F4 submit hook sits inside `xfs_buf_submit_bio`
(both `submit_ex` and delwri call it) so there is no bypass path — this
is registry-accounting debt, not a coherence defect, per the ruling.

F3 INODE-class unproved-CAS macro comment truth-up (macro stays 0) is a
prerequisite for D-0516, tracked but not itself the fix
(`docs/history/docs/history/docs/history/compiled-sess448-449-iclus-tcp-departure-campaign.md`).

Evidence trail: chain 55 NDR lap1 PASS (355s) with f4truth zero
REAL-UNSUBMITTED; laps 2-3 also PASS (376/373s), streak held at 3/3
(`docs/history/docs/history/docs/history/compiled-sess448-449-iclus-tcp-departure-campaign.md`,
`docs/history/docs/history/docs/history/compiled-sess448-449-iclus-tcp-departure-campaign.md`).
Chain 56 then ran domain matrix 7/7 + OUD x10 + NDR x7, reaching **NDR
10/10 consecutive and OUD 10/10** under production defaults on 0.54.0 —
closed **D-CROSSNODE-OPEN-UNLINK-DATA-LOSS FIXED AND VERIFIED**: root
cause was the default-off blanket refusal, fix was the 0.54.0 default
flip (`docs/history/docs/history/docs/history/compiled-sess448-449-iclus-tcp-departure-campaign.md`).
Chain 59 (LAB build, `icluster_dlm=1`, NDR x3 + OUD x2 with relmark
evidence) and chain 60 (fault matrix) queued to produce the positive
evidence needed before flipping `MXFS_ICLUS_RELMARK_READY=1` and
dropping the validator arm — that flip was still pending at sess449 END.

## dirent P6->P8 capture-scope artifact

Chain 57 failed `dirent_publish_integrity` + `dirent_type_integrity` on
24/32 nodes. Diagnosed as a capture-scope artifact, not a real defect:
test2..test9 were NDR victims rebooted after chain 55's
`dirent_durability` stamp, so their counters read zero and 8 nodes show
`window=0 win_src=none`
(`docs/history/docs/history/docs/history/compiled-sess448-449-iclus-tcp-departure-campaign.md`).
Chain 63 was written to re-run `dirent_durability` + both P8 rows in one
invocation to confirm before any disposition.

## TCP transport refusal

RULE-5 follow-up ruling: refuse the TCP transport based on the SELECTED
transport read after DLM init, RO mounts exempt, gated by a LAB macro.
Landed as `mxfs_transport_domain_admit` in `pal/linux/xfs_super.c`,
called after `mxfs_v5_dlm_init` and again on ro->rw remount; matrix row
R8 added; `docs/dlm-protocol.md` "Durability-domain admission" section;
D-0288 containment note filed
(`docs/history/docs/history/docs/history/compiled-sess448-449-iclus-tcp-departure-campaign.md`).
R8 verification against the 0.55.x production build was still owed at
sess448 END (`docs/history/docs/history/docs/history/compiled-sess448-449-iclus-tcp-departure-campaign.md`).

## INODE ticket-failure deferral (0.55.1)

`mxfs_relbar_close_or_defer` previously returned `false` on persistent
ticket failure, letting both unlock arms CAS unproved (sess258
telemetry exit). 0.55.1 changes this to defer: cert
`proof_failed`/`FLUSH_FAILED` + `DEMOTING` +
`mxfs_relbar_deferred++` + `P228-RELBAR-TICKET-DEFER`, returns `true`.
This is the D-0516 prerequisite.
`tests/relgate_fault_inject.sh` inode mode now FAILs if stage-10 hits
without the TICKET-DEFER line
(`docs/history/docs/history/docs/history/compiled-sess448-449-iclus-tcp-departure-campaign.md`).

## CAW same-node reconcile exerciser (0.56.0)

Added `mxfs_v5_dlm_caw_samenode_selftest` (modes 1 hold/2 collide/3
negative) plus test helpers `mxfs_dlm_caw_test_slot_bits`/
`_test_lreq_state`/`_test_arm_wait_expire[_left]` in `dlm_caw.c`, a
debugfs `caw_samenode_selftest` entry (removed early in `put_super` like
`pwtest`), and harness `tests/caw_samenode_selftest.sh`
(`docs/history/docs/history/docs/history/compiled-sess448-449-iclus-tcp-departure-campaign.md`).
GPT review found gaps: needed a mid-hold proof (pending + waiter bit
set), the negative control must show the waiter bit set before
injection and cleared after, and scenarios B/C need barrier hooks —
recorded as owed work against #6/#7, D-RECONCILE-EXHAUSTION-SILENT, and
D-TRACK-PUBLISH-ORDERING. Scenario B/C hooks landed in 0.57.0 as
`caw_inject_dow_pause_ms`/`caw_inject_owed_pause_ms`
(`P276-INJECT-DOW/OWED-PAUSE`)
(`docs/history/docs/history/docs/history/compiled-sess448-449-iclus-tcp-departure-campaign.md`).

## Write-EIO injection (0.57.0, D-513B)

`xfs_buf.c` knobs `freplay_inject_write_eio`/`buf_inject_write_eio_live`
(`P227-FR-INJECT-WRITE-EIO`) plus a generic
`mxfs_dlm_caw_test_arm`/`_knob_left` API, exercised by chain 67
(`docs/history/docs/history/docs/history/compiled-sess448-449-iclus-tcp-departure-campaign.md`).

## Operational trap: pgrep-loop kill of own shell

Killing PIDs collected from an `mxfs_pgrep` loop killed the agent's own
Bash shell — the search pattern matched the calling shell's own
`cmdline`. Must exclude `$$` and match `/proc/<pid>/cmdline` explicitly.
A `chmod +x` issued right after the kill silently never ran because the
shell was already dead, so the intended relaunch failed with no visible
error
(`docs/history/docs/history/docs/history/compiled-sess448-449-iclus-tcp-departure-campaign.md`).

## Departure re-stamp (0.58.0, D-0356/D-377) — landed then ruled insufficient

0.58.0 landed: `dlm/disklock.c
mxfs_disklock_restamp_withdrawn_after_release`; `slot_release_commit` no
longer destroys the slot directly, split into `_release_finish` +
`_restamp_unretired`; `pal/linux/xfs_super.c put_super` re-stamps on
P301 (unregister) failure (`P303-RETIRE-PENDING-RESTAMPED` /
`P303-DEPARTURE-INDETERMINATE`) and finishes on both paths; a
`dbg_pr_unregister_fail` one-shot knob added
(`docs/history/docs/history/docs/history/compiled-sess448-449-iclus-tcp-departure-campaign.md`).

GPT RULE-5 review at sess449 END ruled this **NOT sufficient**: the
RELEASED/EMPTY slot state is published *before* the PR key is proven
absent, so a crash between release and unregister leaves the key still
registered on a now-reusable EMPTY slot. Required redesign for 0.59.0
(`docs/history/docs/history/docs/history/compiled-sess448-449-iclus-tcp-departure-campaign.md`):
- New `MXFS_DISKLOCK_FLAG_RETIRE_PENDING` (value 4 — check the current
  flag list first) written by `mxfs_disklock_release_slot` instead of
  EMPTY; identity/epoch/`ident.pr_key` preserved; slot non-reusable by
  `claim_slot`; `hb_ident_fill` must be re-run (`hb_ident_crc` covers
  flags) and `hb_ident_observe` must accept the new state.
- Peer monitor on first sight of RETIRE_PENDING: a `key_present_fn`
  callback (wire like the existing `v5_prkey_present_cb` at
  `v5_mount.c:1655`) — key absent -> CAS to EMPTY
  (`P304-RETIRE-COMPLETED-BY-PEER`) then run the sess346 clean-depart
  arm (`hb_clean_empty_match` needs to accept RETIRE_PENDING too, or run
  after the CAS); key present past the grace deadline
  (`MXFS_PR_VERIFY_DEADLINE_MS` 20s + margin) -> treat as WITHDRAWN and
  fire the dead-node path (fence, clean replay, purge).
- Departing node's P301-failure path still re-stamps RETIRE_PENDING ->
  WITHDRAWN (adjust the accepted-image predicate from the 0.58.0 code).
- Lone/last-node and bootstrap: a RETIRE_PENDING slot with key absent is
  reclaimable after the mounter's own READ KEYS; key present routes to
  the existing dead-slot fence path.
- Test plan: extend `tests/pr_unregister_fail_restamp.sh` with a crash
  arm (knob skipping the re-stamp, modelling crash-after-RETIRE_PENDING
  — peers must fence+EMPTY) and a clean path exercising P304.

D-377 remaining items scoped: item 2 (local policy) = quarantine +
refuse remount until fence/absence is certified, explicitly NOT
alert-only; item 3 = admission must reject multipath `reservation_key`
config; item 4 = an operator-driven `chk_mxfs --preempt-key` with the
ruling's authority list is acceptable — no in-kernel reaper needed.

## Ledger state at sess449 END (63 open)

Closed F&V: D-CROSSNODE-OPEN-UNLINK-DATA-LOSS. Pending disposition:
D-0356 (F&V on 2/2 PASS), D-377 (phases i/iv/v landed, items 2-4 owed
per above), D-0516 (INODE deferral prerequisite chain), D-402 (F&V after
chain 63's re-run), D-MONITOR-INCARNATION-DOWNGRADE-TO-ZERO (closes on
chain 61 RESULT PASS both arms + P-HB-INC-ZERO present +
UNOBSERVED absent), D-0288 (TCP containment note), #1/#2 ICLUS
disposition review (owed: chain 58 phase-5 pieces, then review), #6/#7
same-node exerciser family (owed: chain 66b 3 laps + pair2 PASS
including scenarios B/C). A miner-built owed-work map of all 63 open
records exists only in the sess449 transcript (~16:50Z), not persisted
elsewhere.
