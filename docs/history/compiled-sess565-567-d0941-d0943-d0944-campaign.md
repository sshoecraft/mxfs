<!-- sess565-567: D-0941 ESTALE-shell closed F&V (2 causes, A/B knob trap); D-0943 mount-panic fixed; D-0944 AG-0 quarantine root-narrowed, open. -->
# D-0941 / D-0943 / D-0944 — sess565-567 2-node TCP campaign

All three defects surfaced on the 2-node TCP rig within three sessions, two of
them (D-0941, D-0944) under harnesses that had been green for days. Filed and
closed/root-caused in this order.

## D-0941 — poisoned inode shell unretireable, ESTALE on existing files

sess565: `cache_coherency` at 2/tcp had 9 consecutive PASSes (2026-09-05 →
09-08, checks=534 passed=534) then failed 2 of 4 runs on 0.75.97. Filed as
`D-CACHE-COHERENCY-PEER-DIRENTS-INVISIBLE-2NODE-TCP-0941`
`docs/history/docs/history/docs/history/compiled-sess565-567-d0941-d0943-d0944-campaign.md`.
Symptom read as a shared-directory view lagging the peer across a barrier, both
create and delete directions (`exp=128 got=102` / `uv gone node2_fileN` still
present after sync+barrier). Host load, sess565's own AG-meta work, and a
leaf-hash hole (D-0496) were all measured and excluded. Filing note: the
harness's `ck` assertion names read backwards — a "gone" check FAIL means the
file is still present, not missing; read the harness line before trusting a
check name.

sess566: root cause proven wrong at the description level.
`docs/history/docs/history/docs/history/compiled-sess565-567-d0941-d0943-d0944-campaign.md` — the
directory view is correct; **lookup** fails with `-ESTALE` on files that exist
and whose dirents resolve. `mxfs_incarn_poison()` (`xfs/xfs_mxfs_dlm.c:26229`)
takes an `igrab()` and queues `mxfs_incarn_revoke_work_fn`, which only calls
`xfs_irele` once it runs — so a poisoned shell always carries exactly two
references until that work completes. Measured: poison→revocation latency
2.88–68.39 ms (10/10 samples); the retirement loop's entire budget was 23 µs,
four spins, zero delay. Not a race sometimes lost — a race that cannot be won.
Fix: own retry counter (previously shared with the `XFS_ISTALE_CAW` arm, so a
shell passing through both arrived with part of its budget already spent) plus
8 retries with escalating sleep (immediate, then 2/4/8/16/32/64/128 ms ≈
254 ms, ~3.7× worst measured latency). Fail-closed unchanged for a reference
that never drains (open fd on a dead incarnation).

sess567: a second, independent cause found under the same symptom.
`docs/history/docs/history/docs/history/compiled-sess565-567-d0941-d0943-d0944-campaign.md`
— an unrelated transient reference from the DLM BAST pipeline
(`mxfs_dlm_bast_work_fn` / `mxfs_dlm_bast_dwork_fn`) pushed `i_count` 2→3 at
try 8 and dropped it 10 ms later; the give-up line read `i_count=1 tries=9` —
the shell was retireable at the exact instant it was declared unretireable.
Lesson: a fixed try count is the wrong exit condition for a wait whose
references arrive from paths the loop does not control; the correct exit
condition is the one already being measured — the reference is gone. Fix
(0.75.106, `xfs/xfs_inode.c`): the drain-wait retires on its own observation
(watches `i_count` reach 1, then prunes / `xfs_irele` / retries the iget)
instead of falling through to `-ESTALE`, bounded by a separate `poison_drains`
counter (max 2).

Measurement trap hit while verifying both causes:
[[trap-a-fix-outside-the-ab-knob-turns-the-control-arm-into-a-second-treatment-arm]]
— the second-cause fix was added outside the `poison_retire_wait` A/B knob
(it lives in a different code block). Result: the 0.75.106 control arm
(`retire_wait=0`) stopped reproducing the defect at all (0.75.105 control
tracked `poison_n` 1:1 in 8/8 node-laps; 0.75.106 control showed 0). The
control had silently become a second treatment arm — it could not fail, so a
"clean control, clean fix" reading would have measured nothing. Rule: every
change that alters outcome — including a later fix for a different cause found
by the same investigation — goes behind the A/B knob. Corollary: a control arm
that goes clean after a code change is the first thing to distrust; diff what
moved between builds before believing any arm.

Closure: `docs/history/docs/history/docs/history/compiled-sess565-567-d0941-d0943-d0944-campaign.md`
— D-0941 closed FIXED AND VERIFIED on build 0.75.109 via a three-arm A/B
(control: neither fix, 8/8 node-laps unretired tracking poisons 1:1;
drain-retire only: 0/0 unretired, 138 DRAINRETIRE events; shipping default,
both fixes: 0/0 unretired, DRAINWAIT/DRAINRETIRE both 0 since the budget never
expires). General lesson distilled: one knob gating two independent fixes
makes the second unmeasurable — the shipping-default arm proves the pair
works but says nothing about either fix alone; isolating fix 2 required a
third knob configuration (sleep off, drain-retire on) to force the same
budget-expiry path the control takes.

Open design note (not yet resolved): the `XFS_ISTALE_CAW` arm
(`xfs_inode.c ~1853`, sess95) handles the same referenced/stale-generation
same-type-shell state with an in-place reload and its own comment says
eviction cannot fix a referenced inode — but the poison arm is checked first
(`~1613` vs `~1811`) and fails closed, so the arm with a working strategy is
never reached. Proposed: after the drain wait expires, fall back to a
same-type in-place reload gated on matching `S_IFMT`.

## D-0943 — NULL function-pointer panic during mount fencing window

sess567: the new `SOLO=1` arm of `tests/d0932_fence_takeover_probe.sh`
reported `RESULT: VACUOUS` — no evidence — because the node had actually
panicked and rebooted.
`docs/history/docs/history/docs/history/compiled-sess565-567-d0941-d0943-d0944-campaign.md`
Node journals are volatile; after reboot `journalctl -k` showed a fresh boot
with zero mxfs lines, reading exactly like "the workload never ran". The panic
survived only in the libvirt serial log
(`/var/log/libvirt/qemu/<node>-serial.log`) — a VACUOUS probe result must not
be believed until that log is checked.

Root cause, read directly from the oops (not inferred): `address 0x0` +
`supervisor instruction fetch` + `RIP=0x0` is a call through a NULL pointer.
`v5_dispatch_slice_recovery` (`dlm/v5_mount.c:8742`) has exactly two indirect
calls, both through `ctx->dead_node_notify_fn`, and documents the precondition
at `:8732` ("caller must have verified ... dead_node_notify_fn"). Three of
four call sites honor it; the fence-retry site at `:6421` — reached from a
kthread created at mount (`:6079`, hence `Comm: mxfs-worker`) — did not. The
hook is NULL for the entire mount window by design (registered by
`mxfs_dlm_cache_init`, which runs after `xfs_mountfs` returns; the window is
long on purpose — log recovery, the 62s barrier confirmation,
`xfs_log_mount_finish`). SOLO just parks the mount in that window for minutes,
so it hits every time; any mount long enough for an armed fence retry to
certify before `mxfs_dlm_cache_init` runs is exposed.

Fix (0.75.109, `dlm/v5_mount.c:6421`): do not dispatch when the hook is absent
(matching the pattern already used elsewhere in the file) and instead hand the
slot to the late-death mask via `mxfs_v5_dlm_mount_defer_late_deaths`, logging
`P567-FENCE-RETRY-DEFER`; Phase 3a of `mxfs_v5_dlm_mount_settle`
(`v5_dispatch_late_deaths`, `:10034`) elects a replayer once the mount is
live. A defensive NULL check inside `v5_dispatch_slice_recovery` itself was
deliberately rejected — it would absorb the precondition violation for every
caller instead of fixing the one that breaks it, and two simultaneous changes
would make neither attributable. Verification owed: node must not reboot
(probe now compares `boot_id` across the join), at least one
`P567-FENCE-RETRY-DEFER` line, and a subsequent `P233-MPHASE-DISPATCH` for
that slot (a node that survives but never replays the slice trades this
defect for a silent one).

## D-0944 — untokened freed btree buffers force ATOMIC-SKIP, quarantine AG 0

sess567: `tests/agmeta_shutdown_retire.sh` on 2-node TCP — injected log I/O
error kills node A mid-churn, A unloads and rejoins. Rejoin fails
**positionally**: the first shutdown arm after a fresh prep gets
`mount_rc=32`; every later arm in the same prep succeeds (2 of 2 reproduced).
`docs/history/docs/history/docs/history/compiled-sess565-567-d0941-d0943-d0944-campaign.md`
Chain: no PR key frozen for the incarnation (`NO_VICTIM_KEY`, the victim had
declared a **voluntary** death and its key was already preempted) → foreign
replay classifies the slice terminal-durable (`reason=1 domain=AG-MASK
ag_mask=0x1`) → refused slice is never replayed → AG 0 quarantined →
`Failed to read root inode 0x80, error 5`. AG 0 holds the root inode, so a
refusal there is indistinguishable from quarantining the whole filesystem —
nobody can mount. Central design question: a node that says goodbye is not a
node that needs proving dead, but the current fencing path treats it as one
once its key is gone. Possible duplicates to reconcile first:
`D-FOREIGN-REPLAY-REFUSAL-CLUSTERWIDE-SUICIDE-513`,
`D-QUARANTINED-SLOT-EXHAUSTS-CLUSTER-ADMISSION-376`. Method note: twice in one
session a harness summary line invented a cleaner result than the actual
verdict — here `rejoin=mount_rc=0` was printed for an arm that had failed at
`mount_rc=32`, because the summary grepped the first `mount_rc=` token out of
stdout and matched the assertion's own `want=` half instead of the observed
value. A summary must quote the underlying verdict, never re-derive it.

Narrowed: `docs/history/docs/history/docs/history/compiled-sess565-567-d0941-d0943-d0944-campaign.md`
— foreign replay tokenizes each logged item and ATOMIC-SKIPs the whole
transaction if any item is untokened. In the failing transaction, AG 0's
bnobt/cntbt root blocks (`blkno=8`/`16`) carry `class=1` and apply; other
blocks of the same trees (`blkno=80`/`88`, `blft=4` = `XFS_BLFT_BTREE_BUF`)
carry `class=0 lineage=0 gepoch=0 st=11` and are skipped. The refusal and
quarantine themselves are deliberate (sess233 incident-481 ruling: an
ATOMIC-SKIP can't undo a victim's partial AIL writeback, so publishing would
tear the platter) — do not patch that part; re-opens incident 481. The bug is
upstream: the harness grows-and-collapses one AG's free-space btrees, and
blocks freed by that collapse are logged via the binval/free path, which does
not go through normal AG-authority token assignment. Cross-links: `D-0402`
(`TMPFILE-CHURN-KILL-FOREIGN-REPLAY-EFSCORRUPTED`) is the same terminal shape
via a different injector, filed at 32/caw and wrongly scoped out of 2-node TCP
by every prior scope pass — concrete proof a 32-node-filed defect can
reproduce at 2 nodes. `D-0924` uses this same harness and leaks an `xfs_buf`
on these same freed btree buffers — treat as one investigation with D-0944.

Measured without any death or injection, 6662 samples in 13s:
`docs/history/docs/history/docs/history/compiled-sess565-567-d0941-d0943-d0944-campaign.md`
— on a fresh 2-node TCP cluster (0.75.109), `agmeta_stale_leak_2node.sh`
PASSes clean in 13s, yet on the node performing the btree collapse, 6662 of
27413 logged images (24.3%, all `BTREE`/`blft=4`) capture `MXFS_OWNAUTH_UNPUB`
authority (unpublished epoch) and **zero** durable — while the peer doing
ordinary alloc/unlink captures 26112/26114 durable. `AUTH_NOT_HELD` (one of
three outcomes stamped by `OWNAUTH_UNPUB`/`NONE`/`RELEASING`,
`pal/linux/xfs_buf_item.c:1039-1043`) is status 11 on the wire — exactly the
status on the images a peer's foreign replay refuses, forcing ATOMIC-SKIP →
quarantine. **The defect is present on 100% of laps**; the previously observed
3-of-7 rejoin-failure rate is a timing lottery on top of an always-true
condition — it only asks whether an `AUTH_NOT_HELD` image happened to sit in a
committed transaction at the instant of death. Never quote the rejoin rate as
the defect rate. Next measurement (no death needed): instrument the btree
collapse's AG-grant/epoch-publish window directly — does the collapse path
modify blocks between acquiring the AG grant and publishing its epoch, or does
publish never happen for this path? Cross-check: the `P239-OWNAUTH-NONDUR`
probe was added by sess467 for `D-FOREIGN-SLICE-INTENTS-ABANDONED`, which may
already own this population.
