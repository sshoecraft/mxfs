<!-- sess132-133: D-PR-FENCE-PREEMPT-WITHOUT-ABORT in-flight exclusion test — SCST code proof, the design-consult rule test-design ruling, harness measuring the 12s violat… -->
# D-PR-FENCE-PREEMPT-WITHOUT-ABORT: in-flight-exclusion test design (sess132-133)

Step 4 of the ledger entry — "prove the in-flight write is excluded" — worked
through code proof, a the design-consult rule test-design ruling, and a working harness that
measured the actual defect, in one continuous arc.

## sess132 — SCST code proof + the `pr` trace channel `docs/history/docs/history/docs/history/compiled-fence-inflight-exclusion-test-design.md`

Read from `/src/scst`. Rig target is **SCST**, not LIO —
`vdisk_fileio`, `o_direct=1`, `threads_num=8`, PR state at
`/var/lib/scst/pr/mxfs`, one IQN, 64 sessions (32 nodes × 2 paths),
multipath `mpatha` per node. Established as CODE fact (hypothesis material,
still needing measurement): SCST's PREEMPT AND ABORT provably waits for the
victim's outstanding commands, all in core (`scst_pres.c`/`scst_targ.c`), not
handler code — `scst_pr_preempt_and_abort` overrides `cmd->scst_cmd_done`,
issues `SCST_PR_ABORT_ALL` per preempted registrant, and blocks on
`pr_aborting_cmpl` until `__scst_abort_task_set()` has marked every one of
the victim's commands aborted; the P&A's own SCSI status is deferred further
until the TM state machine passes both `WAITING_AFFECTED_CMDS_DONE` and
`_FINISHED`. Consequence to measure: a held victim write is expected to LAND
but strictly BEFORE the P&A returns — "bytes never on the platter" is not
achievable by any implementation (no target can un-submit a bio), so the
ledger's original wording is a shape suggestion, not the true invariant.
Handler difference is nil for this property: `vdisk_file_devtype` and
`vdisk_blk_devtype` share `vdisk_task_mgmt_fn_done` and neither defines
`task_mgmt_fn_received` — the abort/wait machinery is entirely core.

`pr` tracing enabled as a live on-wire evidence channel
(`echo "add pr" > .../trace_level`; measured 0 extra dmesg lines at rig
idle, verbose only during actual PR traffic — left ON deliberately to catch
the next real fence). Yields `scst_pr_do_preempt`'s literal `" and abort"`
string only for service action 0x05 (on-wire proof of which SA fired, no
sg_persist needed) and `scst_pr_abort_reg`'s abort count = the victim's
task-set size at the instant of the abort — direct target-side evidence of
in-flight state. Multipath/nexus scope resolved for production: SCST's
`scst_pr_find_registrants_list_key()` collects all registrants sharing a key,
so one P&A of a node's key aborts both of that node's sessions — the
"which path was preempted" ambiguity only matters for a purpose-built
single-path test LUN.

## sess132 — design-consult ruling: the proposed test is BLOCKED `docs/rulings/step4-inflight-exclusion-test-blocked.md`

Original proposal (dm-delay under a second vdisk_blockio LUN, held O_DIRECT
write, `sg_persist --preempt-abort`, poll the loop device, assert
`t_land<=t_return`, A/B 0x04 vs 0x05) ruled a discriminator concept but NOT
sufficient for the zero-defect bar closure. Four blockers: (1) `t_land<=t_return` is
weaker than the ledger's stated criterion ("bytes never on the platter") —
must record TWO separate properties (abort/cancellation: P never observed
after full drain; fence linearization: no victim modification after P&A
completion) and never silently score a pre-return landing as full PASS;
(2) `sg_persist` doesn't exercise the patched MXFS call chain — an sg_persist
PASS proves the target CAN provide the property when asked, not that
`fence_node()` reaches the patched function with `abort=true` on the right
device/path/key (sess132's code proof partially refutes the handler half of
this concern, but fileio must still be measured directly); (3) a 1-second
sleep is not evidence the write is in the target's task set — gate the P&A on
an OBSERVED in-flight state (SCST's own `scst_pr_abort_reg` trace line);
(4) cross-host `t_return` comparison via SSH-observed process exit is LATER
than the real ioctl return and can misclassify a post-return landing as
pre-return — timestamp the P&A's SCSI response on the same host that polls
the backing store.

Mandatory corrections: test vdisk_fileio (shipped handler), not only
blockio; eliminate multipath/nexus ambiguity with a dedicated single-session
test LUN; move W away from initiator timeout thresholds (use W=10-15s and
raise the test device's `/sys/block/*/device/timeout` to ≥120s); use aligned
O_DIRECT reads immediately below dm-delay (buffered reads of a loop device
have up to 5 cache aliases) with `losetup --direct-io=on` CONFIRMED, never
read the backing file buffered; run 0x04→0x05→0x04 so the discriminator is
shown not to evaporate after one trial; rule out write-never-admitted, wrong
path preempted, initiator-side SCSI EH masquerading as target cancellation,
and dm-delay flush/FUA reordering (validate the delay stack standalone
first). A below-delay sentinel can demonstrate clobbering but must not erase
the primary evidence.

Staged plan ruled: (1) harness feasibility on delayed blockio, single path —
not closure evidence, validates the method; (2) repeat on delayed
vdisk_fileio; (3) real MXFS fence with on-wire CDB capture; (4) closure rerun
of the unchanged acceptance criteria with all traces preserved.

## sess133 — harness built; 0x04 measured the defect; disposition amended `docs/history/docs/history/docs/history/compiled-fence-inflight-exclusion-test-design.md`

the design-consult rule disposition on the open question: FIXED AND VERIFIED is justified
"after the ledger criterion is formally corrected from cancellation to
linearization, the response boundary is measured at actual SCSI PR
completion, and the real MXFS replay gate is established." Replacement
criterion, verbatim: *"Once PREEMPT AND ABORT has successfully completed, no
command belonging to a preempted victim nexus may subsequently modify the
protected medium."* Property (A) cancellation is NOT what SCSI P&A promises
(terminate/drain, not undo) — the ledger entry was formally amended, old text
retained as withdrawn, not silently reread. Added mandatory closure
requirements: **C1** boundary measured at real PR completion on a common
monotonic timeline; **C2** property (C) CONTINUED EXCLUSION — a post-fence
victim write must get RESERVATION CONFLICT; **C3** prove the survivor doesn't
replay early (expected to FAIL on the shipped build since
`mxfs_disklock_recovery_fence_certify()` has zero callers — a separate open
defect, D-FENCED-STAGE-WITHOUT-PROVEN-EXCLUSION).

Conservative-boundary trick that solved C1 cheaply: `trace_clock=mono` makes
ftrace timestamps directly comparable to userspace `clock_gettime`, and the
boundary is picked PER ARM so each direction is conservative without tracing
the whole response path — 0x05 arm boundary = ftrace entry of
`scst_cmd_done_pr_preempt` (earlier than wire GOOD, so "landed before" is
stricter); 0x04 arm boundary = userspace PROUT return (later than wire GOOD,
so "landed after" is stricter).

Harness built in `tests/fence_inflight/` (the source-tree rule): `prprobe.c` (SG_IO probe
with controlled timeout — sg_persist 0.67 has none and sysfs device timeout
doesn't govern SG_IO), `stack.sh` (preallocated image → loop
`--direct-io=on` → dm-delay → SCST vdisk_blockio `fencedelay` → dedicated
IQN, two local iSCSI sessions on distinct ifaces — production LUN untouched),
`inflight_ab.sh` + `verdict.py`. Confirmed on the rig: two distinct I_T
nexuses at the target (distinct TransportIDs/ISIDs), target offers WE-RO
(type 5), harness mirrors production's REGISTER+RESERVE
`PR_WRITE_EXCLUSIVE_REG_ONLY` shape, delay stack validated standalone at
12097ms for W=12000ms.

Two traps that cost a run each: (1) PROUT CLEAR posts a Unit Attention to the
OTHER nexus, so the victim's next REGISTER silently CHECK-CONDITIONs and
fails — fix with a `clearua` (TEST UNIT READY loop) after every CLEAR plus
explicit `good=1` assertions; (2) `/sys/block/dm-N/inflight` never rises for
deferred bio-based dm IO — the correct in-flight probe is SCST's own
`active_commands` count under the target's session dir, which is literally
the property the ruling demands, not a device-layer proxy.

**Result, 0x04 arm**: the defect MEASURED — victim write completed on the
lower device **12.089s AFTER** the PROUT 0x04 return (write submit +0.000239,
PROUT return +0.024972 GOOD in 0.311ms, lower-device write complete
+12.114131). `scst_pr_preempt_and_abort`/`scst_cmd_done_pr_preempt` did NOT
fire — target-side proof the service action really was plain PREEMPT.
Property (C) continued-exclusion PASSED independently (post-fence victim
write got RESERVATION_CONFLICT). Two scorer bugs found in `verdict.py`
(fix before next run): `EH_MARKERS` flags the RESERVATION CONFLICT that
property (C) deliberately provokes — exclude the expected one; and the
target-observed-SA check matches dmesg strings instead of the stronger
already-captured ftrace evidence (0x04 ⇒ `scst_pr_do_preempt` present AND
`scst_pr_preempt_and_abort` absent; 0x05 ⇒ both present).

Next steps queued: fix the two scorer bugs, run 0x05 then 0x04 again (ruled
order 0x04→0x05→0x04), then stage (ii) on vdisk_fileio, stage (iii) real-MXFS
on-wire capture, then C3's replay gate. `pr` tracing left on (0 lines/20s
idle cost). Teardown: `sudo bash tests/fence_inflight/stack.sh down`.
