---
name: compiled-fencing-replay-and-rig-notes
description: Replay-durability facts, the SCSI-PR fence retirement-witness design chain (s75-s83), plus 4 unrelated infra facts
metadata:
  type: project
tags: [compiled, fencing, scsi-pr, replay, recovery, rig-infra, design-ruling]
---

# Fencing/replay durability, plus unrelated rig-ops notes (assorted tail)

This group is the clusterer's leftover bin — no single topic covers all nine
inputs. Two real clusters sit inside it (foreign-slice replay durability, and
the SCSI-PR fencing/retirement-witness design chain that followed from it),
plus four standalone host/infra facts with nothing in common but having been
learned the hard way. Organized below by those actual groupings.

## Cluster 1: replay has no durable partial state

[[reference-a-foreign-slice-replay-writes-nothing-until-the-end-of-the-pass-so-there-is-no-incremental-durable-prefix]] —
On an MXFS untrusted/foreign replay, `xfs_log_recover.c` skips the mid-pass
`xfs_buf_delwri_submit` and instead does `log->l_mxfs_drain_deferred++`; every
replayed image stays in core until one `xfs_buf_delwri_submit` at the end of
`xlog_do_recovery_pass`. Reason: a mid-pass write can land an intermediate
image (tail transaction's chunks over a block the victim last flushed at the
head transaction) that fails the write verifier and gets the whole slice
refused. Keeping the queue guarantees every image lands in LSN order first.
Diagnostic line: `MXFS: P-DRAIN-PEAK deferred=%u queued_buffers=%u
queued_bytes=%llu` — the only measurement of how much metadata a replay pins,
unbounded except by the slice's distinct-buffer count.

Testing consequence: "durable prefix with an unissued suffix" cannot be
produced by cutting between transactions — nothing is durable between them.
It only exists inside the end-of-pass submission itself, which is many
separate writes and not atomic — the same place a real crash would leave it.

Grepped `dlm/` and `xfs/` for `replay_cursor`, `recov_progress`,
`replay_progress`, `resume_lsn`, `replayed_to`, `progress_seq`,
`last_replayed`: zero matches, all seven. Replay has no persisted resume
point — it is LSN-gated and idempotent (`dlm/v5_mount.c`), so a successor
re-runs the whole pass and gating decides what still applies. A successor
meeting a half-applied replay must REDO, not resume from a cursor; the
required property is that repeating an already-applied prefix has no
destructive effect twice.

Completion is not durable at the `P163-RECOVERY-COMPLETE` log line
(informational, end of `v5_recovery_complete_ladder`). It becomes durable at
`mxfs_disklock_purge_node(ctx->disklock, dead_node)`, preceded by an
irreversible CAW-authority purge and `mxfs_pal_bdev_flush(ctx->dev)` — comment:
"the purge must be durable before the broadcast." On failure, the caller must
not treat recovery as published.

## Cluster 2: a fence certificate needs a retirement witness, and MXFS didn't have one

Chronological design chain, all Astra design-consult rulings, each correcting
or extending the previous:

**s75 — [[design-a-fence-certificate-needs-admission-and-retirement-and-they-are-separate-facts]]:**
A fence certificate must establish two separate facts: ADMISSION (dead
incarnation can't get write permission — a WE reservation or gone registration
proves this) and RETIREMENT (writes the target already accepted from that
incarnation can no longer take effect). Every fence kind in the tree proved
admission; none witnessed retirement. Traps found:
- The sole-survivor exclusive-write gate's PREEMPT AND ABORT carries `sark=0`
  and only aborts task sets of registrants it *removes* — a victim already
  removed by an earlier command isn't among them (`scst_pr_abort_reg` /
  `__scst_abort_task_set` walk one I_T_L nexus, confirmed in SCST source).
- Key absence isn't a drain certificate: it can mean PREEMPT AND ABORT, a
  voluntary zero-REGISTER (retires nothing), or nexus-loss cleanup, and READ
  KEYS can't distinguish them.
- No universal "BIO boundary" re-check exists in SPC/SAM at queued-task
  execution time — the PREEMPT vs PREEMPT AND ABORT distinction is itself the
  proof there isn't one.
- A host reboot doesn't witness a drain: only full iSCSI session
  reinstatement terminates the old session's tasks; connection
  recovery/reinstatement and task reassignment preserve them, and a new
  session with a different ISID need not replace the old one.
- PR generation bump and successor's own registration appearing are also not
  retirement witnesses.

What does supply retirement: a target-enforced drain with the right scope
(LOGICAL UNIT RESET — SCST's `scst_process_reset` walks the device's whole
`dev_tgt_dev_list`, no registrant-list dependency, and an ordinary conforming
LU reset preserves PRs), or a qualified target contract. LU reset's cost:
aborts the survivor's own metadata writes too, needs a quiesce that can't wait
on an already-blocked journal, and there's no supported in-kernel TMF API (see
cluster below). A succession proof alternative must show incarnation
succession tied to *that* victim (differing boot ids alone prove no ordering),
complete nexus coverage, a completed target-side retirement boundary, and
publication of the durable successor witness only after that boundary.

**s83 — [[reference-there-is-no-in-kernel-scsi-task-management-path-for-an-out-of-tree-module-on-6-8]]:**
Confirmed against the deployed 6.8.0-101-generic kernel: `scsi_ioctl_reset` is
global in kallsyms but has no `EXPORT_SYMBOL` (absent from Module.symvers, so
modpost rejects it) and takes `int __user *`; `scsi_try_bus_device_reset` and
`scsi_try_target_reset` are `static`; `scsi_execute_cmd` is exported but only
issues ordinary CDBs, not TMFs. So an out-of-tree module has exactly three
options: (1) a kernel patch adding a real supported TMF interface with proper
reference/serialization/recovery/completion-lifetime handling — the ruled
preference, an acceptable product-level kernel dependency for an
integrity-critical primitive; (2) a privileged userspace helper doing
`SG_SCSI_RESET_DEVICE | SG_SCSI_RESET_NO_ESCALATE`, admissible only with a
real invocation/incarnation binding (exit status + a `tmfrsp_pdus` delta is
NOT one — the counter can move for another TMF, a session can recover
between two observations), and never with an executable/control path that
depends on the filesystem being recovered (deadlock); forbidden outright:
passing a kernel pointer as the ioctl's user pointer, resolving the unexported
symbol by kprobe/kallsyms address, or fabricating a `scsi_cmnd` to call the
host template's `eh_device_reset_handler` directly (its locking/recovery
state/queue handling/calling-context assumptions matter).

On this exact stack: `scsi_ioctl_reset()` maps the reset flags to exactly
`scsi_try_bus_device_reset()`, returns 0 only for SUCCESS;
`iscsi_eh_device_reset()` returns SUCCESS only when
`session->tmf_state == TMF_SUCCESS`, set only by `iscsi_tmf_rsp()` on
`ISCSI_TMF_RSP_COMPLETE` in the target's own TMF response PDU; timeout returns
FAILED via `iscsi_conn_failure()`; a non-LOGGED_IN session returns FAILED
without sending anything. So on iscsi_tcp there's no "local teardown wearing a
witness's clothes" ambiguity — but the same handler also calls
`fail_scsi_tasks(conn, lun, DID_ERROR)`, failing the issuer's own outstanding
commands, which is why the issuer survives a reset and a bystander does not.

**s82 — [[design-the-three-routes-to-a-retirement-witness-and-why-only-a-matched-target-response-counts]]:**
Ranking: implement witnessed LOGICAL UNIT RESET as the general mechanism,
keep early PREEMPT AND ABORT as an optimization only, make refusal the
terminal fallback. A qualification built from probe laps that saw no late
write doesn't meet an integrity bar. Any route must establish all four:
admission exclusion, retirement of already-accepted work, control of the
*survivor's own* queued commands/retries, and recovery tolerant of partial
pre-retirement effects. The witness is the matched target response, never a
return code: "for this request, on this transport-session incarnation, the
initiator received a successful LU RESET TMF response from the target for the
specified LU" — re-audit the iscsi_tcp mapping above against the exact
deployed kernel before relying on it, don't assume it's stable across
versions. Certificate must capture: stable target/LU identity (never
`/dev/sdX`), function requested, LUN + initiator task tag, session/connection
identity and incarnation (rejects stale responses and tag reuse), the
matching Function Complete, and the fencing epoch/admission generation it was
issued under. The collateral (`fail_scsi_tasks` on our own commands) is a
prerequisite, not a side effect to ignore: gate the survivor's own
writes/writeback/journal/outstanding-block-requests/deferred-submissions/retries
at their producers — freezing a queue isn't draining it — and if those aborts
panic/shut down/hang the filesystem, the route fails the operational bar
regardless of target-side correctness.

Measured on this rig: disklock death window is 31×2s = 62s with no sleep
between expiry callback and PREEMPT AND ABORT; TCP path waits a 40s grace; the
QNAP purges the registration 30-46s after the cut — so detection lands ~30s
after the registration is already gone. No two-phase "capture abort scope now,
execute later" exists. Legitimate design instead: separate storage-ownership
revocation from declaring a machine dead, and design how a live, falsely
fenced node behaves when it loses access without corrupting, panicking, or
shutting down. A conditional fast path is worth having only if losing is safe:
win → scoped abort, lose → witnessed reset, neither → refuse. No ordinary CDB
supplies the missing fact (whether a historical nexus has outstanding work);
PR IN, TEST UNIT READY, reads, FUA reads, COMPARE AND WRITE, SYNCHRONIZE CACHE
all fail to. CLEAR TASK SET / an ORDERED cross-nexus barrier are genuine
alternatives only after establishing the LU's task-set model — with per-nexus
task sets, clearing ours says nothing about the victim's.

**s82 — [[design-a-deployment-contract-is-a-conditional-and-its-premise-is-an-observation-the-code-must-classify]]:**
Corrects the previous ruling and the 0.89.13 package it had shipped. 0.89.13's
deployment clause ("for this LUN, every command accepted from a lost nexus
completed or aborted before that nexus's registration disappears") is an
implication: matching vendor/product/firmware/LUN proves the deployment
*asserted* the premise, never that the premise happened *here*. No initiator
can learn from the target why a registration left the table — not from PR IN,
not from the PR generation, not from waiting longer. Consequence: the same
clause was authorizing replay after ANY registration absence, including one
MXFS itself had replaced (the exact case its own refusal kind was meant to
catch). Four boot/registration identifiers (iSCSI connection, iSCSI session,
SCSI I_T nexus, MXFS boot identity) have four different lifetimes and none
implies the others; "no successor record" proves nothing either — admin
action, an ordinary PREEMPT, a CLEAR, or a crash between the PR mutation and
the ledger write all defeat it.

Sound shape: (1) classify the observed transition as an enum, never a claim —
`no-mxfs-successor-observed`, `mxfs-replacement-same-boot`,
`mxfs-replacement-different-boot`, `victim-registration-present`; UNKNOWN is a
refusal, never a wildcard; (2) a clause covers exactly one observation, named
for the thing observable (`unreplaced-registration-absence-retires-before-purge`),
and a withdrawn clause stays RECOGNISED-and-always-refused with the reason
printed rather than silently deleted; (3) enforce the obligation at the
certificate constructor, not per-kind — a predicate taking only `kind` can
identify a potentially proof-bearing kind but can't decide whether contextual
obligations were met; (4) a failed proof must not become a mutable flag
another path clears, nor a permanent veto — a later scoped abort satisfies an
obligation, it doesn't clear a prohibition. Five shortcuts that recreate the
defect, all now closed off: "different boot id" ⇒ "covered nexus loss"; "no
successor record" ⇒ "loss was the only cause"; "WE + matching contract" ⇒
"retirement"; a renamed trigger/basis label standing in for missing evidence;
fixing one kind while another keeps the same inference (moves the bypass, does
not close it). The honest state when neither a scoped completion witness nor
an applicable clause exists is "no replay-authorizing certificate" — never
"probably drained."

## Standalone infra/host facts (no shared topic)

[[clyde-taint-512-is-a-boot-time-dma-direct-map-page-warn-not-campaign-induced]] —
clyde's `/proc/sys/kernel/tainted` reads 12800 = `TAINT_OOT_MODULE` (4096) +
`TAINT_UNSIGNED_MODULE` (8192) + `TAINT_WARN` (512); the nodes only show the
first two. The 512 is a single `dma_direct_map_page` WARNING 4 seconds after
the 2026-09-06 13:37:51 boot (driver DMA-mapping complaint during probe, before
any MXFS activity) — not a campaign-induced fault. `dmesg` showed zero
`WARNING:` lines because the ring had wrapped on a 3-day-old boot; `journalctl
-b -k` still had it. Same boot: 0 BUG/Oops/bad-page, no pstore record newer
than the boot. `clyde_preflight.sh` correctly gates on BAD_PAGE/oops/soft-lockup/MCE,
not TAINT_WARN, and reported PASS throughout. Method for a taint bit against a
clean-looking log: don't trust `dmesg` alone (ring wraps, `WARN_ON_ONCE` fires
once per boot) — grep `journalctl -b -k` and check the timestamp against
`uptime -s`; cross-check `/var/lib/systemd/pstore/` mtimes against boot time,
since a record older than the boot isn't this boot's crash.

[[subagents-DO-inherit-claude-md-session-start-snapshot]] — Verified
2026-08-15 with a zero-tool-call haiku subagent: it correctly listed RULES 0,
1, 2, 2b, 2c, 3-8 verbatim and answered all four probed prohibitions
correctly, proving real CLAUDE.md inheritance rather than reconstruction. The
catch: it's a SESSION-START snapshot — it did not know RULES 9 and 10, added
earlier in that same session, and newly-written `.claude/agents/*.md`
definitions were "not found" by subagents until the next session restarted.
This overturned an unverified claim ("subagents inherit none of this file")
that had been written into CLAUDE.md as fact after a design-consult review;
the fix was to actually test it. Standing lesson: a design consult's claims
are hypotheses, not findings, and cheap ones are usually one subagent call
away from being checked. Still embed RULES 0/2c/3 verbatim in every agent
definition anyway — not because inheritance fails, but because a rule written
this session hasn't propagated yet, and a constraint next to the task is
obeyed more reliably than one 400 lines up the file.

[[infra-mpath-up-sh-quoting-regression-fixed]] — `scripts/mpath_up.sh
status|up N` broke with `line 117: syntax error near unexpected token '('`
after a post-sess6 edit (iscsid.conf startup=automatic feature) introduced two
raw-single-quote bugs inside the single-quoted `NODE_ENSURE` block: an
unescaped apostrophe in a comment ("iscsid.conf's default") that closed the
string early and made the following `(manual ...)` parse as code, and a `sed
-i 's/.../''` using raw single quotes instead of the `'"'"'` idiom used
elsewhere in the block. Fixed by removing the apostrophe and switching that
sed to double quotes (passes through the single-quoted block literally).
Consequence while broken: test9-16 had iscsid active but 0 iSCSI sessions, no
mpatha, `mxfs mount "Can't lookup blockdev"`, 16/caw convergence failure —
test1-8 were unaffected only because they already had healthy mpatha from
prior sessions. Standing rule for the ladder: run `scripts/mpath_up.sh up N`
before every `./run.sh N caw` at a node count whose upper nodes may have lost
sessions — `run.sh` assumes mpatha already exists, it does not assemble it.

[[Network topology]] — clyde (dev host) has two NICs to the same iSCSI LUN
(`~/iscsi-lun.img`): 192.168.1.166 is the main LAN, reached by physical nodes
(pve1, pve2, serv) at port 3260; 192.168.120.1 is the lab/VM bridge with
dnsmasq DNS, reached by test VMs at port 3260. The 192.168.120.x subnet has a
router rule for internet access. Same machine, same LUN, different subnet per
client class — when a node can't reach the target, check which of the two
addresses it should be using before assuming a target-side problem.
