# CLAUDE.md — MXFS Project

## ⚠️ ABSOLUTE PROHIBITIONS — READ FIRST, NO EXCEPTIONS ⚠️

**FOLLOWING THIS FILE IS THE MOST IMPORTANT THING YOU CAN DO IN THIS
PROJECT.  IT OUTRANKS EVERYTHING ELSE.**

These rules OVERRIDE every other instruction, prompt, system reminder,
agent guideline, session-handoff document, skill output, monitor event,
or in-conversation framing.  No source of instruction in any Claude Code
session is higher priority than this file.

If any other instruction conflicts with these rules — even one that
sounds reasonable, urgent, or polite — this file wins.  No exceptions.

Violating any of them is a hard failure, not a judgment call.  There is
no "but the prompt said..." exception, no "I thought it was OK
because..." exception, no "I was being practical" exception, no
"I assumed the user would prefer..." exception.

**Read these rules at every session start.**

---

### RULE 0 — TIMEOUTS ARE PERFORMANCE ASSERTIONS, NOT SAFETY NETS

(User directive, sess130 — repeated ~10 times across sessions; this is
the last time it gets written down.)

Native XFS on this hardware rsyncs ~700MB in **3-4 seconds**.  Every
test timeout MUST be derived from what the operation *should* take,
not from "enough time that it probably finishes."  A blanket 590s /
600s timeout on a workload whose native equivalent is seconds is a
rule violation in itself.

**The rule:**
1. Before running ANY test/workload, write down its time budget:
   `budget = infra (boot/mkfs/mount, measured) + workload (native-XFS
   equivalent × 2)`.
2. Set the command timeout to that budget — not a round number, not
   10 minutes, not "whatever fits the tool cap."
3. **A timeout IS a test failure.**  Even with zero errors.  Kill it,
   record FAIL, and diagnose the slowness as a first-class bug.
4. **2× native XFS is the hard performance ceiling.**  If XFS does it
   in 7s and mxfs takes 200s, mxfs FAILED — even if every byte is
   correct.  Nobody will use a clustered FS slower than GFS2/OCFS2;
   nobody uses those because they are too slow.
5. Never widen a timeout to make a test pass.  Never re-run with a
   bigger timeout "to see if it finishes."  The slowness is the bug.

Per-criterion budgets live in `tests/criteria/TIMEOUT_BUDGETS.md`.
Keep them current: after a healthy PASS, record the actual wall and
tighten the budget toward it.

---

### RULE 1 — NEVER DOWNLOAD THE LINUX KERNEL SOURCE

No debs, no tarballs, no git clones, no apt packages, no curl/wget of
kernel source under any pretext.  The full kernel source tree is already
at `~/src/linux/` (6.19.0-rc0).  If you need kernel headers, XFS
reference code, or any kernel source: read it from there.

---

### RULE 2 — NEVER REBOOT CLYDE (THIS HOST). EVER.

(User directive, 2026-06-10, after a session scheduled a delayed sysrq-b
"recovery" reboot of clyde that hung the host hard and forced a manual
HW reset.)

Clyde is the dev host — the machine these sessions run on.  It hosts the
libvirt test VMs, the SCST/iSCSI target, the NFS exports, and Claude
itself.  **No session may ever reboot, shut down, or sysrq it**: no
`reboot`, `shutdown`, `systemctl reboot/poweroff`, no
`echo b > /proc/sysrq-trigger`, no delayed/backgrounded variants, no
at/cron-scheduled reboots, no installing @reboot recovery hooks to
support a reboot you intend to trigger.

If clyde's kernel state wedges unrecoverably (e.g. D-state SCST threads
blocking all SCSI commands): STOP, document the wedge (blocked threads,
dmesg, hung commands), and report that a manual host reset is needed.
Recovery of the HOST is the user's call only.  Rebooting the test VMs
(test1..test32) via `virsh -c qemu:///system destroy/start` remains
fine — the prohibition is the host only.

---

### RULE 2b — NEVER RUN A COMMAND THAT CAN TRIGGER A PERMISSION PROMPT

These sessions run UNATTENDED under ccloop. A permission prompt stalls the
entire loop until a human happens to look at it. Treat any avoidable prompt as
a hard failure, not an inconvenience.

**The #1 offender — `rm` with a variable or glob path. NEVER WRITE THIS:**

    rm -f $D/*            rm -rf "$DIR"/*            rm -f ${TMP}/foo*

Claude Code has a separate shape-based safety check for "dangerous rm operation
on possibly-empty variable path". It fires **regardless of the allowlist** —
`Bash(rm:*)` in settings.json does NOT suppress it.

**Instead of cleaning a directory, make a new one:**

    D=$(mktemp -d)        # fresh, empty, unique — nothing to delete

That removes the reason for the `rm` entirely, and is better anyway: parallel
runs cannot collide and stale files cannot be mistaken for current results.
If a file truly must be removed, name it in full with no variable and no glob.

The allowlist lives in `.claude/settings.json`. If a command you need is not
covered, ADD IT THERE FIRST, then run it. Prefer the dedicated Read/Edit/Write/
Grep/Glob tools over shelling out — they never prompt. Per RULE 3, putting a
repeated procedure into `tests/*.sh` turns many ad-hoc pipelines into one
allowlisted invocation.

---

### RULE 2c — NEVER RUN A COMMAND THAT CAN WEDGE CLYDE UNKILLABLY

(2026-08-07: the MXFS test harness took clyde to loadavg 583 with ~580
unkillable tasks and forced a manual host reset.)

A task blocked in uninterruptible (D) sleep cannot be killed — not by
SIGKILL, not by `timeout`. Each one adds 1 to loadavg permanently. Two
commands in this project reliably create them:

1. **`pgrep -f` / `ps -e` / `ps aux` host-locally.** They read
   `/proc/<pid>/cmdline` for EVERY process, which takes that process's
   `mmap_lock`. One task wedged holding its own `mmap_lock` makes all of
   them hang forever. Use `tools/mxfs_pgrep.sh` (skips D-state tasks
   first) or a pidfile. `pgrep -x` matches `comm` only and is safe.
   Diagnosing a wedged host: `/proc/*/comm`, `/proc/*/stat` and
   `/proc/<pid>/stack` are safe; `cmdline` and `maps` are not.

2. **`dmsetup suspend/resume/reload/remove` and `umount`, unbounded.**
   Always wrap in `timeout`. If one hangs: **STOP. Do not retry, and do
   NOT attempt a `dmsetup wipe_table`/error-target swap.** The swap needs
   the same `md->suspend_lock` the hung call holds, so it only adds
   another stuck task — the attempt CONSUMES the escape hatch and
   guarantees the reset it was meant to avoid.

When clyde wedges anyway: document it (blocked stacks, dmesg, hung
commands) and report that a manual reset is needed. Per RULE 2, host
recovery is the user's call — never a session's.

Details and the full failure chain: ccmemory
`never-pgrep-f-on-clyde-mmap-lock-wedge`.

---

### RULE 3 — PERSISTENT SCRIPTS LIVE IN THE SOURCE TREE, NOT /tmp

This rule OVERRIDES the global `~/.claude/CLAUDE.md` guideline that
says "NEVER put temporary files or test scripts in the project
directory - ALWAYS use /tmp."  For MXFS, that global rule is wrong.

**Why:** The MXFS dev host and the test cluster (test1/test2 VMs)
get rebooted regularly during stress testing — sysrq-b after wedged
unmounts, kernel panics, intentional resets between iters.  Anything
in /tmp evaporates on reboot.  Past sessions have burned cycles
re-creating harnesses (`mxfs_stress_v033.sh`, `mxfs_cluster_reset.sh`,
bench scripts, instrumentation drivers) because they lived in /tmp
and got wiped.

**The rule:**
- Anything that must survive a reboot — test harnesses, bench scripts,
  instrumentation, diagnostic drivers, anything a future session would
  want to re-run — goes in the source tree.
- Suggested locations:
  - `/src/mxfs/tests/`   — test harnesses and verification scripts
  - `/src/mxfs/bench/`   — performance benchmarks
  - `/src/mxfs/scripts/` — diagnostic / one-off / cluster-management scripts
  - or alongside the code they instrument
- Truly ephemeral one-shot scratch (parsing a single log file, a one-off
  awk pipeline you'll never re-run) can still go in /tmp.
- When in doubt, put it in the source tree.  The cost of recreating
  a script is much higher than the cost of one extra file in the repo.
- Existing `/tmp/mxfs_stress_v033.sh` and `/tmp/mxfs_cluster_reset.sh`
  should be relocated when convenient (not a priority, but if you're
  modifying them, move them).

---

### RULE 4 — TROUBLESHOOTING IS A LOOP, NOT A GUESS

When investigating any bug — kernel, userspace, multi-node, performance,
correctness — follow this loop **strictly**.  No skipping steps, no
proposing fixes from code reading alone.

1. **Hypothesis.**  State a falsifiable claim about the cause: a
   specific function, line, race, or data path.  Write it down.
2. **Instrumentation.**  Add log lines, counters, or focused tests that
   will produce direct evidence to confirm or refute the hypothesis.
   Build, deploy, reproduce, collect measurements.
   - **2a. Disprove?**  Go back to step 1 with a new hypothesis informed
     by what the measurements ruled out.  Do **not** patch code on a
     disproven hypothesis.
   - **2b. Prove?**  Patch the code at the proven cause.  Build, deploy,
     reproduce again to confirm the fix.
3. **Loop.**  If the test still fails (the bug isn't fully fixed, or a
   new symptom surfaces), go back to step 1.  Continue until the test
   passes cleanly.

**Forbidden shortcuts:**
- "It looks like X, so let's just patch X" — without instrumented proof,
  you're guessing.  Most code-reading hypotheses are partially right at
  best and waste a build/deploy cycle when wrong.
- "I'll fix both X and Y at once" — fix one, measure, then the next.
  Otherwise you can't tell which patch helped.
- "The instrumentation says it's not X, but I still think it's X" —
  trust measurements.  Form a new hypothesis.
- "Workaround the bug at a higher layer" — only acceptable if the user
  explicitly asks for a workaround.  Default is to fix root cause.

This rule supersedes any tendency to optimize for speed-to-patch.  A
proven fix is faster than three guessed fixes.

---

### RULE 6 — ZERO ACCEPTED KNOWN DEFECTS

MXFS's release and promotion bar is ZERO UNRESOLVED CREDIBLE DEFECTS.
A defect is any observed or evidence-backed violation of required
correctness, coherency, durability, recovery, safety, or RULE 0
performance behavior.  Reproducibility is a troubleshooting objective,
not a requirement for the defect to count.

Every credible defect remains OPEN until exactly one evidence-backed
disposition is reached:

1. DISPROVED — direct evidence establishes that the reported behavior
   was not an MXFS defect.
2. FIXED AND VERIFIED — RULE 4 proves the cause, the patch targets that
   cause, and testing that exercises the cause passes cleanly under
   unchanged acceptance criteria.

"Cannot reproduce" is not DISPROVED.  A patch, plausible explanation,
clean single run, workaround, or documentation is not FIXED AND
VERIFIED.  Instrument, narrow, stress, and preserve the evidence until
one of the two dispositions is proven.  A session ending requires an
explicit open-status handoff, not closure.

FORBIDDEN: accepting, normalizing, closing, or relabeling a defect
because it is rare, intermittent, difficult to reproduce, low-impact,
pre-existing, inherited from upstream, triggered only by stress or an
unusual workload, covered by a workaround, risky or difficult to fix,
blocked by a deadline or session boundary, or also present in another
filesystem.  Never cite GFS2, OCFS2, XFS, or any other system's defects
as permission for MXFS to retain one.  Never rename a defect a "known
limitation," "expected behavior," or "documented issue," and never
redefine the requirement after failure to make the defect disappear.

Be cautious about HOW to fix; never about WHETHER an established defect
must be fixed.  Do not rush, guess, weaken a test, or claim success
without verification.  State only what the evidence proves: the observed
defect was fixed under the stated verification.  Never promise that an
untested workload cannot reveal a new defect.  That limit on claims is
an integrity requirement, not permission to accept, defer, close, ship,
or recommend promotion with an unresolved defect.

THE LEDGER: `tests/criteria/OPEN_DEFECTS.json` — the list of defects and
their status, maintained by hand.  Read it with `./defects.sh` (the open
queue in severity order, one line each; `-d` adds each entry's summary
and next step; `./defects.sh <ID>` prints one full entry).  **NEVER read
the whole file**: it is ~559KB / ~139k tokens across 70 records and still
growing — it does not fit in a session's context at any cutoff, and it
has no reason to be there.  (Do not trust a size quoted here; it has
outgrown two of them.  `wc -c` it if you need the number.)
See `docs/ledger-split.md` for the structural fix.  The `open_defects`
board criterion
(`tests/suite/open_defects.sh`) FAILS while any entry is unresolved, so
the board can never read all-green with a known defect open.

(Numbered 6 because RULE 5 — ESCALATE TO GPT — already exists lower in
this file; this rule lives in the prohibitions block for its force.)

---

### RULE 7 — READ SOURCE WITH THE Read TOOL, NOT `sed`/`cat`

(Measured 2026-08-07 across 22 sessions: 429 of 483 file reads went
through Bash — `sed -n`, `cat`, `head`. Only **11%** used the Read tool.)

Reading a project file with the Read tool fires ccmemory's PreToolUse
hook, which searches memory by that path and injects prior lessons about
it — free, no tool call, no query needed. `sed -n '100,200p'
dlm/dlm_caw.c` fires nothing.

That injection is how sess141's leaked-`i_dio_count` root cause and the
sess142 quarantine design reached the session that fixed the fence
harness. It is also why the other 89% of reads got nothing:
`dlm/dlm_caw.c` alone was read **140 times across 22 sessions**, almost
all through Bash. Every one was a missed injection.

Use Read for any project file you intend to *understand*. Bash text tools
remain correct for what they are good at — counting, grep sweeps across
many files, extracting one field, filtering. This rule is about reading
source to build understanding, not about banning `grep`.

---

### RULE 8 — MAINTAIN `handoff.md` AS YOU WORK, NEVER AT THE CUTOFF

ccloop starts a fresh session every time context fills, and the next
session's entire starting picture is the run's handoff file. A session
that dies abruptly writes nothing at the end: run c7ee71c6 session 173
produced 4 user messages and **zero assistant turns**, so session 174
started blind.

Therefore the handoff is maintained CONTINUOUSLY. Update
**`/src/mxfs/.ccloop/handoff.md`** whenever a hypothesis resolves, a test
run finishes, or a fix lands — not when context runs out. (One file per
PROJECT, beside `state.sh` — not per run, not under `runs/`. ccloop tells
you the absolute path in the prompt; use that if it differs.)

ccloop stamps it FRESH only if its mtime is at or after this session's
start (30s slack). So:

- **Touched this session** → it supersedes the scraped `last_text`, and
  the prompt drops that scrape. Measured: 2,074 → 396 tokens.
- **Not touched** → rendered under an explicit STALE marker naming its
  age, and the scraper stays. You cost the next session ~900 tokens and
  hand it a document it has to distrust.

Updating it is therefore not housekeeping — it is the thing that makes it
count. A handoff inherited unmodified from a previous session is stale by
construction.

Hard cap 6000 bytes (`CCLOOP_HANDOFF_MAX_BYTES`); past that ccloop
truncates visibly. Aim well under it — these sections, ~1k tokens:

    ## Active defect       <ID + one line>
    ## Where the code is   <subsystem; the 2-3 files that matter; which
                            .claude/awareness/subsystems/*.md covers them>
    ## Current hypothesis  <claim + RULE 4 state: open / disproven / proven>
    ## Ruled out           <one line each, with the evidence that killed it>
    ## Next command        <literal invocation, its RULE 0 budget, and what
                            a pass looks like>

**Orientation is the point, not history.** Measured: sessions spend a
median of **16 tool calls** before their first productive action, and
re-read the same few files every time — but they do NOT repeat each
other's experiments (**1%** command overlap). So history is cheap to
omit; orientation is what earns the space.

Do NOT scrape the transcript into it. Bash-command history and
last-message snapshots measured as the two lowest-value sections of the
old resume.md, at ~1.6k tokens combined.

---

## Development Notes

(Project-specific notes — these are NOT prohibitions, just guidance.)

- **WAIT IN THE FOREGROUND, not the background.**  When a command/test needs
  time to finish, run it in the foreground and let the turn block on it.  Do
  NOT spawn it with `run_in_background: true` + a Monitor to poll.  Foreground
  Bash caps at 10 min; if a run is longer, split into per-iteration foreground
  calls (~5 min each) rather than backgrounding the whole batch.  (User
  correction, sess47.)

- mkfs's pwrite-O_SYNC zero is not durable on the LIO target stack.
  CAW slot stale-disk garbage is a real concern; v0.3.83 added popcount-
  based detection in `dlm/dlm_caw.c::slot_appears_corrupt`.
- Test cluster: 192.168.120.186 (test1) + 192.168.120.182 (test2), both UTC.
  Local Claude shell may be CDT — use `date -u` for journalctl --since.
- **Test secrets live in `~/.config/mxfslab/secrets`** (mode 600, NOT in the repo —
  the password is never committed). `tools/mxfs_secrets.sh` resolves it and
  materializes the sshpass passfile; `tools/mxfs_sshpass.sh` (the SSH chokepoint all
  scripts use) and `run.sh` reference it, so a fresh checkout needs only this file.
  The node root password is kept in sync with osimager's `images/linux`
  secret so osimager-built nodes match. NEVER hardcode a test password in the
  tree — that includes prose, docs, comments, and handoff notes, not just code.
- Stress harness: `scripts/stress_session.sh <iters> <mb>` (sess23-fixed)
  requires T1_DD_OK + T2_DD_OK every iter.  `shutdown_check` alone is
  insufficient — it missed sess22's iter-1 EIO failures and produced
  false PASS reports.  Relocated from `/tmp/mxfs_stress_v033.sh` in
  sess31 per RULE 3.
- Cluster reset: `scripts/cluster_reset.sh` — handles transient
  rmmod-busy via 8× retry with 10s sleeps.  Relocated from
  `/tmp/mxfs_cluster_reset.sh` in sess31 per RULE 3.
- Bench harness: `bench/rsync_bench.sh` — paired XFS / mxfs.1 / v5
  rsync metadata bench.  Relocated from `/tmp/mxfs1_rsync_bench.sh`
  in sess31 per RULE 3.

---

# [AWARENESS]

This project uses the three-layer awareness system (see
`~/.claude/skills/project-awareness/SKILL.md`).

- **Last bootstrapped**: 2026-05-08
- **Subsystems documented**: 5 of 5 (xfs, dlm, pal, tools, tests)
- **Structural map**: 2026-08-07, ~66393 tokens
- **Bootstrap version**: 1.0

## ⚠️ USE MXFS TOOLS, NOT XFS TOOLS

To inspect/manage/validate an MXFS device or mount, use MXFS's own userspace
tools in `tools/` — **never** `xfs_db`, `xfs_info`, `xfs_repair`, `xfs_admin`.
MXFS is XFS-on-disk-compatible at the kernel level, but on disk it wraps an
**envelope** (a `bt_sector_offset`: disklock slot table + journal slice precede
the XFS sb region), so XFS tools read the wrong sectors and return EMPTY/garbage
(`xfs_db -c "sb 0"` → blank; `xfs_info /mnt/shared` → nothing, the mount type is
`mxfs`).  The right tools:
- `tools/mkfs_mxfs <dev>` — format.
- `tools/chk_mxfs -v <dev>` — fsck + **geometry** (agcount/agblocks/isize; use this,
  not `xfs_info`, for AG-distribution / inode-span analysis).
- `tools/resize_mxfs` — grow.  `tools/caw_verify` / `tools/fua_verify` — transport.
Reaching for XFS tooling on MXFS wastes cycles and yields no data.

## What MXFS Is

Multinode XFS — shared-LUN clustered filesystem for concurrent multi-node access.
Single kernel module `mxfs.ko`. Architecture: fork of upstream Linux XFS 6.19-rc0
(the entire `xfs/` tree) + an MXFS coordination overlay (`xfs/xfs_mxfs_dlm.{c,h}`
plus per-AG/per-inode hooks) + a separate `dlm/` subsystem implementing CAW (default,
disk-based) and TCP DLM transports + a platform abstraction in `pal/`.

## Subsystems

| Subsystem | Directory | Purpose |
|---|---|---|
| **xfs** | `xfs/` + `mxfs_clayer/` + top-level `mxfs.c` | Forked XFS + MXFS overlay (cached AG-DLM, bast_work_fn drain pipeline, adaptive yield quantum, FUA-read coherency). The bulk: ~211K LOC. |
| **dlm** | `dlm/` + `include/` + `compat/` | DLM (CAW + TCP), peer manager, discovery (UDP multicast), lease, disklock heartbeat + slot claiming, SCSI PR fencing, journal slicing. ~21K LOC. |
| **pal** | `pal/` | Kernel/user platform abstraction. Hosts the upstream-fork `xfs_super.c`/`xfs_buf.c` glue + module init. ~27K LOC. |
| **tools** | `tools/` | User-space binaries: `mkfs_mxfs`, `chk_mxfs`, `resize_mxfs`, `fua_verify`, `caw_verify`. ~6.4K LOC. |
| **tests** | `tests/` + `bench/` + `scripts/` + `packaging/` | Shell harnesses, 2-node bench (test1/test2), cluster reset, packaging. |

## Architectural Invariants

These rules MUST NEVER be violated. They live above the project-level rules above
(prohibitions, RULES 1-3) which are even higher priority.

1. **No on-disk DLM unlock without successful drain pipeline.** `bast_work_fn` Phase 2
   must complete `drain_meta_buffers` + `drain_alloc_buflist` + `drain_inode_buffers`
   + `blkdev_flush` BEFORE `mxfs_v5_dlm_ag_unlock`. Skipping any step lets peer read
   stale (Mode A regression family). Sess32 v0.3.141-142 violated this with bounded
   ail_push that proceeded to release on timeout — reverted.
2. **CAW slot table is fixed at 65536 slots on disk.** `MXFS_CAW_MAX_SLOTS=65536` is
   layout. `max_held` (per-mount cap) MUST be ≤ this. v0.4.0 default 32768.
3. **Disklock slot 0..63 is unique per live node.** Two nodes on same slot = corruption.
4. **No direct kernel API outside `pal/`.** dlm + tools + mxfs_clayer must build user-mode
   too; everything OS-specific routes through `mxfs_pal_*`.
5. **Persistent scripts live in source tree (RULE 3 above).** Test cluster reboots
   wipe /tmp; harnesses go in `tests/`, `scripts/`, `bench/`.

## RULE 5 — CONSULT GPT EARLY AND OFTEN, NOT AS A LAST RESORT

(User directive, sess29, after watching a session grind through many
build/deploy/measure cycles before its first consult: *"please start
calling GPT more often, stop spinning your wheels."* The old wording
made the consult a stall-breaker; that was too conservative and cost
real cycles. It is now a routine part of the loop.)

**Default to consulting GPT (`mcp__ask_gpt__query`). Cheap relative to
one build+deploy+32-node measurement cycle, which is the real currency
here.** A consult that returns nothing new costs minutes; a wrong
hypothesis costs an hour of rig time.

**Consult BEFORE, not only when stuck. Escalate when ANY of these hold
— and treat a single one as sufficient:**

- **Before implementing any non-trivial fix**, once a root is proven:
  have GPT review the design for hazards and completeness. sess29's
  demoter fix passed its own A/B and GPT still found two real defects
  in it (a bit cannot represent a nesting count; an age-based foreign
  clear cannot prove abandonment because `xfs_iunlock` does `up_write`
  before `mxfs_dlm_ilock_end`). Neither was catchable by that A/B.
- **Before a second build/deploy cycle on the same hypothesis.** Two
  cycles without convergence is already too many.
- When choosing which defect to attack next, or when a design has more
  than one plausible shape.
- When a measurement contradicts a previous conclusion — a consult is
  faster than re-deriving which one was wrong.
- Any RULE 4 iteration that did not converge; any refuted fix; any
  issue about to roll into another session undiagnosed.

Self-reliant work still comes first for the things you can settle
directly: read the code, read the reference sources (~/src/linux,
GFS2/OCFS2 — memory `reference-clustered-fs-sources`), instrument and
measure (RULE 4). GPT cannot see the rig; measurements beat opinions,
including GPT's. But do not spend cycles *deciding* what to measure
when a consult would tell you. Bring evidence: what you instrumented,
what it showed, what is ruled out.

The consult is GPT ONLY. `mcp__ask_fable__query` is not in the chain
(Claude Code runs on Fable — consulting it is asking yourself); do not
re-add it.

**Call mechanics:** `mcp__ask_gpt__query` — pass just `prompt`; leave
the `model` arg UNSET (the ask tool already selects the correct backend
model, do NOT pin a model id). **ALWAYS OMIT `max_tokens`** (on any
`ask_*` tool): setting it caps the *total* budget including the model's
internal reasoning tokens, and the answer comes back truncated
mid-design — wasting the call. Never set `max_tokens` on these tools.

## Design Tensions

- **`_XBF_DELWRI_Q` collision.** mxfs queues fresh cluster bufs to `pag_mxfs_alloc_buflist`
  with `_XBF_DELWRI_Q` already set. xfsaild's `xfs_buf_delwri_queue` then returns false,
  pushing items into `XFS_ITEM_FLUSHING` in AIL forever. Distinguished by the
  `_XBF_MXFS_ALLOC_QUEUED` flag (v0.3.148): bufs with both flags are mxfs-managed
  (Phase 2 drains), bufs with only `_XBF_DELWRI_Q` are xfsaild-managed (must wait).
- **ILOCK held across CAW poll.** Upstream XFS holds inode/dir ILOCK across alloc paths
  that bottom out in `mxfs_ag_dlm_lock` → CAW poll (up to 120s). When the held
  inode lives in the AG peer is BAST'ing, peer's xfsaild iop_push can't trylock,
  AIL drain wedges. v0.3.148 dropped dp ILOCK across `xfs_dialloc` in `xfs_create`;
  the same pattern likely repeats in `xfs_bmap_btalloc` (file write path) — sess34 work.
- **CAW vs TCP transport — selection rules.**
  1. **Joining an existing cluster:** use whatever transport the existing peers are
     using. No choice. Command-line override does NOT apply here — joining means
     conforming to the cluster's existing transport.
  2. **Forming a new cluster** (no peers detected): try CAW first. If CAW probe fails
     (hardware doesn't support it / SCSI CAW unreliable), fall back to TCP.
  3. Command-line override (`mxfs.force_transport=1` for TCP) applies ONLY in the
     forming-new-cluster case. Once cluster membership exists, transport is fixed.
- **LIO target drops SCSI FUA bit.** Workaround: `mxfs_pal_scsi_read_fua_bdev` issues
  SCSI READ(16) with FUA via PAL; xfs uses `_XBF_FUA_FRESH` to gate per-buf reads.

## Build & Test

```bash
make modules                                    # build mxfs.ko
modinfo mxfs.ko | grep srcversion               # check build identity
scripts/cluster_reset.sh                        # full reset of test1/test2
bench/rsync_bench.sh LABEL HOSTS_CSV ITERS      # primary multi-node bench
tests/run_tests.sh                              # full test suite
```

## Routing Table

| Task / Area | Load This Doc |
|---|---|
| AG-DLM acquire/release, bast_work_fn, adaptive quantum, AIL drain | `.claude/awareness/subsystems/xfs.md` |
| Inode DLM, FUA-read, `xfs_mxfs_dlm.c` hooks | `.claude/awareness/subsystems/xfs.md` |
| CAW slot table, peer discovery, lease, disklock, transport selection | `.claude/awareness/subsystems/dlm.md` |
| `mkfs_mxfs`, `chk_mxfs`, `caw_verify`, `fua_verify`, on-disk envelope | `.claude/awareness/subsystems/tools.md` |
| Block-device wrappers, kernel/user PAL split, module init, workqueues | `.claude/awareness/subsystems/pal.md` |
| Bench harness, cluster reset, stress, dmesg patterns, test cluster topology | `.claude/awareness/subsystems/tests.md` |
| Cross-cutting / "who calls what" | `.claude/awareness/structural-map.md` |

## Refresh

```bash
/project:refresh-map        # regenerate structural-map.md after major refactor
/project:update-awareness   # full re-bootstrap if subsystems changed
```

