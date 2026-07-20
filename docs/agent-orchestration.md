# Agent Orchestration Model

## Hierarchy

```
User
 └── Director (main Claude session)
      ├── Team Lead A
      │    ├── Worker 1 (haiku)
      │    ├── Worker 2 (haiku)
      │    └── Worker N (haiku)
      └── Team Lead B
           ├── Worker 1 (haiku)
           └── Worker N (haiku)
```

**User** — gives direction and asks for things. Receives updates from the director.

**Director** — the main Claude session. Owns the overall plan, makes architectural
decisions, writes and fixes code, spawns team leads, and relays status to the user.
Does not do mechanical/repetitive work directly.

**Team Lead** — owns a specific workstream (e.g. "run 16-node tests", "fix and
redeploy", "run 32-node tests"). Spawns haiku workers for all parallel operations.
Reports status to the director every 5 minutes. Can have multiple team leads active
simultaneously for independent workstreams.

**Workers** — haiku agents. Do one mechanical task each (one govc reset, one node
setup, one SSH test). Report results back to their team lead. Never make decisions.

---

## Naming Conventions

| Role | Team registration name |
|---|---|
| Director (main session) | `director` |
| Team lead | `lead-N` or descriptive (`lead-16node`, `lead-fixer`) |
| Worker | `worker-N` or descriptive (`reset-3`, `setup-7`, `tester`) |

The main session should always join a team as `director`, not `team-lead`, to
avoid confusion with actual team leads.

---

## Communication

- **Workers → Team Lead**: SendMessage on task completion with result summary
- **Team Lead → Director**: SendMessage every 5 minutes with status; immediately on
  completion or blockers
- **Director → User**: relays relevant updates in the main conversation
- **State file**: every agent writes progress to `/tmp/mxfs_scale_state.md` (or
  a workstream-specific file) as a backup to messaging

Team leads should never wait until completion to communicate. A message every 5
minutes prevents the director from having to guess whether the lead is working or
hung.

---

## Spawning Rules

**Director spawns team leads:**
- Use `general-purpose` or `sonnet` model for team leads — they need judgment
- Set `team_name` and `name` (e.g. `name: lead-16node`)
- Set `mode: bypassPermissions` for test/deploy work
- Set `run_in_background: true`
- Give team leads a tight, action-first prompt (see below)

**Team leads spawn workers:**
- Use `haiku` model for all workers — fast and cheap for mechanical tasks
- Spawn all workers for a phase in ONE message (parallel)
- N nodes = N workers launched simultaneously, not sequentially
- Each worker does exactly one thing and reports back

---

## Prompt Design

### Team Lead Prompts
- Start with immediate action: "Your first message = N parallel Bash calls"
- Spell out every step explicitly — do not rely on judgment for sequencing
- Include: SSH command format, govc format, node IPs, all quirks
- State pass criteria for every test numerically
- Include: "Send status to director every 5 minutes. Do not wait until done."
- Include: "If you see an obvious next step, take it without asking."
- Keep prompts short — long prompts cause analysis paralysis

### Worker Prompts
- One task only
- Exact command to run
- Where to report result (SendMessage recipient)
- What to include in the report (PASS/FAIL + key output)
- No judgment, no branching, no sub-spawning

---

## Anti-Patterns (Lessons Learned)

**Lead analysis paralysis** — leads given too much context spend 30-60 minutes
reading code before taking any action. Fix: prompt must say "your FIRST message
is N parallel Bash calls" so execution is forced before analysis.

**Lead serial SSH** — leads default to one SSH call at a time. Fix: prompt must
explicitly say "N nodes = N parallel workers in ONE message. Never sequential."

**Lead asking permission** — leads go idle asking "should I proceed?" Fix: prompt
must say "if you see an obvious next step, take it immediately without asking."

**Dead messaging target** — messages to a team member from a previous session go
nowhere. Always verify team member names match the current session's registrations.

**No status updates** — leads run silently for 45+ minutes with no indication of
progress. Fix: require status messages every 5 minutes as an explicit prompt
requirement.

**Workers doing analysis** — workers given too much context start making decisions.
Fix: worker prompts are one task, one command, one report. No options.

---

## Example: Multi-Lead Test Campaign

```
Director spawns:
  lead-infra  — handles VM resets, NFS mounts, iSCSI, mkfs, module load
  lead-tests  — waits for lead-infra signal, then runs all test phases

lead-infra spawns (all at once):
  reset-1 through reset-16   — govc reset, one per node (haiku)
  (waits for all to complete, then:)
  setup-1 through setup-16   — NFS + iSCSI setup (haiku)
  (then:)
  mount-1 through mount-16   — insmod + mount (haiku)
  (then signals lead-tests)

lead-tests spawns:
  tester-16   — runs T-04-01 through T-04-08 with parallel Bash calls
```

Each phase runs in parallel within its wave. Total wall time for a 16-node
reset+setup+mount+test cycle: ~10-15 minutes vs 60-90 minutes serial.

---

## State Files

Use `/tmp/mxfs_WORKSTREAM_state.md` per active workstream. Format:

```
# MXFS [Workstream] State
## Timestamp: YYYY-MM-DD HH:MM UTC
## Agent: lead-N

### Phase: [current phase]
### Infrastructure
- resets: N/N
- setup: N/N
- mounted: N/N

### Test Results
- T-04-01: PASS/FAIL/PENDING
...

### Next Step
[what the lead is about to do]
```

Directors read state files to monitor progress when message delivery is uncertain.
