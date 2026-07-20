# MXFS Worker Operating Methodology

## The Rule

**You do not make changes until you have proven the problem exists and you understand exactly what causes it.**

This is not a suggestion. This is how you work. Every time. No exceptions.

## The Process

### Step 1: Analyze

Read the code. Understand the data flow. Identify what SHOULD happen vs what IS happening. Don't guess — read.

### Step 2: Hypothesize

Form a specific, testable hypothesis. Write it down in your output. Example:
- BAD: "The directory entries are being lost somewhere"
- GOOD: "Node B's in-memory shortform directory has 0 entries at BAST time because inode_init sets i_dlm_stale=false, so the first DLM acquire skips reload"

### Step 3: Instrument

Add logging/tracing to the code that will PROVE or DISPROVE your hypothesis. The instrumentation must capture:
- The specific values you're comparing (before vs after, expected vs actual)
- Enough context to identify which node, which inode, which operation
- A clear "MATCH" or "MISMATCH" verdict in the log output

Use the `mxfs_pal_log()` function for kernel logging. Use the `P6-INSTR` prefix (or whatever phase prefix is current) so logs can be grepped easily.

### Step 4: Test

Build, deploy, run the test. Capture the instrumentation output. Do NOT skip this step. Do NOT assume the instrumentation will confirm your hypothesis.

### Step 5: Analyze Results

Read the instrumentation output. Does it prove or disprove your hypothesis?

- **Proved**: State what the data shows. Move to Step 6.
- **Disproved**: State what the data shows and WHY your hypothesis was wrong. Go back to Step 2 with a new hypothesis informed by what you learned.

### Step 6: Fix

NOW you can make code changes. The fix must directly address the proven root cause. Not a workaround. Not a "just in case" change. The specific thing the instrumentation showed was wrong.

### Step 7: Validate

Build, deploy, run the SAME test that reproduced the failure. Run it at least 10 times. Report the pass rate. If it's not 10/10, there's either a remaining issue or your fix was incomplete. Go back to Step 1.

## What NOT To Do

- Do NOT say "I found it" or "There it is" or "The fix is clear" without instrumentation data backing it up
- Do NOT make speculative fixes ("this might help", "let's try this")
- Do NOT change code in multiple places at once — one fix at a time, tested between each
- Do NOT skip the validation step
- Do NOT sit idle. If you're thinking, write down what you're thinking. If you're stuck, say you're stuck and why.
- Do NOT ask the Director "should I continue?" — the answer is always yes unless you've been told to stop or you're genuinely blocked on a decision that requires architectural knowledge you don't have
- Do NOT give up and offer alternatives — keep working until you solve it or are told to stop

## How To Report

After each test run, report:

```
## Status: [INVESTIGATING | INSTRUMENTED | PROVED | FIXED | VALIDATED]

### Hypothesis
[One sentence: what you believe is the cause]

### Evidence
[What the instrumentation showed — specific values, not summaries]

### Next Action
[What you're doing next and why]
```

After validation:

```
## Result
**Pass rate**: X/10
**Fix**: [one sentence describing what was changed and why]
**Files modified**: [list]
**Remaining issues**: [any failures that suggest another problem]
```

## Instrumentation Patterns

For kernel logging in mxfs:
```c
mxfs_pal_log(MXFS_LOG_WARN,
    "mxfs: P6-INSTR context ino=%llu key_value=%d expected=%d %s",
    (unsigned long long)ip->i_ino,
    actual_value, expected_value,
    (actual_value != expected_value) ? "MISMATCH" : "ok");
```

For capturing from VMs:
```bash
tools/mxfs_sshpass.sh test1 /tmp/.mxfs_pass "dmesg | grep P6-INSTR"
```

For the standard concurrent mkdir test (the primary regression test):
```bash
# Format, mount both, clear dmesg
tools/mxfs_sshpass.sh test1 /tmp/.mxfs_pass "/src/mxfs/tools/mkfs_mxfs -f -n 4 /dev/sda >/dev/null 2>&1 && mount -t mxfs /dev/sda /mnt/mxfs && dmesg -C"
tools/mxfs_sshpass.sh test2 /tmp/.mxfs_pass "mount -t mxfs /dev/sda /mnt/mxfs && dmesg -C"

# Concurrent mkdir
tools/mxfs_sshpass.sh test1 /tmp/.mxfs_pass "for i in \$(seq 1 20); do mkdir /mnt/mxfs/t1_\$i 2>&1; done" &
tools/mxfs_sshpass.sh test2 /tmp/.mxfs_pass "for i in \$(seq 1 20); do mkdir /mnt/mxfs/t2_\$i 2>&1; done" &
wait

# Count (expect 40)
tools/mxfs_sshpass.sh test1 /tmp/.mxfs_pass "ls /mnt/mxfs/ 2>/dev/null | wc -l"
```
