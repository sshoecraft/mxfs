---
name: runsh-ssh-node-pipeline-swallows-remote-exit-status
description: PROVEN: run.sh ssh_node() returns grep's rc, not the remote command's — mount-readiness checks at lines 466/562 are decided by whether the host has a…
metadata:
  type: project
tags: [run.sh, ssh, harness-bug, RULE4, proxmox, prep_cluster, exit-status]
---

# run.sh `ssh_node()` discards the remote exit status — mount checks are decided by SSH banners

Found 2026-07-20 while debugging `MXFS_NODE_LIST=192.168.1.80 MXFS_DEV=/dev/sdb
./run.sh 1 xfs` failing `prep_cluster_xfs`'s final check against a Proxmox node
that was demonstrably mounted correctly. RULE-4 proven on the first
instrumentation pass, not guessed.

## The defect

```bash
ssh_node() { "$SSH" "$1" "$PASS" "$2" 2>&1 | grep -vE '^Warning:|^Unauthorized|^If you'; }
```

This is a **pipeline**. Bash without `pipefail` (and run.sh sets neither
`pipefail` nor `set -e`) returns the exit status of the **last** command — the
local `grep -vE`, never the remote command.

`grep -v` exits 0 only if it emits at least one line. So `ssh_node`'s exit
status answers "did SSH print anything that survived the banner filter?" — a
question with no relationship to what the remote command did.

Two callers consume that status, and both pass a remote command that is
**silent by construction**:

- `run.sh:562` (`prep_cluster_xfs`) — `mount | grep -q ' on $MNT type xfs'`
- `run.sh:466` (`prep_cluster`, the real mxfs cluster path) —
  `mount | grep -q ' on $MNT type mxfs'`

`grep -q` is quiet mode. It produces zero stdout by design. So the remote side
contributes nothing to the pipeline, and the verdict falls entirely to whatever
SSH itself emitted on stderr (merged in by `2>&1`).

## Measured evidence

Against pve1 (192.168.1.80), where the mount WAS present and correct:

```
TEST A  exact ssh_node pipeline            -> pipeline_rc=1  (0 bytes captured)
TEST B  same remote cmd, no local grep     -> ssh_only_rc=0
TEST C  remote mount line, byte-exact      -> /dev/sdb on /mnt/shared type xfs (rw,relatime,...)
                                              REMOTE_GREP_RC=0
```

The remote command succeeds (rc=0) and the mount line matches the pattern
exactly. The pipeline still reports failure.

Against test1, same pipeline, `cat -A` of the raw stream:

```
Warning: Permanently added 'test1' (ED25519) to the list of known hosts.^M$
$                                                    <-- blank line
Unauthorized access to this system is prohibited.$
$                                                    <-- blank line
If you are not an authorized user, disconnect immediately.$
```

`test1_pipeline_rc=0`.

## Why it flipped between rigs

The filter `^Warning:|^Unauthorized|^If you` removes the three text lines but
**not the two blank lines** in test1's `/etc/issue.net` login banner. Those
blank lines survive, `grep -v` emits them, and it exits 0.

- **test1/test2 (banner present)** → blank lines survive → check **always
  passes**, unconditionally, whether or not anything is mounted.
- **pve1/pve2 (Proxmox, no banner)** → nothing survives the filter → check
  **always fails**, whether or not anything is mounted.

Command substitution strips the trailing newlines, so `${#out}` reads 0 on test1
too — the surviving blank lines are invisible if you only inspect the captured
string. Use `cat -A` on the raw stream.

## Consequence for the historical matrix

`run.sh:466` is the readiness gate whose own comment (lines 456-461) explains it
must catch a stale/wedged leftover mount running an old module. **The mount half
of that gate has been inert on the test VMs for its entire life** — it returned
0 unconditionally. The srcversion half (line 469) still works, because that one
captures output and compares strings rather than relying on exit status.

This does not invalidate the 4-condition matrix results (a genuinely unmounted
node would fail the tests themselves), but a documented safety gate was never
actually gating.

## The fix

Preserve the remote status explicitly rather than letting the pipe define it:

```bash
ssh_node() {
    local out rc
    out=$("$SSH" "$1" "$PASS" "$2" 2>&1); rc=$?
    [ -n "$out" ] && printf '%s\n' "$out" | grep -vE '^Warning:|^Unauthorized|^If you'
    return $rc
}
```

Output filtering is unchanged for the many callers that capture and grep the
text; the exit status becomes meaningful for the two that consume it. Safe
because run.sh uses neither `set -e` nor `pipefail`, and because nothing can
legitimately depend on the current status — it was garbage.

Do **not** reach for `set -o pipefail` here: `grep -v` exits 1 whenever it
filters everything out, so pipefail would just invert the bug.

## This is a recurring class in run.sh

An earlier session already fixed the same shape in `run.sh::run_none()`, where
`out=$(cmd | grep ...); rc=$?` captured grep's status instead of `timeout`'s and
mislabeled killed tests as "no-result" — see
[[compiled-matrix-enforcement-and-perf-measurement-methodology]] and
[[ccloop-0220f43f-CRITERIA-MET-4conditions-32nodes]].

**When auditing run.sh: grep for `$?` after a pipeline, and for any function
whose body ends in a pipe while callers consume its exit status.**

## Related

[[infra-sshpass-wrapper-flattens-args-no-complex-scripts]] — `mxfs_sshpass.sh`
does `CMD="$*"`, flattening args; the same wrapper, a different failure mode.
Remote-execution plumbing in this repo has bitten twice now for reasons that
have nothing to do with the filesystem.
