# The harness capture contract

What a harness must establish before a measurement taken over ssh can feed a
verdict about MXFS, why the boundary sits where it does, and what is still
open. The code is `tests/lib/rig.sh` (the helpers), `tools/mxfs_sshpass.sh`
(the ssh chokepoint's opt-in status record) and `scripts/harness_lint.py`
(the migration control). Ledger: D-A-TEST-HARNESS-CAN-REPORT-A-VERDICT-ABOUT-MXFS.

## The hazard

Every harness reaches the rig through one chokepoint, `tools/mxfs_sshpass.sh`,
so the remote command's stderr arrives on the harness's local stderr. The
helper most harnesses define,

```bash
rs() { timeout "$1" $SSH "$2" "$3" 2>/dev/null | filt; }
```

therefore discards the remote command's stderr and returns `filt`'s status.
A remote command that fails outright — the tool lives on the NFS share and a
freshly booted node has not mounted it; the device path belongs to another
rig; a python exception; the caller's timeout — leaves an empty or partial
capture. A `grep -c` over it reads 0, and a `ck`/`ckge` turns that 0 into a
statement about the filesystem. A zero from a broken instrument and a zero
from a clean system are the same number; only one of them is a result.

The second producer has the same signature with a non-empty capture: a probe
pointed at a device that does not exist on this rig captures the tool's
error text perfectly and the parser, finding no reservation stanza in it,
prints "RESERVATION: NONE HELD". Non-empty is not the test.

## The invariant

Before a measurement feeds an assertion about MXFS, the harness has
established, in the parent shell, that

1. the invocation completed with an acceptable status (remote exit, ssh,
   sshpass and the caller's timeout all observed, not `filt`'s),
2. its stdout holds the structure the tool always emits (anchored, per tool:
   `^slot=[0-9]+ headers=` for a slice scan, `^dumped slot=` for a dump,
   `^ino=[0-9]+ .*state=` for a dinode probe, `^(MOUNTED|NOT_MOUNTED)$` for
   a mount state, `claimed heartbeat slot` for a recovery kernel log), and
3. the capture belongs to this invocation (its own file in this lap's
   evidence directory, written by the acquisition that precedes it).

Otherwise the harness exits ABORT (2) naming the instrument, the node, the
status and the stderr file — never FAIL, never VACUOUS, never PASS. A
validated capture may legitimately count zero; that is the distinction being
restored.

Being alone does not exempt a measurement, and neither does the tool having
worked on the previous lap: the s54j/s54k laps ran the same probe that had
answered a minute earlier, on a node a prior lap had rebooted without its
share.

## The pieces

**`rsx <timeout> <node> <cmd>`** acquires a measurement. Its stdout is the
remote stdout, banner-filtered, byte for byte on success. The remote stderr
goes to its own file under `$OUT/rs_stderr/` (never merged: error text can
contain any string a parser recognizes, and 122 sites in 37 harnesses parse
the helper's last line). When the invocation's status is non-zero, one
record is appended on its own line and the status is returned:

    MXFS-RS-STATUS v=1 host=<node> rc=<n> err=<stderr file>

The record means "the invocation returned non-zero", never "MXFS failed". A
remote command whose non-zero status is expected (a `grep -c` with no
matches exits 1) states so itself (`|| true`); the wrapper reports status
mechanically and cannot know what a test expects.

**`capture_require <file> <shape> <what>`** is the boundary. Missing file,
status record present, empty, or no line matching the shape: ABORT. It is a
statement in the parent shell, because an `exit` inside `$(...)` ends the
substitution and not the harness — the assertion would still run. For the
same reason `cnt_require` (a counter that validates) does not exist.

**`ensure_src_or_abort <node>...`** is a prerequisite check: the share is
mounted and the tools the harnesses use are reachable through it. It is not
a substitute for validating the probe; the mount can go away afterwards, and
the s54k preparation failure shows why a prerequisite command's own
completion must be checked too (a later successful command in the same
remote list masks an earlier failure).

## The device under test is an identity, not a path

A path is a locator; the instrument is the LUN. `/dev/mapper/mpatha` exists
on the CAW multipath rig only, `/dev/sda` is the LUN on the TCP rig and a
path member of the multipath map on the other, and every node also carries
a root disk that answers any probe with well-formed output about the wrong
thing — an acquisition-status check and a shape check both pass while the
verdict is about another instrument (ledger
D-A-HARNESS-CAN-MEASURE-THE-WRONG-DEVICE-AND-REPORT-IT-AS-MXFS). The
design consult's ruling: discovery finds a candidate, an independent
declaration says which LUN is intended, and the two must agree before
anything measures or prepares it; a marker populated from whatever device
prep happened to select would certify the wrong disk after formatting it.

**The declaration.** `data/rigs.json` names each rig's shared LUN by its
SCSI identifier (the NAA WWID the nodes read from
`/sys/block/<disk>/device/wwid`, or a multipath map's dm uuid) under the
tag `tools/mxfs_rig_tag.sh` prints; `MXFS_LUN_WWID` names it for one run.
A rig with no entry resolves nothing — that is the fail-closed default. A
virtio disk has no WWID; the absence of identity evidence is a refusal,
never a fallback to path, size, model or filesystem uuid.

**The identity read.** `tests/setup/dev_identity.sh` runs on the node
(shipped inline over ssh, so a node without the share still answers) and
prints one line: the resolved path, its major:minor, the WWID, the MXFS
envelope superblock's filesystem uuid (a 4 KiB direct read of sector 0, so
a format is visible at once and the page cache cannot answer for the
platter; `none` when there is no MXFS magic), where that device is mounted
as mxfs, and the node's live mxfs mount whatever backs it.

**`mxfs_dev_resolve <node>`** sets `MXFS_DEV_RESOLVED`, `MXFS_DEV_WWID`,
`MXFS_DEV_FSID` and `MXFS_DEV_SOURCE`, and prints one `DEVICE` line into
the lap's log, separately from any tool output. The candidate is, in
order: `MXFS_DEV` when the caller set it; the device of the node's live
mxfs mount; the declared LUN by its own identifier
(`/dev/disk/by-id/wwn-0x<wwid>`); the transport's rig default only when
`MXFS_TRANSPORT` is explicit. Whatever chose it, the candidate must be a
block device on the node carrying the declared WWID, and when the node has
a live mxfs mount the candidate must be that mount's device by
major:minor — a caller may not name another device on a node that is
already measuring one. Bindings are per node: a re-login can make the same
LUN `/dev/sdb` on one node, and it resolves there by identity.

**`mxfs_dev_check <node>`** re-reads the bound path's identity and ABORTs
when the WWID or the filesystem uuid moved — the step before a
device-consuming command that follows a VM restart, a target re-login or a
format the harness did not perform itself. A harness that formats
resolves again afterwards: the uuid changes, the WWID must not.
**`mxfs_dev_same <node>...`** requires every node to resolve to the
declared LUN and the same filesystem uuid, one format generation.

**The marker.** `run.sh` records the WWID, the post-format uuid and a prep
generation in `.cluster_marker.json`, read by identity from the first
node, so "the LUN this cluster was prepped on, this format" is
distinguishable from "a device with the same name".

**Adjudication.** A site whose subject is a rig's storage configuration
(the multipath wiring check, a path-latency comparison, a host-side
backstore experiment) carries `# device-adjudicated: <why>` on the line, or
in the script's header when the whole script is that subject; the lint
lists them separately and they are an auditable disposition, not a runtime
bypass. A relic whose ssh style predates the library takes the device it is
given and says so (`${MXFS_DEV:?...}`), without the identity check.
Executable session chains that ran the `tcpmp` condition (TCP over the
multipath LUN) require the LUN to be named rather than assuming a rig
path; the condition is not rewritten into the TCP rig's default.

**Verification is rejection.** `tests/rig_lib_contract.sh` proves, against
real nodes: an absent path; the root disk on a mounted node (no SCSI
identity) and on an unmounted one (prep would have formatted it); the real
LUN under a different declaration — well-formed probes, a valid WWID and
uuid, the wrong instrument — on one node and with both nodes agreeing on
it; a binding whose path was swapped and one whose filesystem generation
changed; an undeclared rig with a transport default available; an
unreachable host. And the positive controls: the by-id alias resolves to
the same identity as the path, the unmounted node finds the LUN by its
identifier, both nodes agree on one generation.

**The chokepoint's status record** (`MXFS_RS_STATUS=1` in the environment)
makes `tools/mxfs_sshpass.sh` itself append the same record on a non-zero
status, for callers that still use the legacy helper. It is opt-in because a
legacy caller whose remote command legitimately exits non-zero would gain a
line its parse does not expect, and it is a diagnostic aid, not the fix: an
old `grep -c` still turns the record into a clean zero. The fix is the
boundary above, adopted per harness.

**`measure <node> <timeout> <file> <shape> <what> <cmd>`** is `rsx` into
the file and `capture_require` on it as one parent-shell statement, for the
common case of a one-shot measurement whose lines feed a verdict.

### Values and counts are assigned in the parent, never substituted

The second design consult (2026-09-18) widened the class: a verdict fed by
a VALUE taken straight from a remote substitution — `ino=$(rs 30 A "stat
-c %i f")`, `ck "mounted" "$(rs 20 B "grep -c mxfs /proc/mounts")" 1` — is
the same defect as a count over an empty capture. Nothing observed the
status or the shape; a failed ssh reads as an empty value (equal to an
expected "" or, after `tr`, to 0), a fabricated FAIL is still a verdict from
no measurement, and a producer can print the expected value and then fail.
The boundary for these is a statement in the parent shell that assigns the
variable, so no `$(...)` ever stands between the acquisition and the verdict:

- **`value_now_into <var> <node> <timeout> <file> <regex> <what> <cmd>`** — a
  scalar. The capture crosses the boundary, then exactly ONE line must match
  the anchored result regex (`^[0-9]+$`, `^B_RM rc=`, `^(OK|REFUSED)$`);
  none or several is an ABORT. The matching line is assigned whole.
- **`count_file_into <var> <file> <pattern>`** — a count over a capture that
  has already crossed. grep's status 1 is a legitimate zero; any other
  failure, or a value that is not a number, is an ABORT.
- **`window_into <file> <node> <timeout> [mark]`** — the kernel ring from a
  mark (or whole) into a file, requiring the invocation's status, the
  window's end marker and the mark itself (a window whose mark is not in
  the ring is not a window: every count in it would read zero). The harness
  then extracts locally.  **`window_count_into <var> <node> <timeout> <mark>
  <pattern> <tag>`** is that plus the count, the replacement for the
  per-assertion `cnt()`-over-ssh helper.
- **`wait_for_into <var> <node> <bound> <mark> <pattern>`** — the replacement
  for the polling `waitfor()` whose `timeout` could not tell a line the
  kernel never logged from an ssh that never ran. It polls, and on the bound
  the FINAL window crosses the boundary; only a valid window that genuinely
  lacks the pattern yields `timeout`.
- **`prep_require <file> <what>`** — a node preparation's own record
  (`NODE_PREP_OK`) is required; `NODE_PREP_FAIL`, or neither, is an ABORT
  even when a later command in the same remote list succeeded.
- **`capture_require_bg <file> <stderr-file> <shape> <what>`** — the boundary
  for a capture a background pipeline the harness itself started is writing.

**When the command IS the workload** — a read of the file under test, a
digest, an xattr, a PR OUT whose refusal is the finding — no shape can be
imposed on its output, because the content is the result. The command then
reports its own status on a line of its own (`; printf '\nREAD_RC=%s\n' $?`,
or the tool's `rc=` / `wrc=` line) and THAT line is the shape; the ssh's
status is what ABORTs, and the harness's own parse runs over the capture
minus the record. An empty digest is then the node failing to read, never
an ssh that did not run. A PERSISTENT RESERVE IN is the exception with a
shape: an answered one always carries `PR generation=`, an error message
does not.

**`MXFS_FAULT_RSX_NTH=<n>`** is the library-level rejection test: the n-th
measurement of the lap is issued to a host that does not resolve — a real
ssh failure at a real acquisition — and the library prints a `STAGE FAULT`
line on stderr when the injection is reached. The lap must then ABORT with
no verdict after that line. `tests/capture_fault_gate.sh` drives every
entry of `tests/capture_gate.manifest` through it (and, with `--healthy`,
through the unfaulted lap, which must exit 0), so adoption is checked by
rejection per harness rather than by reading.

**`scripts/harness_cnt_rewrite.py`** moves the recurring shapes across
mechanically — the `cnt()` helpers, the zero-argument `shut`/`knob`
helpers, the `waitfor()` polls, the bare remote substitutions
(`--shape remote --only-lint`, which infers the result shape from the
command itself: its echoed tag, the well-known one-line tools, a
`sed -n 's/^tag=//p'` pipe) and the local `filt()`/`rs()` headers. What it
cannot infer it lists, and those sites are read and converted by hand. It
rewrites only the lines the lint names as feeding a verdict: a polling loop
is not a measurement, and turning one into an ABORT would refuse a healthy
lap.

**`scripts/harness_lint.py`** lists every `ck`/`ckge` whose input is a count
over a capture file that no `capture_require` (or a `grep -q` whose failure
branch exits) guarded earlier in the same script; every verdict fed
straight from a remote substitution or from a variable last assigned from
one (mid-line reassignments included); and every local `rs()` that shadows
the library after it was sourced. It is textual and per file: it names
candidates and the residue, it does not adjudicate a flow. The two numbers
it prints are the migration control for the ledger record.

## What was chosen and what was rejected

The design consult (2026-09-18) ruled for the library as the fix, the
chokepoint record as an aid and the lint as the control, and against two
alternatives: a chokepoint-only change (a status marker still gives
`grep -c '^slot '` a zero, and merging remote stderr into stdout class-wide
would break the last-line parsers and let noisy stderr fabricate FAILs — the
opposite error), and a library without enforced, measured adoption ("shared
helper landed" would read as a completion while the old helpers stay
active).

The verification the ruling requires is rejection, not avoidance: the real
fault injected at the real acquisition point of a real harness — the share
unmounted on the probe node immediately before the platter probe, the node
preparation script unreachable on the recoverer, the PR probe given an
absent device — must ABORT with the failure text in the evidence and no
verdict, and the same laps must then pass on the healthy path.
`MXFS_FAULT_UMOUNT_SRC=<node>:<stage>` in the adopted harnesses is that
barrier; it is a real unmount, not a simulated one.

## What is open

- The lint is textual: it cannot see a capture rewritten between its guard
  and its assertion, a verdict reached through `printf -v` or a function's
  side effect, or a shape that is too loose for its tool. A lint at zero is
  the absence of the recurring shapes, not proof of every flow; the gate's
  rejection laps are the proof per harness, and a harness that cannot run
  on this rig (four or more nodes, the CAW multipath device) carries its
  lap as an open obligation.
- The identity check is check-then-use: a re-login between
  `mxfs_dev_check` and the command it guards is not caught; the window is
  the ssh round trip. Identity reads warm no filesystem cache (a direct
  sector read) but they are ssh round trips, so they sit outside timed
  windows.
- The declaration covers SCSI LUNs. A virtio or loop device carries no
  WWID and is refused; supporting one would need a provisioned identity of
  its own, not a serial that happens to be unique.
- A harness killed from outside leaves no capture; the enclosing runner must
  classify a missing completion as infrastructure, not as a verdict.
- Polls (`until … rs …`) that only pace a lap stay on the legacy helper by
  design; a poll that ends in a verdict is a `wait_for_into`.
