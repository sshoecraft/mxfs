---
name: trap-a-harness-run-inside-a-while-read-loop-drains-the-manifest-as-its-stdin-and-the-loop-runs-one-entry
description: TRAP (s58g, capture gate): a harness launched inside `while read line; do ...; done < manifest` inherits the manifest as stdin; a legacy ssh helper d…
metadata:
  type: feedback
---

# A harness run inside a `while read` loop eats the loop's input

**Observed (session 58, tests/capture_fault_gate.sh over chunked manifests):** chunks of 2-4
manifest entries reported `entries=1` and only their first harness ran. The gate's loop is
`while IFS= read -r line; do ...; timeout N tests/$h.sh ...; done < "$MANIFEST"`. The harness
inherits the manifest file as its stdin; any ssh inside it that does not redirect stdin
(`rs()` legacy helpers, a bare `$SSH host cmd`) reads and discards the remaining lines. The
library's `rsx` uses `< /dev/null` (which is why some chunks — rejoin_residue, the d0532
pair — ran fully) and the legacy helpers do not.

**Why it matters:** the loop exits normally with `RESULT: PASS entries=1`, so a manifest of
55 harnesses can "pass" having run a handful, and nothing in the output says so unless
`entries=` is compared with the manifest's count.

**Fix:** `< /dev/null` on every command launched inside the loop (both laps of the gate), and
compare `entries=` against the manifest count when reading a gate result. Chunked runs
from earlier in the session are only valid for the entries that printed a GATE line.

**Also in the same session:** `tools/chk_mxfs -v` on the live LUN reported "bootstrap
record: fs_uuid X is not this volume's" while another harness's prep was formatting it — a
torn read across a format, gone on the next read. An identity read taken while someone else
formats is not a defect report; resolve again and compare.
