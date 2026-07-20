#!/bin/bash
# suite_iter.sh — ONE full-suite iteration for the sess12(a9a03929) flake hunt:
# recycle all N VMs (fresh boot), wait for SSH, run the full ./run.sh suite,
# and print a one-line verdict plus FAIL details.  Meant to be invoked once
# per iteration (foreground or background) so each run gets a fresh cluster
# and the wedge probes (P36-STACK / P12-HOLDERTASK / P12-*) start with empty
# per-boot caps.
#
# Usage: tests/suite_iter.sh [N] [dlm]     (default 4 tcp)
set -u
N="${1:-4}"; DLM="${2:-tcp}"
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")"/.. && pwd)
cd "$REPO"

# sess15(a9a03929): destroy ALL 8 lab nodes, not just 1..N — leftover nodes
# from a previous wider run keep the LUN mounted and race the fresh mkfs's
# disklock zeroing (FS_PREP_FAIL rc=1, 4/tcp r4a).
for i in $(seq 1 8); do virsh -c qemu:///system destroy "test$i" >/dev/null 2>&1; done
sleep 3
for i in $(seq 1 "$N"); do virsh -c qemu:///system start "test$i" >/dev/null 2>&1; done
for i in $(seq 1 "$N"); do
    until timeout 5 tools/mxfs_sshpass.sh "test$i" /tmp/.mxfs_pass "hostname" 2>/dev/null | grep -q "test$i"; do sleep 3; done
done
echo "iter: nodes up, launching suite"

# sess14(a9a03929): the whole-suite cap is a WEDGE backstop, not a pace
# assertion — pace lives in run.sh's per-test budgets (RULE 0).  1100s fit a
# 4-node suite but truncated 8-node iters mid-dir_reuse (drc's budget alone is
# 100*N=800s at 8 nodes; 12 tests + drc + its fail-path artifact pull > 1100),
# silently dropping the last 4 tests (r4, 20260704T163522Z).  Budget: prep
# ~300s + Σ per-test budgets (~16×90s + drc 800s) ≈ 2540s → 2600.
MXFS_EXTRA_MODARGS="${MXFS_EXTRA_MODARGS:-watch_ino=999999999999}" timeout 2600 ./run.sh "$N" "$DLM" 2>&1 | tail -25

# sess12(a9a03929): harvest starvation-proximity signals from every node's
# dmesg BEFORE the next iteration's recycle wipes them — PASSING runs carry
# the near-miss distribution (P12-READOPT depth, worst page_ms, stack dumps).
H="/tmp/suite_iter_probes_$(date -u +%Y%m%dT%H%M%SZ).log"
for i in $(seq 1 "$N"); do
    echo "== test$i ==" >> "$H"
    timeout 20 tools/mxfs_sshpass.sh "test$i" /tmp/.mxfs_pass \
        "dmesg | grep -E 'P12-READOPT|P12-HOLDERTASK|P36-STACK|P67-AG-BAST-STALL|P15-REL-ABORT.*pin=[1-9]|P12-WORK ag=[0-9]+ (bail|COMMIT).*page_ms=[0-9]{4,}' | tail -40" 2>/dev/null | grep -v Warning >> "$H"
done
echo "probe harvest: $H"
