#!/bin/bash
# scst_pr_bounds_check.sh — build and run the SCST PR READ FULL STATUS bounds
# proof (tests/scst_pr_fullstatus_bounds.c), and assert that the SCST module
# actually installed on this host carries the fix.
#
# Two independent checks:
#   1. Arithmetic proof, in userspace, against a guard page — shows the old
#      loop writes out of bounds and the new one does not.  Zero risk: it
#      never touches the kernel.
#   2. Installed-module identity — the running/installed scst.ko must be
#      +caw-abort-reclaim.4 or newer.  Anything older still corrupts host
#      memory once the registrant list outgrows an initiator's probe buffer.
#
# See tests/scst_pr_fullstatus_bounds.c for the full failure chain.
set -u

REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SRC="$REPO/tests/scst_pr_fullstatus_bounds.c"
BIN=$(mktemp -d)/scst_pr_fullstatus_bounds
REGS="${1:-64}"          # 32 dual-path nodes
BUFSZ="${2:-4096}"       # MXFS's probe buffer (pal/linux/kern.c)
rc=0

echo "=== 1. arithmetic proof (guard page) ==="
cc -O2 -Wall -Wextra -o "$BIN" "$SRC" || { echo "BUILD FAILED"; exit 2; }
"$BIN" "$REGS" "$BUFSZ" || rc=1

echo
echo "=== 2. installed SCST module identity ==="
ver=$(modinfo scst 2>/dev/null | awk '/^version:/{print $2}')
echo "installed scst version: ${ver:-<not installed>}"
minor=$(printf '%s' "$ver" | sed -n 's/.*+caw-abort-reclaim\.\([0-9]\+\)$/\1/p')
if [ -z "$minor" ]; then
    echo "FAIL: cannot parse a +caw-abort-reclaim.N suffix — this is not the"
    echo "      patched fork, so the PR READ FULL STATUS overflow is present."
    rc=1
elif [ "$minor" -lt 4 ]; then
    echo "FAIL: +caw-abort-reclaim.$minor predates the PR bounds fix (.4)."
    rc=1
else
    echo "OK: carries the PR READ FULL STATUS bounds fix (.4+)."
fi

# The target driver embeds SCST_INTERFACE_VERSION == SCST_VERSION_STRING plus
# SCST_INTF_VER plus SCST_CONST_VERSION, so it reads as the scst version with
# extra trailing digits (e.g. "...reclaim.4" + "1").  SCST refuses to register
# a target template whose interface version differs, so a stale iscsi-scst.ko
# means the target simply will not come up — catch it here instead.
iver=$(strings /lib/modules/"$(uname -r)"/extra/iscsi-scst.ko 2>/dev/null |
       grep -o '3\.[0-9.]*-pre+caw-abort-reclaim\.[0-9]*' | sort -u | head -1)
echo "iscsi-scst built against: ${iver:-<unknown>}"
case "$iver" in
    "$ver"*) echo "OK: iscsi-scst matches the installed SCST core." ;;
    "")      echo "WARN: could not read iscsi-scst.ko's interface version." ;;
    *)       echo "FAIL: iscsi-scst.ko was built against a different SCST core —"
             echo "      rebuild /src/scst/iscsi-scst before loading the target."
             rc=1 ;;
esac

echo
[ "$rc" -eq 0 ] && echo "scst_pr_bounds_check: PASS" || echo "scst_pr_bounds_check: FAIL"
exit "$rc"
