#!/bin/bash
# tests/pr_all_registrants_semantics.sh
#
# D-DIRTY-SLICE-DEPARTURE-RETIRES-FENCE-KEY-UNMOUNTABLE-379, fix-shape F1.
#
# Measures, on the REAL target, whether WRITE EXCLUSIVE - ALL REGISTRANTS
# (type 0x07) has the property MXFS needs and WE-RO (0x05) lacks:
#   "the reservation survives removal of the holder's registration while
#    at least one other registrant remains."
#
# Uses a scratch key issued from an UNMOUNTED node, so no MXFS node's own
# registration is touched.  Read-mostly on the other nodes: under an
# all-registrants Write Exclusive type every registrant may still write,
# exactly as under WE-RO, so mounted peers are unaffected.
#
# Usage: tests/pr_all_registrants_semantics.sh <spare-host> <observer-host> [dev]
set -u
SPARE="${1:?spare (unmounted) host}"
OBS="${2:?observer host}"
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
MXFS_DEV=${3:-${MXFS_DEV:-}}; mxfs_dev_resolve "$SPARE"; DEV=$MXFS_DEV_RESOLVED
SK=0xdeadbeef
SSH="$(dirname "$0")/../tools/mxfs_sshpass.sh"
sp() { timeout 30 "$SSH" "$SPARE" "sg_persist $* $DEV 2>&1 | tail -6"; }
look() { timeout 30 "$SSH" "$OBS" "sg_persist --in --read-reservation $DEV 2>&1 | tail -4; echo -n 'keycount='; sg_persist --in --read-keys $DEV 2>&1 | grep -cE '^ *0x'"; }
strip() { grep -vE 'Unauthorized|not an authorized|^$|Warning:|SCST_FIO|Peripheral device'; }

echo "### 0. baseline (observer=$OBS)";            look | strip
echo "### 1. register scratch key $SK from $SPARE"; sp --out --register-ignore --param-sark=$SK | strip
echo "### 2. state after register";                 look | strip
echo "### 3. RESERVE type 7 (WE-AR) with $SK";      sp --out --reserve --param-rk=$SK --prout-type=7 | strip
echo "### 4. state after reserve  <-- expect held, 'all registrants'"; look | strip
echo "### 5. UNREGISTER the holder key $SK";        sp --out --register --param-rk=$SK --param-sark=0 | strip
echo "### 6. state after holder unregisters  <-- THE QUESTION"; look | strip

# --- part 2: does RESERVE(type 7) from a SECOND registrant return GOOD? ---
# (SPC-4: under an all-registrants type every registrant is already a holder,
#  so a matching-scope/type RESERVE must be a successful no-op.)
if [ "${PART2:-0}" = 1 ]; then
KA=0xaaaa0001; KB=0xbbbb0002
p1() { timeout 30 "$SSH" "$SPARE" "sg_persist $* /dev/sda 2>&1 | tail -4; echo rc=\$?"; }  # device-adjudicated: two I_T nexuses to the one LUN on the spare node are the subject (ALL_REGISTRANTS semantics per nexus); the LUN itself is resolved by identity above
p2() { timeout 30 "$SSH" "$SPARE" "sg_persist $* /dev/sdb 2>&1 | tail -4; echo rc=\$?"; }  # device-adjudicated: two I_T nexuses to the one LUN on the spare node are the subject (ALL_REGISTRANTS semantics per nexus); the LUN itself is resolved by identity above
echo "### P2.1 register KA on nexus /dev/sda"; p1 --out --register-ignore --param-sark=$KA | strip  # device-adjudicated: two I_T nexuses to the one LUN on the spare node are the subject (ALL_REGISTRANTS semantics per nexus); the LUN itself is resolved by identity above
echo "### P2.2 register KB on nexus /dev/sdb"; p2 --out --register-ignore --param-sark=$KB | strip  # device-adjudicated: two I_T nexuses to the one LUN on the spare node are the subject (ALL_REGISTRANTS semantics per nexus); the LUN itself is resolved by identity above
echo "### P2.3 RESERVE type7 with KA";         p1 --out --reserve --param-rk=$KA --prout-type=7 | strip
echo "### P2.4 RESERVE type7 with KB  <-- expect GOOD, not CONFLICT"; p2 --out --reserve --param-rk=$KB --prout-type=7 | strip
echo "### P2.5 state"; look | strip
echo "### P2.6 RELEASE type7 with KB (any registrant is a holder)"; p2 --out --release --param-rk=$KB --prout-type=7 | strip
echo "### P2.7 state after release <-- expect NONE HELD"; look | strip
echo "### P2.8 unregister KA, KB";  p1 --out --register --param-rk=$KA --param-sark=0 | strip; p2 --out --register --param-rk=$KB --param-sark=0 | strip
echo "### P2.9 final state"; look | strip
fi
