#!/bin/bash
# mxfs_admit_check.sh — node-side admission preflight for a shared MXFS LUN.
#
# Runs ON the node, before `mount -t mxfs <dev>`.  Refuses (exit 1, prints
# ADMIT_REFUSED: <why>) when the host is configured in a way that defeats
# MXFS's SCSI-3 persistent-reservation fencing; prints ADMIT_OK otherwise.
#
# Why this exists (D-PR-RETIREMENT-FAILURE-NOT-FAIL-CLOSED-377, item 3 of the
# sess377 design-consult ruling: "serialize against re-registration for the departing
# key — path addition, multipath recovery, multipathd replay").  MXFS derives
# ONE PR key per {host, boot, LUN} at mount, registers it itself, and retires
# it at unmount; a peer fences a dead node by PREEMPT AND ABORT of that key.
# multipath-tools has its own PR feature: with `reservation_key` set (in the
# defaults or a multipaths stanza, or `reservation_key file` +
# /etc/multipath/prkeys), multipathd REGISTERS that key on every path it adds
# or reinstates and replays it after a restart.  That registration is a second
# registrant on this node's I_T nexus that MXFS did not derive, cannot map to
# an incarnation, does not retire at unmount, and would be re-created by a
# path event AFTER a peer fenced the node — exactly the "unrecognised key with
# no trustworthy mapping" the ruling says must quarantine, and the
# re-registration that defeats the fence.  The kernel cannot see multipathd's
# configuration, so the check is a userspace gate, run by
# tests/setup/prep_node.sh (rig) and by operators (production) before mount.
#
# Usage: tools/mxfs_admit_check.sh <dev>        exit 0 ADMIT_OK / 1 ADMIT_REFUSED
#                                               / 2 INFRA (cannot decide)
set -u
DEV="${1:?usage: mxfs_admit_check.sh <dev>}"
[ -b "$DEV" ] || { echo "ADMIT_INFRA: $DEV is not a block device"; exit 2; }
REAL=$(readlink -f "$DEV"); BASE=$(basename "$REAL")
refused=0
say() { echo "[admit_check] $*"; }
refuse() { echo "ADMIT_REFUSED: $*"; refused=$((refused+1)); }

# 1. Is this a dm-multipath map?  Then multipathd's per-map key applies.
MAPNAME=""
if [ -r "/sys/block/$BASE/dm/name" ]; then
    MAPNAME=$(cat "/sys/block/$BASE/dm/name")
    say "dev=$DEV -> $REAL dm map '$MAPNAME'"
    if command -v multipathd >/dev/null 2>&1; then
        pk=$(timeout 10 multipathd -k"getprkey map $MAPNAME" 2>/dev/null | tr -d '[:space:]')
        case "$pk" in
            none) say "multipathd getprkey map $MAPNAME: none" ;;
            ""|fail|timeout)
                say "multipathd getprkey map $MAPNAME: no answer ('$pk') — multipathd not running or map unknown to it; static config checked below" ;;
            *)  refuse "multipathd holds reservation_key $pk for map $MAPNAME: it would REGISTER that key on every path add/reinstate and after a multipathd restart — a second registrant on this nexus that MXFS did not derive, does not retire at unmount and that re-registers after a peer's fence (D-377 item 3). Unset it: multipathd -k'unsetprkey map $MAPNAME' and remove reservation_key from multipath.conf." ;;
        esac
    else
        say "multipathd not installed; map $MAPNAME has no key manager"
    fi
fi

# 2. Static configuration: an effective reservation_key anywhere in the
#    multipath configuration is refused even when the running daemon has not
#    applied it yet (it will on the next path event or restart).
if command -v multipathd >/dev/null 2>&1; then
    cfg=$(timeout 10 multipathd show config 2>/dev/null | grep -nE '^[[:space:]]*reservation_key[[:space:]]' | head -3)
    if [ -n "$cfg" ]; then
        refuse "multipath configuration sets reservation_key ($(echo "$cfg" | tr '\n' ';')): multipathd would register a key MXFS does not own (D-377 item 3). Remove it and restart multipathd."
    else
        say "multipathd effective config: no reservation_key"
    fi
fi
for f in /etc/multipath.conf /etc/multipath/conf.d/*.conf; do
    [ -r "$f" ] || continue
    hit=$(grep -nE '^[[:space:]]*reservation_key[[:space:]]' "$f" | head -2)
    [ -z "$hit" ] || refuse "$f sets reservation_key ($(echo "$hit" | tr '\n' ';')) (D-377 item 3)"
done
if [ -s /etc/multipath/prkeys ]; then
    refuse "/etc/multipath/prkeys is non-empty ($(wc -l < /etc/multipath/prkeys) entries): multipathd 'reservation_key file' keys would be registered on path events (D-377 item 3)"
fi

if [ "$refused" = 0 ]; then echo "ADMIT_OK dev=$DEV${MAPNAME:+ map=$MAPNAME} multipath_reservation_key=none"; exit 0; fi
exit 1
