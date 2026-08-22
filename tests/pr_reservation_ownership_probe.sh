#!/bin/bash
# tests/pr_reservation_ownership_probe.sh
#
# D-DIRTY-SLICE-DEPARTURE-RETIRES-FENCE-KEY-UNMOUNTABLE-379, step 0.
#
# QUESTION: who owns the WE-RO persistent reservation, and what happens to it
# when that node departs cleanly?
#
# HYPOTHESIS H1: the reservation is held by exactly ONE I_T nexus (the first
# node to RESERVE).  SPC-4 releases a *_REGISTRANTS_ONLY reservation when the
# holder's registration is removed.  MXFS unregisters its key unconditionally at
# put_super, and no survivor re-reserves -> a single clean unmount of the holder
# disarms fencing CLUSTER-WIDE (kind=NO_RESERVATION(8) for every later fence).
#
# Usage: tests/pr_reservation_ownership_probe.sh <observer-host> [dev]
#   Prints holder key + initiator IQN + key count.  Read-only; safe to re-run.
#
set -u
OBS="${1:-test1}"
DEV="${2:-/dev/mapper/mpatha}"
SSH="$(dirname "$0")/../tools/mxfs_sshpass.sh"

out=$(timeout 40 "$SSH" "$OBS" "sg_persist --in --read-reservation $DEV 2>&1; sg_persist --in --read-full-status $DEV 2>&1; echo '###KEYS###'; sg_persist --in --read-keys $DEV 2>&1" 2>/dev/null)

# Count only the key lines themselves.  Anchoring on "^ *0x...$" excludes the
# "PR generation=0x8a4" header, which an unanchored hex match would count as a
# 33rd key, and does not drop keys whose hex form is shorter than 8 digits.
klines=$(echo "$out" | sed -n '/###KEYS###/,$p' | grep -E '^ *0x[0-9a-f]+$' | tr -d ' ')
nkeys=$(echo "$klines" | grep -c . )
ndistinct=$(echo "$klines" | sort -u | grep -c . )

# The holder stanza: "<< Reservation holder >>" then type, then the initiator id.
holder_key=$(echo "$out" | awk '
  /^ *Key=0x/ { k=$1; sub("Key=","",k) }
  /Reservation holder/ { print k; exit }')
holder_iqn=$(echo "$out" | awk '
  /Reservation holder/ { seen=1 }
  seen && /world wide unique port id/ { print $NF; exit }')
rtype=$(echo "$out" | awk '/Reservation holder/{seen=1} seen && /type:/{ sub(/.*type: /,""); print; exit }')

# READ RESERVATION is the authority on whether one is held and of what type.
# READ FULL STATUS only tells us WHICH nexus is the holder, and under an
# all-registrants type that question has no single answer (SPC reports the
# reservation key as 0 and every registrant is a holder), so the IQN is
# reported only for single-holder types.
rr=$(echo "$out" | sed -n '/Reservation follows/,/type:/p')
[ -n "$rr" ] || { echo "RESERVATION: NONE HELD   keys=$nkeys distinct=$ndistinct   (observer=$OBS)"; exit 2; }
rtype=$(echo "$rr" | sed -n 's/.*type: //p' | head -1)
case "$rtype" in
  *"all registrants"*)
      echo "RESERVATION: HELD type='$rtype' holder=ALL-REGISTRANTS keys=$nkeys distinct=$ndistinct (observer=$OBS)";;
  *)
      echo "RESERVATION: HELD type='$rtype' holder_key=$holder_key iqn=$holder_iqn keys=$nkeys distinct=$ndistinct (observer=$OBS)";;
esac
exit 0
