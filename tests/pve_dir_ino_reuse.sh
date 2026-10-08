#!/bin/bash
# pve_dir_ino_reuse.sh — when one host of a two-host MXFS pair removes a
# directory the other host has been using and makes a new one that reuses its
# inode number, the other host's first operations in the new directory must
# succeed.
#
# Seen under tests/pve_churn_fairness.sh on the nested pair (0.90.97,
# 2026-10-07): each run's shared directory, made by participant 0 after the
# previous run's was removed, came back as the same inode (2884), and the
# first append of 3-5 of participant 1's 8 loops into it failed while
# P34H-INCARN-POISON counted up on participant 1.  The loops discard stderr,
# so the error was not known.
#
# Each round: participant 0 makes OLD; participant 1 creates and appends
# files in it (its in-core copy of OLD now holds a grant); participant 0
# removes OLD with everything in it and makes NEW until NEW reuses OLD's inode
# number (up to TRIES directories); then participant 1, at once and with
# PAR writers in parallel, appends to a file in NEW, creates one, renames it
# and lists NEW, each with its error text captured.  Every operation must
# succeed and NEW's listing must show what was written.
#
# Usage: tests/pve_dir_ino_reuse.sh
# Env:
#   PVE_PAIR   "<addr> <addr>" (default "192.168.120.137 192.168.120.192",
#              nested pair A); participant 0 is the lower address
#   ROUNDS     rounds (default 5)
#   PAR        participant 1's parallel writers into NEW (default 8)
#   TRIES      directories participant 0 may make looking for the reused
#              number (default 20)
# Evidence: tests/evidence/pve_dir_ino_reuse/<UTC stamp>-<participant 0>/
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
read -r -a PAIR <<<"${PVE_PAIR:-192.168.120.137 192.168.120.192}"
if python3 -I -c 'import ipaddress, sys; sys.exit(0 if ipaddress.ip_address(sys.argv[1]) < ipaddress.ip_address(sys.argv[2]) else 1)' "${PAIR[0]}" "${PAIR[1]}"; then
    P0=${PAIR[0]}; P1=${PAIR[1]}
else
    P0=${PAIR[1]}; P1=${PAIR[0]}
fi
ROUNDS=${ROUNDS:-5}
PAR=${PAR:-8}
TRIES=${TRIES:-20}
MNT=/mnt/shared
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
EVID="$REPO/tests/evidence/pve_dir_ino_reuse/$STAMP-$P0"
mkdir -p "$EVID" || exit 1
BASE=$MNT/dirreuse/$STAMP
say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$EVID/log"; }
on() {  # <host> <cmd> [timeout]
    timeout "${3:-60}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}
FAIL=0
for h in "$P0" "$P1"; do
    s=$(on "$h" "echo name=\$(hostname) build=\$(cat /sys/module/mxfs/srcversion) poison=\$(journalctl -k -b --no-pager | grep -c P34H-INCARN-POISON) mnt=\$(awk '\$2 == \"$MNT\" && \$3 == \"mxfs\" {print \$2}' /proc/mounts)" 20)
    say "$h: $s"
    case "$s" in *"mnt=$MNT"*) ;; *) say "ABORT: $h has no MXFS mount on $MNT"; exit 1 ;; esac
done
on "$P0" "mkdir -p $BASE && echo MADE" 30 | grep -q MADE || { say "ABORT: could not make $BASE"; exit 1; }

for r in $(seq 1 "$ROUNDS"); do
    OLD=$BASE/r$r.old
    oino=$(on "$P0" "mkdir $OLD && stat -c %i $OLD" 30 | tail -1)
    # participant 1 works in OLD: its in-core OLD holds a grant afterwards
    out=$(on "$P1" "for k in \$(seq 1 $PAR); do echo p1 \$k >> $OLD/f.\$k || echo ERR; done; ls $OLD | wc -l" 60)
    say "round $r: OLD $OLD inode $oino; participant 1 wrote in it: $(tr '\n' ' ' <<<"$out")"
    # participant 0 removes OLD and makes directories until one reuses its number
    nino=""; NEW=""
    for t in $(seq 1 "$TRIES"); do
        cand=$BASE/r$r.new$t
        i=$(on "$P0" "[ -d $OLD ] && rm -rf $OLD; mkdir $cand && stat -c %i $cand" 30 | tail -1)
        if [ "$i" = "$oino" ]; then nino=$i; NEW=$cand; break; fi
    done
    if [ -z "$NEW" ]; then
        say "round $r: no new directory reused inode $oino in $TRIES tries; round not counted"
        continue
    fi
    say "round $r: participant 0 removed OLD and made $NEW, inode $nino (reused)"
    # participant 1, at once, in parallel: append, create, rename, list
    res=$(on "$P1" "for k in \$(seq 1 $PAR); do ( e=\$( { echo p1 \$k >> $NEW/shared.\$k; } 2>&1 ) || echo \"ERR append \$k: \$e\"; e=\$( { echo x > $NEW/c.\$k; } 2>&1 ) || echo \"ERR create \$k: \$e\"; e=\$(mv $NEW/c.\$k $NEW/c.\$k.r 2>&1) || echo \"ERR rename \$k: \$e\" ) & done; wait; e=\$(ls $NEW 2>&1) || echo \"ERR list: \$e\"; echo LISTED \$(ls $NEW 2>/dev/null | wc -l); echo POISON \$(journalctl -k -b --no-pager | grep -c P34H-INCARN-POISON)" 90)
    echo "$res" | sed "s/^/  /" | tee -a "$EVID/log"
    errs=$(grep -c '^ERR' <<<"$res")
    listed=$(sed -n 's/^LISTED //p' <<<"$res")
    if [ "$errs" != 0 ] || [ "$listed" != $(( 2 * PAR )) ]; then
        say "round $r: FAIL ($errs errors, $listed entries listed, $(( 2 * PAR )) expected)"
        FAIL=1
    else
        say "round $r: participant 1's $PAR writers all succeeded in the reused directory"
    fi
done
on "$P1" "journalctl -k -b --no-pager -o short-precise | tail -n 400" 60 > "$EVID/klog.$P1"
on "$P0" "journalctl -k -b --no-pager -o short-precise | tail -n 400" 60 > "$EVID/klog.$P0"
on "$P0" "rm -rf $BASE; echo GONE" 120 >/dev/null
[ $FAIL = 0 ] && say "PASS: evidence $EVID" || say "FAILED: evidence $EVID"
exit $FAIL
