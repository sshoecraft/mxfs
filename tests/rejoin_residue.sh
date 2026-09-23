#!/bin/bash
# rejoin_residue.sh — D-TCP-SLOT-SUCCESSOR-IMPORTS-PREDECESSOR-SHARED-BIT-AS-
# OWN-GRANT-REJOIN-MOUNT-HANGS-IGET-0904: a node that leaves cleanly and
# rejoins the same heartbeat slot within seconds must not inherit its
# predecessor incarnation's shared ledger grants.  The race is made
# deterministic with the 0.75.5 debug parameter depart_purge_delay_ms on the
# surviving master A: its departure worker holds the departed owner's ledger
# purge for DELAY_MS, so B's rejoin activates the departed slot's pages
# before the purge reaches them (the losing order of s509d, where the rig
# lost it by two seconds).
#
# Which node MASTERS the root inode's ledger page decides the shape the
# residue takes: master = active_nodes[page % N] over the id-SORTED active
# list, so with two nodes the lower id masters the even pages and the higher
# id the odd ones.  When B's new incarnation masters the page it IMPORTS the
# predecessor's bit as its own grant (the s509d hang shape, fixed in 0.75.5 by
# releasing it: P-TAUTH-IMPORT-RESIDUE); when A masters it, B's root-inode
# request waits at A behind the bit until A's purge clears it (s510b: a 19 s
# mount against 6 s plain).  A random id lands on either side, which is why
# s510b's single armed lap saw no residue line.  The 0.75.6 debug parameter
# node_id_override pins B's id on each side in turn, so both shapes are
# measured every lap and the import shape is certain to run once.
#
# Arms (both nodes start mounted on TCP, from a prep):
#   1  armed LOW:  A's purge delayed; B leaves and rejoins at once with
#      node_id_override=ID_LOW (sorts first: masters the even pages).
#   2  armed HIGH: the same with node_id_override=ID_HIGH (sorts last: the
#      odd pages).
#      Per armed lap: B's mount must return 0 within JOIN_BOUND, zero 'DLM
#      inode lock failed: ino=128', zero P47-FILEBLOCK, zero P-DEMWAIT-
#      REDRIVE (the s509d hang shape), and a file written on each node must
#      read back on the other.  A must log P-DEPART-PURGE-DELAY and no
#      P278-HB-STALL / P-HB-MONSLOW.  Since 0.75.16 a clean departure
#      releases its remaining grants through the DLM before the goodbye
#      (P-RELALL-WIRED held_after=0 on B's leave), so B must log ZERO
#      P-TAUTH-IMPORT-RESIDUE on either parity, A's held purge must find
#      nothing to clear (P-TAUTH-PURGE cleared=0 cand=0) and A must never
#      attribute a slot-1 bit on ino=128 to the successor.
#   3  plain: knob cleared, random id; B leaves and rejoins again.  Same
#      assertions.
#   4  (RR_HELD_ARM=1, 0.75.6; reshaped 0.75.16) planted: B's departure is
#      made to leave its grants behind (depart_wire_release=0), A's purge is
#      delayed again and B rejoins with tauth_import_residue_release=0 — on
#      both parities (fresh ids ID_LOW+1 and ID_HIGH-1).  On B's parity the
#      DLM keeps the residue as B's own grant (P-TAUTH-IMPORT-RESIDUE-HELD,
#      the pre-0.75.5 shape); on A's parity A attributes the bit to B.  Each
#      lap: B's xfs_iget sees the blocked-upgrade refusal, releases the
#      phantom itself (P109-EDEADLK-NL, one lap, nak_rc=0) and mounts within
#      the same bound, with the one joiner-mount self-BAST bail honored
#      (P70-BP EXIT=full) and zero P47-FILEBLOCK / P-DEMWAIT-REDRIVE; over
#      the two laps HELD >= 1.
# The rig is left with both nodes mounted on TCP.
#
# budget: an armed cycle = leave (~5 s) + rejoin (6-19 s measured, 40 s
# bound) + the DELAY_MS+10 s wait for A's held purge = ~50 s; the plain
# cycle ~15 s.  Two armed + plain = ~115 s expected, bound 250 s; the planted
# arm adds two armed cycles: 400 s.
# Usage: tests/rejoin_residue.sh <label> [A=test1] [B=test2]
# Env:   MXFS_DEV (default: the device of A's live mxfs mount, resolved by
#        mxfs_dev_resolve — no rig's device path is assumed), MXFS_MNT,
#        RR_DELAY_MS (default 15000), RR_MODARGS for B's rejoin (default
#        target_cache_protected=1 — the adopting joiner), RR_ID_LOW /
#        RR_ID_HIGH (default 100 / 4000000000), RR_HELD_ARM=1 to run arm 4,
#        MXFS_FAULT_UNREACHABLE=<stage> (capture-contract verification only:
#        the named acquisition, join_<tag> e.g. join_1b, is issued to a host
#        that does not resolve — a real ssh failure — and the lap must then
#        ABORT, never reach a verdict).
#
# Every capture a verdict is taken from crosses tests/lib/rig.sh's boundary
# (rsx + capture_require in the parent shell) before it is counted.
set -u
LABEL=${1:?label}
A=${2:-test1}
B=${3:-test2}
cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
MNT=${MXFS_MNT:-/mnt/shared}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
DELAY_MS=${RR_DELAY_MS:-15000}
MODARGS=${RR_MODARGS:-target_cache_protected=1}
ID_LOW=${RR_ID_LOW:-100}
ID_HIGH=${RR_ID_HIGH:-4294967294}   # one below MXFS_DLM_NODE_UNKNOWN: any random id sorts below it
RR_HELD_ARM=${RR_HELD_ARM:-0}
HELD_ARM=0
KO=/root/mxfs.ko.prep
P=/sys/module/mxfs/parameters
JOIN_BOUND=40
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_rejoin_residue_$LABEL
mkdir -p "$OUT"
fails=0
ck() { if [ "$2" = "$3" ]; then echo "  PASS $1 ($2)"; else echo "  FAIL $1 got=$2 want=$3"; fails=$((fails+1)); fi; }
ckge() { if [ "${2:-0}" -ge "$3" ] 2>/dev/null; then echo "  PASS $1 ($2 >= $3)"; else echo "  FAIL $1 got=${2:-?} want>=$3"; fails=$((fails+1)); fi; }
# rs/rsx/capture_require/require_epoch/mxfs_dev_resolve (tests/lib/rig.sh)
. "$(dirname "$0")/lib/rig.sh"
sshq() { rs "$@"; }
# jl <node> <mark> > <file>: a kernel journal window; the caller validates
# the file with capture_require 'kernel: ' before counting anything in it
jl() { rsx 20 "$1" "journalctl -k --since @$2 --no-pager 2>/dev/null | cut -c1-700"; }
field() { grep -ao "^$2=[^ ]*" "$1" | head -1 | cut -d= -f2; }
fault_host() { # <stage> <node> -> the node to acquire from
    if [ "${MXFS_FAULT_UNREACHABLE:-}" = "$1" ]; then
        echo "STAGE FAULT: acquiring $1 from an unresolvable host instead of $2" >&2
        echo "$2-unreachable.invalid"
    else
        echo "$2"
    fi
}

leave() {   # <node> <tag>
    local lm; lm=$(rsx 10 "$1" "date +%s" | tail -1)
    require_epoch "$lm" "$2: $1's clock mark before its departure"
    rsx 70 "$1" "mountpoint -q $MNT && timeout 40 umount $MNT; echo UMOUNT_RC=\$?; for i in 1 2 3 4 5 6; do rmmod mxfs 2>/dev/null; lsmod | grep -q '^mxfs' || break; sleep 2; done; lsmod | grep -q '^mxfs' && echo STILL_LOADED || echo UNLOADED" > "$OUT/$2_leave.txt"
    capture_require "$OUT/$2_leave.txt" '^(UNLOADED|STILL_LOADED)$' "$2: the departure of $1"
    # the departing node's own record of what its unmount left behind
    # (0.75.15 P-RELALL-LEFT census, the ledger close stats)
    jl "$1" "$lm" > "$OUT/$2_leave_journal.txt"
    capture_require "$OUT/$2_leave_journal.txt" 'kernel: ' "$2: the kernel journal on $1 across its departure"
    ck "$2: $1 unmounted (rc=$(field "$OUT/$2_leave.txt" UMOUNT_RC)) and unloaded" "$(grep -c '^UNLOADED' "$OUT/$2_leave.txt")" "1"
    echo "  INFO $2: $(grep -a 'P-RELALL-LEFT\|P-RELALL-WIRED\|P-TAUTH-STATS why=close\|P-TAUTH-DLM-STATS' "$OUT/$2_leave_journal.txt" | sed 's/.*kernel: //; s/mxfs: mxfs: //; s/mxfs: tauth: //' | cut -c1-220 | tr '\n' '|' | cut -c1-1000)"
}
# join <node> <tag> <residue_min>: the mount runs under nohup so a hung one
# (the defect) is observable and cannot hold the ssh; its task stack is
# captured if it has not returned by JOIN_BOUND.  Sets NRES to the residue
# count the join logged.
NRES=0
join() {
    local h; h=$(fault_host "join_$2" "$1")
    rsx $(( JOIN_BOUND + 30 )) "$h" "M=\$(date +%s); echo MARK=\$M; insmod $KO $MODARGS; echo INSMOD_RC=\$?; rm -f /root/rr_mount.rc; T0=\$(date +%s); nohup sh -c 'mount -t mxfs $DEV $MNT; echo \$? > /root/rr_mount.rc' >/dev/null 2>&1 & for i in \$(seq 1 $JOIN_BOUND); do sleep 1; [ -f /root/rr_mount.rc ] && break; done; if [ -f /root/rr_mount.rc ]; then echo MOUNT_RC=\$(cat /root/rr_mount.rc); else echo MOUNT_RC=HUNG; for p in \$(pidof mount); do echo \"--- mount pid \$p state \$(awk '{print \$3}' /proc/\$p/stat)\"; cat /proc/\$p/stack; done; fi; echo WALL=\$(( \$(date +%s) - T0 )); journalctl -k --since @\$M --no-pager 2>/dev/null | grep -a 'DLM init: node_id=' | tail -1 | sed 's/.*node_id=\([0-9]*\).*transport=\([a-z]*\).*/NODE_ID=\1\nTRANSPORT=\2/'; journalctl -k --since @\$M --no-pager 2>/dev/null | grep -ao 'claimed heartbeat slot [0-9]*' | tail -1 | sed 's/.*slot /SLOT=/'; mountpoint -q $MNT && echo MOUNTED || echo NOT_MOUNTED" > "$OUT/$2_join.txt"
    capture_require "$OUT/$2_join.txt" '^(MOUNTED|NOT_MOUNTED)$' "$2: the join of $1"
    capture_require "$OUT/$2_join.txt" '^MARK=[0-9]+$' "$2: the clock mark of $1's join"
    jl "$1" "$(field "$OUT/$2_join.txt" MARK)" > "$OUT/$2_join_journal.txt"
    capture_require "$OUT/$2_join_journal.txt" 'kernel: ' "$2: the kernel journal on $1 across its join"
    local rc; rc=$(field "$OUT/$2_join.txt" MOUNT_RC)
    ck "$2: $1 mounted (rc=${rc:-?} wall=$(field "$OUT/$2_join.txt" WALL)s, bound ${JOIN_BOUND}s)" "${rc:-?}" "0"
    ck "$2: $1 came up on transport=tcp ($(field "$OUT/$2_join.txt" TRANSPORT))" "$(field "$OUT/$2_join.txt" TRANSPORT)" "tcp"
    ck "$2: $1 admitted (P-DOMAIN-ADMITTED)" "$(grep -ac 'P-DOMAIN-ADMITTED' "$OUT/$2_join_journal.txt")" "1"
    echo "  INFO $2: $1 node_id=$(field "$OUT/$2_join.txt" NODE_ID) slot=$(field "$OUT/$2_join.txt" SLOT) (A node_id=$A_ID)"
    NRES=$(grep -ac 'P-TAUTH-IMPORT-RESIDUE ' "$OUT/$2_join_journal.txt")
    if [ "$3" -gt 0 ]; then
        ckge "$2: $1 saw and released the predecessor's residue (P-TAUTH-IMPORT-RESIDUE)" "$NRES" "$3"
    else
        echo "  INFO $2: P-TAUTH-IMPORT-RESIDUE count on $1 = $NRES"
    fi
    ck "$2: zero P-TAUTH-IMPORT-RESIDUE-RELEASE-FAIL on $1" "$(grep -ac 'P-TAUTH-IMPORT-RESIDUE-RELEASE-FAIL' "$OUT/$2_join_journal.txt")" "0"
    if [ "$HELD_ARM" = 1 ]; then
        # one parity keeps the residue as our own grant (HELD), the other has
        # the master attribute it to us; the two-lap total is asserted by
        # the caller, the refusal and its heal by every lap
        local nheld nref
        nheld=$(grep -ac 'P-TAUTH-IMPORT-RESIDUE-HELD' "$OUT/$2_join_journal.txt")
        nref=$(grep -ac 'DLM inode lock failed: ino=128' "$OUT/$2_join_journal.txt")
        echo "  INFO $2: P-TAUTH-IMPORT-RESIDUE-HELD count on $1 = $nheld"
        if [ "$nheld" -gt 0 ] || [ "$nref" -gt 0 ]; then
            ckge "$2: the phantom produced the upgrade refusal ('DLM inode lock failed: ino=128')" "$nref" 1
            ckge "$2: the inode layer released the phantom and retried (P109-EDEADLK-NL)" "$(grep -ac 'P109-EDEADLK-NL ino' "$OUT/$2_join_journal.txt")" 1
        else
            # A masters the page and imported the bit before the slot map
            # named the successor: the departed id holds it (the 0908
            # shape B), B's request waits behind the dead holder until A's
            # held purge; nothing reaches the inode layer as a phantom.
            echo "  INFO $2: no phantom reached the inode layer on this parity (the bit stayed with the departed id on $A; mount wall=$(field "$OUT/$2_join.txt" WALL)s waited for the held purge)"
        fi
    else
        # A phantom on the MASTER (the predecessor's slot bit attributed to
        # this node, D-...-0908) reaches the inode layer as a blocked-upgrade
        # refusal on a plain rejoin: the zero assertions stay (they detect
        # that record); when it happens, the arm must heal it in ONE lap with
        # the unconditional release delivered (D-...-0904, 0.75.12).
        ck "$2: zero 'DLM inode lock failed: ino=128' on $1 (the s509d upgrade refusal)" "$(grep -ac 'DLM inode lock failed: ino=128' "$OUT/$2_join_journal.txt")" "0"
        ck "$2: zero P109-EDEADLK-NL on $1 (no phantom reaches the inode layer)" "$(grep -ac 'P109-EDEADLK-NL ino' "$OUT/$2_join_journal.txt")" "0"
    fi
    n109=$(grep -ac 'P109-EDEADLK-NL ino' "$OUT/$2_join_journal.txt")
    if [ "$n109" -gt 0 ]; then
        ck "$2: the phantom healed in one lap (P109-EDEADLK-NL laps)" "$n109" "1"
        ckge "$2: the unconditional release reached the master (P109-EDEADLK-NL-RELEASE nak_rc=0)" "$(grep -ac 'P109-EDEADLK-NL-RELEASE .*nak_rc=0' "$OUT/$2_join_journal.txt")" 1
    fi
    # 0.75.14 (s513l2 arm 4 vs s513l plain arms 1-3, sameboot 1d/2f): ONE
    # P142-BWORK-STALE fires on EVERY joiner mount, planted phantom or not.
    # The root inode's slow-path acquire inside xfs_iget_cache_miss leaves
    # i_dlm_stale set (src=7: a fresh inode, i_mode==0, is never reloaded
    # there), the post-grant check arms the self-BAST (bastq_src=7), the
    # work fires before the inode is in the radix tree and bails, and the
    # MHT-armed work (P70-BP qsrc=9) honors the BAST state ~18 ms later
    # (P35-DIRHONOR, P51-REL, EXIT=full).  The s509d hang was a bail with NO
    # later honor and a waiter re-driving it; so the assertion is: every
    # bail on ino=128 is followed by a full bast_process, and nothing
    # re-drives (P-DEMWAIT-REDRIVE below).
    n142=$(grep -ac 'P142-BWORK-STALE' "$OUT/$2_join_journal.txt")
    if [ "$n142" -gt 0 ]; then
        ck "$2: the self-BAST bail on $1 is the single joiner-mount shape (P142-BWORK-STALE)" "$n142" "1"
        ckge "$2: the bailed self-BAST on ino=128 was honored afterwards (P70-BP ino=128 EXIT=full)" "$(grep -ac 'P70-BP ino=128 EXIT=full' "$OUT/$2_join_journal.txt")" 1
    fi
    ck "$2: zero P47-FILEBLOCK on $1 during the join" "$(grep -ac 'P47-FILEBLOCK' "$OUT/$2_join_journal.txt")" "0"
    ck "$2: zero P-DEMWAIT-REDRIVE on $1 during the join" "$(grep -ac 'P-DEMWAIT-REDRIVE' "$OUT/$2_join_journal.txt")" "0"
    ck "$2: zero 'lock request failed after' on $1 during the join" "$(grep -ac 'lock request failed after' "$OUT/$2_join_journal.txt")" "0"
    echo "  INFO $2: $(grep -a 'P-TAUTH-IMPORT-RESIDUE\|P-TAUTH-IMPORT-ACTIVE type=1 ino=128\|P-TRANSPORT-\|P109-EDEADLK-NL\|DLM inode lock failed\|P-NODE-ID-OVERRIDE' "$OUT/$2_join_journal.txt" | sed 's/.*kernel: //' | cut -c1-160 | tr '\n' '|' | cut -c1-800)"
    if [ "${rc:-HUNG}" = HUNG ]; then
        echo "  INFO $2: mount HUNG — stack: $(grep -a -A8 '^--- mount pid' "$OUT/$2_join.txt" | tr '\n' '|' | cut -c1-500)"
        echo "INFRA: $1's mount is hung; the rig needs a destroy of $1 — stopping here"
        return 1
    fi
    return 0
}
xwrite() {  # <writer> <reader> <tag>
    rsx 30 "$1" "mkdir -p $MNT/rr_$LABEL && head -c 65536 /dev/urandom > $MNT/rr_$LABEL/$3 && sync -f $MNT/rr_$LABEL && md5sum $MNT/rr_$LABEL/$3 | cut -c1-32" > "$OUT/$3_write.txt"
    capture_require "$OUT/$3_write.txt" '^[0-9a-f]{32}$' "$3: the write and md5 on $1"
    # the reader's md5sum failing (ENOENT, EIO) is the measurement: its text
    # is output and the status is expected non-zero, never a status record
    rsx 30 "$2" "md5sum $MNT/rr_$LABEL/$3 2>&1 | cut -c1-32; true" > "$OUT/$3_read.txt"
    capture_require "$OUT/$3_read.txt" '.' "$3: the read-back on $2"
    ck "$3: file written on $1 reads back on $2 with its md5" "$([ "$(head -1 "$OUT/$3_write.txt")" = "$(head -1 "$OUT/$3_read.txt")" ] && echo 1 || echo 0)" "1"
}
knob() {   # <node> <param> <value> <tag> <label>
    rsx 12 "$1" "echo $3 > $P/$2; cat $P/$2" > "$OUT/$4_knob.txt"
    capture_require "$OUT/$4_knob.txt" '^[0-9]+$' "$4: the knob $2 on $1"
    ck "$5" "$(tr -d '\r' < "$OUT/$4_knob.txt")" "$3"
}
# armed_cycle <arm> <modargs_extra>: A's purge held; B leaves and rejoins;
# cross-writes; the held purge is waited out and A's journal asserted.
armed_cycle() {
    local arm=$1 extra=$2 am
    am=$(rsx 10 "$A" "date +%s" | tail -1)
    require_epoch "$am" "$arm: $A's clock mark before the armed cycle"
    knob "$A" depart_purge_delay_ms "$DELAY_MS" "${arm}" "$arm: knob armed on $A (depart_purge_delay_ms=$DELAY_MS)"
    leave "$B" "${arm}a"
    MODARGS="$MODARGS $extra" join "$B" "${arm}b" 0 || { knob "$A" depart_purge_delay_ms 0 "${arm}_off" "$arm: knob cleared on $A"; return 1; }
    xwrite "$B" "$A" "${arm}_b2a"
    xwrite "$A" "$B" "${arm}_a2b"
    sleep $(( DELAY_MS / 1000 + 10 ))     # A's held purge runs and finishes
    jl "$A" "$am" > "$OUT/${arm}_journal_A.txt"
    capture_require "$OUT/${arm}_journal_A.txt" 'kernel: ' "$arm: the kernel journal on $A across the armed cycle"
    ckge "$arm: $A held the purge (P-DEPART-PURGE-DELAY)" "$(grep -ac 'P-DEPART-PURGE-DELAY' "$OUT/${arm}_journal_A.txt")" 1
    ckge "$arm: $A's departure work ran (P-DEPART-WORK)" "$(grep -ac 'P-DEPART-WORK ' "$OUT/${arm}_journal_A.txt")" 1
    ck "$arm: zero P278-HB-STALL on $A" "$(grep -ac 'P278-HB-STALL' "$OUT/${arm}_journal_A.txt")" "0"
    ck "$arm: zero P-HB-MONSLOW on $A" "$(grep -ac 'P-HB-MONSLOW' "$OUT/${arm}_journal_A.txt")" "0"
    ck "$arm: zero P1-AGCONFLICT storms on $A (the s509d survivor shape, > 5 lines)" "$([ "$(grep -ac 'P1-AGCONFLICT' "$OUT/${arm}_journal_A.txt")" -le 5 ] && echo 1 || echo 0)" "1"
    # 0.75.18 (D-...-0909): A must never PREPARE a page to the node whose
    # goodbye it has just processed (measured s514d: page 16642 prepared to
    # the departed incarnation under the new view; B's AG 0 request parked
    # 13 s on it).  The departed id is the one A's goodbye names.
    local gid; gid=$(grep -ao 'P-GOODBYE-RX node [0-9]*' "$OUT/${arm}_journal_A.txt" | head -1 | awk '{print $NF}')
    ckge "$arm: $A processed $B's goodbye (P-GOODBYE-RX)" "$(grep -ac 'P-GOODBYE-RX' "$OUT/${arm}_journal_A.txt")" 1
    ck "$arm: zero page prepared to the departed node ${gid:-?} after its goodbye (P-TAUTH-HANDOFF to=$gid why=view-change)" "$(grep -ac "P-TAUTH-HANDOFF page=[0-9]* to=${gid:-NONE}/.* why=view-change" "$OUT/${arm}_journal_A.txt")" "0"
    # 0.75.20: the departer's FROZENs announce the departure; A must record
    # it (P-TAUTH-DEPARTING-RX) and then never hand a page to that node in
    # ANY window, before or after the goodbye (the tick-cadence shape).
    ckge "$arm: $A recorded $B's departure announcement (P-TAUTH-DEPARTING-RX node=${gid:-?})" "$(grep -ac "P-TAUTH-DEPARTING-RX node=${gid:-NONE}/" "$OUT/${arm}_journal_A.txt")" 1
    ck "$arm: zero page handed to the departing node ${gid:-?} at any time (P-TAUTH-HANDOFF to=$gid)" "$(grep -ac "P-TAUTH-HANDOFF page=[0-9]* to=${gid:-NONE}/" "$OUT/${arm}_journal_A.txt")" "0"
    echo "  INFO $arm: stale hand-off targets refused on $A = $(grep -ac 'P-TAUTH-HANDOFF-STALE-TARGET' "$OUT/${arm}_journal_A.txt"), retargets = $(grep -ac 'P-TAUTH-RETARGET' "$OUT/${arm}_journal_A.txt")"
    echo "  INFO $arm: $(grep -a 'P-DEPART-PURGE-DELAY\|P-TAUTH-PURGE node\|P-DEPART-WORK\|P-TAUTH-PREPARED' "$OUT/${arm}_journal_A.txt" | sed 's/.*kernel: //; s/mxfs: mxfs: //; s/mxfs: tauth: //' | cut -c1-150 | tr '\n' '|' | cut -c1-700)"
    knob "$A" depart_purge_delay_ms 0 "${arm}_off" "$arm: knob cleared on $A"
    return 0
}

measure "$A" 15 "$OUT/rv_pre_a_1.txt" '^READ_RC=[0-9]+$' "pre_a on $A" "mountpoint -q $MNT && echo M; cat $P/force_transport 2>/dev/null; ls $P/depart_purge_delay_ms $P/node_id_override >/dev/null 2>&1 && echo KNOB; journalctl -k --no-pager 2>/dev/null | grep -ao 'DLM init: node_id=[0-9]*' | tail -1 | sed 's/.*node_id=//'; printf '\nREAD_RC=%s\n' \$?"; pre_a=$(grep -av '^READ_RC=' "$OUT/rv_pre_a_1.txt")
measure "$B" 15 "$OUT/rv_pre_b_1.txt" '^READ_RC=[0-9]+$' "pre_b on $B" "mountpoint -q $MNT && echo M; cat $P/force_transport 2>/dev/null; printf '\nREAD_RC=%s\n' \$?"; pre_b=$(grep -av '^READ_RC=' "$OUT/rv_pre_b_1.txt")
if ! echo "$pre_a" | grep -q '^M' || ! echo "$pre_b" | grep -q '^M'; then
    echo "INFRA: precondition not met (A='$(echo $pre_a | tr '\n' ' ')' B='$(echo $pre_b | tr '\n' ' ')') — prep 2/tcp first"; exit 2
fi
# A's node id is its own measurement with a shape: the journal line absent
# (s58h-H21: journalctl printed nothing for it) is an ABORT here, never an
# id of "KNOB" that fails two preconditions and lets the arms run
# the kernel ring, not journalctl -k: journald reads /dev/kmsg behind the
# module's print rate and drops entries, and on s62a (and s58h before it)
# the DLM init line was absent from the journal while dmesg held it
value_now_into A_ID "$A" 15 "$OUT/rv_aid_1.txt" '^[0-9]+$' "A's node id from the kernel ring" "dmesg | grep -ao 'DLM init: node_id=[0-9]*' | tail -1 | sed 's/.*node_id=//'"
ck "precondition: both nodes mounted on force_transport=1, A carries the 0.75.6 knobs" "$(echo "$pre_a $pre_b" | tr '\n' ' ' | grep -c 'M 1 KNOB [0-9]* M 1')" "1"
# the LUN as MXFS actually uses it, from A's live mount (MXFS_DEV overrides)
mxfs_dev_resolve "$A"
DEV=$MXFS_DEV_RESOLVED
echo "=== rejoin_residue label=$LABEL A=$A B=$B delay_ms=$DELAY_MS ids=$ID_LOW/$ID_HIGH dev=$DEV sv=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p') out=$OUT $(date -u +%FT%TZ) ==="
ck "precondition: A's node id ($A_ID) lies strictly between ID_LOW=$ID_LOW and ID_HIGH=$ID_HIGH" "$([ "${A_ID:-0}" -gt "$ID_LOW" ] && [ "${A_ID:-0}" -lt "$ID_HIGH" ] && echo 1 || echo 0)" "1"
xwrite "$A" "$B" "pre"

# wired_leave_checks <tag>: since 0.75.16 a clean departure releases its
# remaining grants through the DLM before the goodbye, so the peers' purge
# has nothing to clear and no successor can meet a predecessor's bit.
wired_leave_checks() {
    ckge "$1: $B's departure released its remaining grants through the DLM (P-RELALL-WIRED)" "$(grep -ac 'P-RELALL-WIRED' "$OUT/$1_leave_journal.txt")" 1
    ck "$1: nothing was left held after the release (P-RELALL-WIRED held_after=0)" "$(grep -ac 'P-RELALL-WIRED .*held_after=0' "$OUT/$1_leave_journal.txt")" "1"
}
echo "--- arm 1: $A's purge delayed ${DELAY_MS} ms; $B leaves and rejoins as node_id=$ID_LOW (masters the even pages) $(date -u +%T)"
armed_cycle 1 "node_id_override=$ID_LOW" || exit 1
wired_leave_checks 1a
ck "1b: zero P-TAUTH-IMPORT-RESIDUE on $B (nothing left for a successor to inherit)" "$NRES" "0"
echo "--- arm 2: $A's purge delayed ${DELAY_MS} ms; $B leaves and rejoins as node_id=$ID_HIGH (masters the odd pages) $(date -u +%T)"
armed_cycle 2 "node_id_override=$ID_HIGH" || exit 1
wired_leave_checks 2a
ck "2b: zero P-TAUTH-IMPORT-RESIDUE on $B (nothing left for a successor to inherit)" "$NRES" "0"
for arm in 1 2; do
    ck "$arm: $A's held purge found nothing of the departed node to clear (P-TAUTH-PURGE cleared=0 cand=0)" "$(grep -ac 'P-TAUTH-PURGE node=[0-9]* slot=[-0-9]* cleared=0 pages=[0-9]* cand=0' "$OUT/${arm}_journal_A.txt")" "1"
    ck "$arm: zero shared bit of the departed node attributed to the successor on $A (P-TAUTH-IMPORT-ACTIVE type=1 ino=128 slot=1)" "$(grep -ac 'P-TAUTH-IMPORT-ACTIVE type=1 ino=128 .*slot=1 ' "$OUT/${arm}_journal_A.txt")" "0"
done

echo "--- arm 3: plain leave and rejoin of $B (random id, no hold) $(date -u +%T)"
leave "$B" "3a"
wired_leave_checks 3a
join "$B" "3b" 0 || exit 1
ck "3b: zero P-TAUTH-IMPORT-RESIDUE on $B (nothing left for a successor to inherit)" "$NRES" "0"
xwrite "$B" "$A" "3_b2a"
xwrite "$A" "$B" "3_a2b"

if [ "$RR_HELD_ARM" = 1 ]; then
    # arm 4 (0.75.6, reshaped 0.75.16): the planted phantom.  B's departure
    # is made to leave its grants behind (depart_wire_release=0, the
    # pre-0.75.16 shape), A's purge is held, and B rejoins with the DLM's
    # residue release switched off (tauth_import_residue_release=0).  Which
    # node masters the root inode's page decides the shape: on B's parity the
    # DLM keeps the residue as B's own grant (P-TAUTH-IMPORT-RESIDUE-HELD, the
    # s509d shape); on A's parity A attributes the bit to B (the 0908 shape).
    # Both reach xfs_iget as a blocked-upgrade refusal that the inode layer
    # must heal in one lap (P109-EDEADLK-NL, nak_rc=0) within the join bound.
    # Both parities run, with fresh ids: a departed node id is RETIRED for
    # the life of the peer's mount (P164-DEAD-NOTE; measured s513i2h: reusing
    # arm 1's id left B unadmitted for the whole bound, then fenced).
    held_total=0
    for side in L H; do
        if [ $side = L ]; then HELD_ID=$(( ID_LOW + 1 )); else HELD_ID=$(( ID_HIGH - 1 )); fi
        echo "--- arm 4$side: wire release OFF and residue release OFF on $B; $A's purge delayed; $B leaves and rejoins as node_id=$HELD_ID $(date -u +%T)"
        knob "$B" depart_wire_release 0 "4${side}_pre" "4$side: $B will leave its grants behind (depart_wire_release=0)"
        HELD_ARM=1 armed_cycle "4$side" "node_id_override=$HELD_ID tauth_import_residue_release=0" || exit 1
        HELD_ARM=0
        ck "4${side}a: $B's departure left its grants to the purge (P-RELALL-UNWIRED)" "$(grep -ac 'P-RELALL-UNWIRED' "$OUT/4${side}a_leave_journal.txt")" "1"
        held_total=$(( held_total + $(grep -ac 'P-TAUTH-IMPORT-RESIDUE-HELD' "$OUT/4${side}b_join_journal.txt") ))
        knob "$B" tauth_import_residue_release 1 "4${side}_b" "4$side: residue release restored on $B"
    done
    ckge "4: one parity kept the residue as $B's own grant (P-TAUTH-IMPORT-RESIDUE-HELD over both laps)" "$held_total" 1
fi

if [ $fails = 0 ]; then echo "RESULT: PASS label=$LABEL evidence=$OUT"; else echo "RESULT: FAIL label=$LABEL fails=$fails evidence=$OUT"; fi
exit $fails
