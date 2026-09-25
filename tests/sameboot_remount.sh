#!/bin/bash
# sameboot_remount.sh — D-TCP-LAST-NODE-SAMEBOOT-REMOUNT-HANGS-OWN-RETIRE-
# PENDING-SLOT-KEY-PRESENT-SETTLE-UNHELD-0904: a node that unmounts cleanly
# must be able to mount again in the SAME boot, including when it was the
# last member (nobody left to settle its RETIRE_PENDING record) and when it
# is alone.  Measured before the fix on the QNAP 2-node TCP rig: the remount
# looped 27 rounds of 'NOT replayed (-61)' behind P-ADMIT-RETIRE-PENDING-HELD
# and was killed at 46 s; every later mount by either node hung the same way.
#
# Arms (both nodes start mounted on the same transport, from a prep):
#   1  last-leaver remounts first: B leaves, A leaves (A is last), A
#      remounts with default module arguments, then B remounts.
#   2  lone-node cycles: B leaves; A unmounts and remounts twice.
#   3  everyone leaves (the rig is left unmounted; the next prep re-forms).
# Every mount must return 0 within JOIN_BOUND (a clean join measured 1-5 s
# on this rig; bound 20 s), the mounting node must log zero
# P-PR-SETTLE-UNHELD, zero P-ADMIT-RETIRE-PENDING-HELD and zero
# P304-RETIRE-UNKNOWN-STALLED, its own RETIRE_PENDING record must be found
# and settled (P305-PR-SAME-BOOT-RETIRE-PENDING then P305-RETIRE-SETTLED)
# whenever it was the last to leave, and a file written by one node must
# read back from the other after the remount.  Every unmount must be clean
# on the departing node's own record (P304-RETIRE-PENDING-RELEASED, zero
# P-SB-SEAL-DIRTY-DEPARTURE).
#
# budget: 7 mount/umount cycles at <= 25 s each => bound 200 s.
# Usage: tests/sameboot_remount.sh <label> [A=test1] [B=test2]
# Env:   MXFS_DEV (default: the device of A's live mxfs mount, resolved by
#        mxfs_dev_resolve — no rig's device path is assumed), MXFS_MNT,
#        MXFS_MODARGS (default target_cache_protected=1 force_transport=1),
#        MXFS_TRANSPORT (the transport every join must come up on, default
#        tcp), ARMS (comma list of arms to run, default 1,2,3 — arm 1 alone
#        reproduces the s510b whole-cluster-restart hang without dragging
#        arms 2-3 through the wreckage), MXFS_FAULT_UNREACHABLE=<stage>
#        (capture-contract verification only: the named acquisition,
#        join_<tag> e.g. join_1c, is issued to a host that does not resolve,
#        a real ssh failure; the lap must then ABORT, never reach a verdict).
#
# Every capture a verdict is taken from crosses tests/lib/rig.sh's boundary
# (rsx + capture_require in the parent shell): a journal window that could
# not be read, a mount whose state line never came back, an md5 that was
# never computed — each is an ABORT, never a count of zero.
#
# The module is reloaded on every join, so the transport is whatever the
# module arguments say: a join without force_transport=1 by the LAST leaver
# forms a NEW cluster and a new cluster tries CAW first, and the peer then
# conforms to it.  The s509c/s509d laps measured exactly that — seven CAW
# remounts — while the record under test is the TCP mount path, so every
# join now asserts the transport it actually came up on.
set -u
LABEL=${1:?label}
A=${2:-test1}
B=${3:-test2}
cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
MNT=${MXFS_MNT:-/mnt/shared}
TRANSPORT=${MXFS_TRANSPORT:-tcp}
export MXFS_TRANSPORT=$TRANSPORT
ARMS=${ARMS:-1,2,3}
arm() { case ",$ARMS," in *",$1,"*) return 0;; *) return 1;; esac; }
KO=/root/mxfs.ko.prep
JOIN_BOUND=20
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_sameboot_$LABEL
mkdir -p "$OUT"
fails=0
ck() { if [ "$2" = "$3" ]; then echo "  PASS $1 ($2)"; else echo "  FAIL $1 got=$2 want=$3"; fails=$((fails+1)); fi; }
ckge() { if [ "${2:-0}" -ge "$3" ] 2>/dev/null; then echo "  PASS $1 ($2 >= $3)"; else echo "  FAIL $1 got=${2:-?} want>=$3"; fails=$((fails+1)); fi; }
# rs/rsx/capture_require/require_epoch/mxfs_dev_resolve (tests/lib/rig.sh)
. "$(dirname "$0")/lib/rig.sh"
sshq() { rs "$@"; }
MODARGS=${MXFS_MODARGS:-$(mxfs_rig_modargs)}   # rig-derived: includes this rig's retirement contract
# jl <node> <mark> > <file>: a kernel journal window; the caller validates
# the file with capture_require 'kernel: ' before counting anything in it
jl() { rsx 20 "$1" "journalctl -k --since @$2 --no-pager 2>/dev/null | cut -c1-700"; }
field() { grep -ao "^$2=[^ ]*" "$1" | head -1 | cut -d= -f2; }
# Nothing this harness acquires depends on /src (the module was copied at
# prep), so the fault that can reach a verdict here is the ssh invocation
# itself failing.  MXFS_FAULT_UNREACHABLE=<stage> aims that one acquisition
# at a host that does not resolve: a real ssh failure through the real
# chokepoint, and the harness must ABORT on it.
fault_host() { # <stage> <node>  -> the node to acquire from
    if [ "${MXFS_FAULT_UNREACHABLE:-}" = "$1" ]; then
        echo "STAGE FAULT: acquiring $1 from an unresolvable host instead of $2" >&2
        echo "$2-unreachable.invalid"
    else
        echo "$2"
    fi
}

# leave <node> <tag>: clean umount + rmmod; asserts the departure was clean
leave() {
    local m
    m=$(rsx 10 "$1" "date +%s" | tail -1)
    require_epoch "$m" "$2: $1's clock mark before its departure"
    rsx 70 "$1" "mountpoint -q $MNT && timeout 40 umount $MNT; echo UMOUNT_RC=\$?; for i in 1 2 3 4 5 6; do rmmod mxfs 2>/dev/null; lsmod | grep -q '^mxfs' || break; sleep 2; done; lsmod | grep -q '^mxfs' && echo STILL_LOADED || echo UNLOADED" > "$OUT/$2_leave.txt"
    capture_require "$OUT/$2_leave.txt" '^(UNLOADED|STILL_LOADED)$' "$2: the departure of $1"
    jl "$1" "$m" > "$OUT/$2_leave_journal.txt"
    capture_require "$OUT/$2_leave_journal.txt" 'kernel: ' "$2: the kernel journal on $1 across its departure"
    ck "$2: $1 unmounted (rc=$(field "$OUT/$2_leave.txt" UMOUNT_RC)) and unloaded" "$(grep -c '^UNLOADED' "$OUT/$2_leave.txt")" "1"
    ck "$2: $1's departure released its slot cleanly (P304-RETIRE-PENDING-RELEASED)" "$(grep -ac 'P304-RETIRE-PENDING-RELEASED' "$OUT/$2_leave_journal.txt")" "1"
    ck "$2: zero P-SB-SEAL-DIRTY-DEPARTURE on $1" "$(grep -ac 'P-SB-SEAL-DIRTY-DEPARTURE' "$OUT/$2_leave_journal.txt")" "0"
    ck "$2: zero 'lock request failed after' on $1 during its unmount" "$(grep -ac 'lock request failed after' "$OUT/$2_leave_journal.txt")" "0"
}
# join <node> <tag> <expect_own_settle 0|1>: insmod + mount, bounded, asserts
join() {
    local h
    h=$(fault_host "join_$2" "$1")
    rsx 60 "$h" "M=\$(date +%s); echo MARK=\$M; insmod $KO dyndbg=+p $MODARGS; echo INSMOD_RC=\$?; T0=\$(date +%s); timeout $JOIN_BOUND mount -t mxfs $DEV $MNT; R=\$?; echo MOUNT_RC=\$R; echo WALL=\$(( \$(date +%s) - T0 )); mountpoint -q $MNT && echo MOUNTED || echo NOT_MOUNTED" > "$OUT/$2_join.txt"
    capture_require "$OUT/$2_join.txt" '^(MOUNTED|NOT_MOUNTED)$' "$2: the join of $1"
    capture_require "$OUT/$2_join.txt" '^MARK=[0-9]+$' "$2: the clock mark of $1's join"
    jl "$1" "$(field "$OUT/$2_join.txt" MARK)" > "$OUT/$2_join_journal.txt"
    capture_require "$OUT/$2_join_journal.txt" 'kernel: ' "$2: the kernel journal on $1 across its join"
    ck "$2: $1 mounted (rc=$(field "$OUT/$2_join.txt" MOUNT_RC) wall=$(field "$OUT/$2_join.txt" WALL)s, bound ${JOIN_BOUND}s)" "$(field "$OUT/$2_join.txt" MOUNT_RC)" "0"
    ck "$2: $1 admitted (P-DOMAIN-ADMITTED)" "$(grep -ac 'P-DOMAIN-ADMITTED' "$OUT/$2_join_journal.txt")" "1"
    ck "$2: $1 came up on transport=$TRANSPORT ($(grep -ao 'DLM init: node_id=[0-9]* transport=[a-z]*' "$OUT/$2_join_journal.txt" | tail -1 | sed 's/.*transport=//'))" "$(grep -ac "DLM init: node_id=[0-9]* transport=$TRANSPORT\$" "$OUT/$2_join_journal.txt")" "1"
    ck "$2: zero P-PR-SETTLE-UNHELD on $1" "$(grep -ac 'P-PR-SETTLE-UNHELD' "$OUT/$2_join_journal.txt")" "0"
    ck "$2: zero P-ADMIT-RETIRE-PENDING-HELD on $1" "$(grep -ac 'P-ADMIT-RETIRE-PENDING-HELD' "$OUT/$2_join_journal.txt")" "0"
    ck "$2: zero P304-RETIRE-UNKNOWN-STALLED on $1" "$(grep -ac 'P304-RETIRE-UNKNOWN-STALLED' "$OUT/$2_join_journal.txt")" "0"
    ck "$2: zero 'NOT replayed' mount-recovery rounds on $1" "$(grep -ac 'NOT replayed' "$OUT/$2_join_journal.txt")" "0"
    if [ "$3" = 1 ]; then
        ckge "$2: $1 found its own RETIRE_PENDING record (P305-PR-SAME-BOOT-RETIRE-PENDING)" "$(grep -ac 'P305-PR-SAME-BOOT-RETIRE-PENDING' "$OUT/$2_join_journal.txt")" 1
        ckge "$2: $1 settled it (P305-RETIRE-SETTLED)" "$(grep -ac 'P305-RETIRE-SETTLED' "$OUT/$2_join_journal.txt")" 1
        ck "$2: zero P274-CLAIM-RETIRE-PENDING-SKIP on $1 (its own slot was consumed, not skipped)" "$(grep -ac 'P274-CLAIM-RETIRE-PENDING-SKIP' "$OUT/$2_join_journal.txt")" "0"
    fi
    echo "  INFO $2: $(grep -a 'P305\|claimed heartbeat\|P-TRANSPORT-\(ADOPTED\|CONFORMED\)' "$OUT/$2_join_journal.txt" | sed 's/.*kernel: //' | cut -c1-120 | tr '\n' '|' | cut -c1-500)"
}
# xwrite <writer> <reader> <tag>: a file written on one node reads back on the other
xwrite() {
    rsx 30 "$1" "mkdir -p $MNT/sameboot_$LABEL && head -c 65536 /dev/urandom > $MNT/sameboot_$LABEL/$3 && sync -f $MNT/sameboot_$LABEL && md5sum $MNT/sameboot_$LABEL/$3 | cut -c1-32" > "$OUT/$3_write.txt"
    capture_require "$OUT/$3_write.txt" '^[0-9a-f]{32}$' "$3: the write and md5 on $1"
    # the reader's md5sum failing (ENOENT, EIO) is the measurement, so its
    # status is expected non-zero: keep it as output, never as a status record
    rsx 30 "$2" "md5sum $MNT/sameboot_$LABEL/$3 2>&1 | cut -c1-32; true" > "$OUT/$3_read.txt"
    capture_require "$OUT/$3_read.txt" '.' "$3: the read-back on $2"
    ck "$3: file written on $1 reads back on $2 with its md5" "$([ "$(head -1 "$OUT/$3_write.txt")" = "$(head -1 "$OUT/$3_read.txt")" ] && echo 1 || echo 0)" "1"
}

pre_a=$(sshq 15 "$A" "mountpoint -q $MNT && echo M")
pre_b=$(sshq 15 "$B" "mountpoint -q $MNT && echo M")
if [ "$pre_a" != M ] || [ "$pre_b" != M ]; then
    echo "INFRA: precondition not met (A='$pre_a' B='$pre_b') — prep first"; exit 2
fi
# the LUN as MXFS actually uses it, from A's live mount (MXFS_DEV overrides)
mxfs_dev_resolve "$A"
DEV=$MXFS_DEV_RESOLVED
echo "=== sameboot_remount label=$LABEL A=$A B=$B dev=$DEV sv=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p') out=$OUT $(date -u +%FT%TZ) ==="

if arm 1; then
echo "--- arm 1: $B leaves, $A leaves last, $A remounts first, then $B $(date -u +%T)"
xwrite "$A" "$B" "arm1_pre"
leave "$B" "1a"
leave "$A" "1b"
join "$A" "1c" 1
# SAMEBOOT_ARM1_DELAY_S (default 0): hold B's join so A's takeover of its
# predecessor's pages completes with A ALONE in the view (every page goes to
# A itself, activated without an import); B's join then receives those pages
# by an ordinary hand-on whose writer IS the authority — the path that
# carries the departed incarnation's records with no takeover marker
# (the hole named in D-0906).  ~8-9 s measured for the purge + takeover pass;
# 12 s puts the join squarely after it.
[ "${SAMEBOOT_ARM1_DELAY_S:-0}" -gt 0 ] && { echo "  INFO 1c: holding $B's join ${SAMEBOOT_ARM1_DELAY_S}s so $A's takeover completes alone"; sleep "$SAMEBOOT_ARM1_DELAY_S"; }
join "$B" "1d" 0     # B's record was settled by a live peer's monitor (foreign key proven absent)
# s510b: B's join parked on ledger pages still ACTIVE under A's PREVIOUS
# incarnation (the last leaver of the previous era) and A then shut itself
# down on the same pages.  Both sides must show the takeover, and neither
# may park or die.
ck "1d: zero P-TAUTH-PAGE-PARKED on $B during its join" "$(grep -ac 'P-TAUTH-PAGE-PARKED' "$OUT/1d_join_journal.txt")" "0"
ck "1d: zero 'lock request failed after' on $B during its join" "$(grep -ac 'lock request failed after' "$OUT/1d_join_journal.txt")" "0"
# s511b (0.75.7): the pages A took over and handed to B still carried A's
# PREVIOUS incarnation's EX records; B imported them as live blockers and its
# mount queued behind a holder that no longer existed.
PRED_A=$(grep -ao 'P305-RETIRE-SETTLED slot=[0-9]* node=[0-9]*' "$OUT/1c_join_journal.txt" | head -1 | sed 's/.*node=//')
ck "1d: zero imported EX blockers naming $A's predecessor (${PRED_A:-?}) on $B" "$(grep -ac "P-TAUTH-IMPORT-ACTIVE .*owner=${PRED_A:-NONE} " "$OUT/1d_join_journal.txt")" "0"
ck "1d: zero P-LKTIMEOUT-HOLDER on $B during its join" "$(grep -ac 'P-LKTIMEOUT-HOLDER' "$OUT/1d_join_journal.txt")" "0"
echo "  INFO 1d: $(grep -a 'P-TAUTH-DEPARTED-AUTH\|P-TAUTH-PURGE-OWNER\|P-TAUTH-PURGE-SLOT-LIVE\|P-TAUTH-IMPORT-ACTIVE' "$OUT/1d_join_journal.txt" | sed 's/.*kernel: //' | cut -c1-140 | head -4 | tr '\n' '|' | cut -c1-600)"
xwrite "$B" "$A" "arm1_post"
# The bulk takeover pass of A's own predecessor (purge scan + takeover scan,
# ~8 s after the mount) can still be running when both joins took a second
# each (0.75.14, s513l: captured at :45, P-TAUTH-TAKEOVER printed at :47 —
# the on-demand path had already served every page).  Wait for the
# departure work to report before capturing, bounded well inside the budget rule
# (the pass measured 7.8-9 s; 20 s is the ceiling, not a timeout to widen).
for i in $(seq 1 20); do
    sshq 15 "$A" "journalctl -k --since @$(field "$OUT/1c_join.txt" MARK) --no-pager 2>/dev/null | grep -aq 'P-DEPART-WORK .*why=own-predecessor-settled' && echo DEPART_DONE" | grep -q DEPART_DONE && break
    sleep 1
done
echo "  INFO 1: waited ${i}s for $A's own-predecessor departure work"
jl "$A" "$(field "$OUT/1c_join.txt" MARK)" > "$OUT/1_journal_A_since_1c.txt"
capture_require "$OUT/1_journal_A_since_1c.txt" 'kernel: ' "1: the kernel journal on $A since its remount"
ck "1: zero P-TAUTH-PAGE-PARKED on $A since its remount" "$(grep -ac 'P-TAUTH-PAGE-PARKED' "$OUT/1_journal_A_since_1c.txt")" "0"
ck "1: zero 'shutting down filesystem' on $A since its remount" "$(grep -ac 'shutting down filesystem' "$OUT/1_journal_A_since_1c.txt")" "0"
ckge "1: $A took over its predecessor's ledger pages (P-TAUTH-TAKEOVER departed=<predecessor>)" "$(grep -ac 'P-TAUTH-TAKEOVER departed=' "$OUT/1_journal_A_since_1c.txt")" 1
echo "  INFO 1: $(grep -a 'P-TAUTH-TAKEOVER \|P-DEPART-WORK\|P-TAUTH-PAGE-PARKED' "$OUT/1_journal_A_since_1c.txt" | sed 's/.*kernel: //' | cut -c1-160 | head -4 | tr '\n' '|' | cut -c1-600)"
fi

if arm 2; then
echo "--- arm 2: $B leaves; $A cycles alone twice $(date -u +%T)"
leave "$B" "2a"
leave "$A" "2b"
join "$A" "2c" 1
leave "$A" "2d"
join "$A" "2e" 1
join "$B" "2f" 0
ck "2f: zero P-TAUTH-PAGE-PARKED on $B during its join" "$(grep -ac 'P-TAUTH-PAGE-PARKED' "$OUT/2f_join_journal.txt")" "0"
xwrite "$A" "$B" "arm2_post"
fi

if arm 3; then
echo "--- arm 3: both leave $(date -u +%T)"
leave "$B" "3a"
leave "$A" "3b"
fi

echo "=== sameboot_remount $LABEL: fails=$fails out=$OUT $(date -u +%FT%TZ) ==="
[ $fails = 0 ]
