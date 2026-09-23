#!/bin/bash
# device-adjudicated: the resolver is the subject under test here and these paths are its inputs
# rig_lib_contract.sh — the contract of tests/lib/rig.sh, exercised against a
# real node with real commands (nothing mocked): a measurement that did not
# complete, produced nothing, produced the wrong structure, or timed out
# before or after a valid-looking line must ABORT (exit 2) before any count
# is taken; a completed measurement with a legitimate zero count must pass
# through; a successful command's noisy stderr must not change its stdout.
#
# budget (derived): ~14 short ssh round-trips (~1 s each) + two deliberate
# 3 s timeouts + one unreachable-host connect timeout (10 s) -> ~35 s for the
# capture cases; the device-identity cases add 16 resolves of 2-3 round-trips
# each (measured: the whole file ran in 27 s before the unmounted-node
# cases) and one more unreachable host (10 s); the unmounted-node cases add a
# clean unmount of the peer behind a live node (35-80 s measured on TCP,
# bound 120 s) and its remount (bound 90 s) -> ~150 s; bound 300 s.
#
# Usage: tests/rig_lib_contract.sh <label> [node=test1]
# Exit 0 PASS, 1 FAIL, 2 INFRA.
set -u
LABEL=${1:?label}
N=${2:-test1}
cd "$(dirname "$0")/.." || exit 2
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_riglib_$LABEL
mkdir -p "$OUT"
. tests/lib/rig.sh
fails=0
# ck: tests/lib/rig.sh (sourced above) provides it, and its version ABORTs on an EMPTY value instead of printing a FAIL about MXFS
s0=$(date +%s)
echo "=== rig_lib_contract label=$LABEL node=$N $(date -u +%FT%TZ) ==="

# run_case <name> <timeout> <cmd> <shape>: acquire with rsx into its own
# capture, then validate in a SUBSHELL so an ABORT's exit 2 is observed
# here; print what the validator said.  Outputs "rc=<n> abort=<0|1>".
run_case() {
    local name=$1 t=$2 cmd=$3 shape=$4 rc arc
    rsx "$t" "$N" "$cmd" > "$OUT/$name.txt"; rc=$?
    ( capture_require "$OUT/$name.txt" "$shape" "case $name" > "$OUT/$name.verdict" 2>&1 ); arc=$?
    echo "rc=$rc abort=$( [ $arc = 2 ] && grep -qa '^ABORT:' "$OUT/$name.verdict" && echo 1 || echo 0 )"
}

echo "--- reachability"
r=$(rsx 15 "$N" 'echo REACH_OK' | tail -1)
[ "$r" = REACH_OK ] || { echo "RESULT: INFRA label=$LABEL node $N unreachable ($r)"; exit 2; }

ck "1 status 0, valid structure, legitimate zero count -> allowed" "$(run_case c1 15 'echo slot 0 flags=EMPTY' '^slot [0-9]+ ')" "rc=0 abort=0" # capture-adjudicated: run_case IS the subject under test; its rc/abort pair is computed in the parent from the library's own verdict file, so a failed acquisition here is the case's expected outcome, never a hidden one
capture_require "$OUT/c1.txt" '^slot [0-9]+ ' "case c1 in the parent shell"
ck "1b ... and the count taken from it is the real zero" "$(cnt "$OUT/c1.txt" 'flags=ACTIVE')" 0
ck "2 status 0, EMPTY output -> ABORT" "$(run_case c2 15 'true' '^slot [0-9]+ ')" "rc=0 abort=1" # capture-adjudicated: run_case IS the subject under test; its rc/abort pair is computed in the parent from the library's own verdict file, so a failed acquisition here is the case's expected outcome, never a hidden one
ck "3 status 0, malformed non-empty output -> ABORT" "$(run_case c3 15 'echo an error message mentioning slot' '^slot [0-9]+ ')" "rc=0 abort=1" # capture-adjudicated: run_case IS the subject under test; its rc/abort pair is computed in the parent from the library's own verdict file, so a failed acquisition here is the case's expected outcome, never a hidden one
ck "4 valid-looking line then non-zero exit -> ABORT" "$(run_case c4 15 'echo slot 0 flags=ACTIVE; exit 3' '^slot [0-9]+ ')" "rc=3 abort=1" # capture-adjudicated: run_case IS the subject under test; its rc/abort pair is computed in the parent from the library's own verdict file, so a failed acquisition here is the case's expected outcome, never a hidden one
ck "4b ... the status record names the rc" "$(grep -ac "^$RS_STATUS_TAG v=1 host=$N rc=3 " "$OUT/c4.txt")" 1   # capture-adjudicated: c4 is a failed capture BY DESIGN; the count is of the library's own failure record, whose absence is exactly what 4 above already failed on
ck "5 timeout before any output -> ABORT" "$(run_case c5 3 'sleep 20; echo slot 0' '^slot [0-9]+ ')" "rc=124 abort=1" # capture-adjudicated: run_case IS the subject under test; its rc/abort pair is computed in the parent from the library's own verdict file, so a failed acquisition here is the case's expected outcome, never a hidden one
ck "6 timeout AFTER a valid-looking line -> ABORT" "$(run_case c6 3 'echo slot 0 flags=ACTIVE; sleep 20' '^slot [0-9]+ ')" "rc=124 abort=1" # capture-adjudicated: run_case IS the subject under test; its rc/abort pair is computed in the parent from the library's own verdict file, so a failed acquisition here is the case's expected outcome, never a hidden one
ck "7 success with noisy stderr -> stdout unchanged, no record" "$(run_case c7 15 'echo slot 0 flags=ACTIVE; echo mount: WARNING something >&2' '^slot [0-9]+ ')" "rc=0 abort=0" # capture-adjudicated: run_case IS the subject under test; its rc/abort pair is computed in the parent from the library's own verdict file, so a failed acquisition here is the case's expected outcome, never a hidden one
ck "7b ... stdout is exactly the tool's line" "$(cat "$OUT/c7.txt")" "slot 0 flags=ACTIVE"
ck "7c ... and the stderr was kept in its own file" "$(cat "$OUT"/rs_stderr/${N}_* | grep -ac 'WARNING')" 1
ck "8 unreachable host -> ABORT with rc=255" "$(N=test99 run_case c8 20 'echo slot 0' '^slot [0-9]+ ')" "rc=255 abort=1"
ck "9 a remote grep -c with zero matches exits 1: the caller states the expected status" "$(run_case c9 15 'dmesg | grep -ac NOPE_NOT_A_LINE_X9 || true' '^[0-9]+$')" "rc=0 abort=0" # capture-adjudicated: run_case IS the subject under test; its rc/abort pair is computed in the parent from the library's own verdict file, so a failed acquisition here is the case's expected outcome, never a hidden one
ck "9b ... and the count read is zero" "$(tail -1 "$OUT/c9.txt")" 0
ck "10 missing capture file -> ABORT" "$( ( capture_require "$OUT/never_written.txt" '^slot ' 'case 10' > "$OUT/c10.verdict" 2>&1 ); [ $? = 2 ] && grep -qa '^ABORT:' "$OUT/c10.verdict" && echo abort=1 || echo abort=0)" "abort=1"
echo "--- device resolver: identity, not path"
# rej <name> <want-text> <cmd...>: run the resolver in a subshell, require exit 2,
# an ABORT line, and that the ABORT names the reason it was supposed to find
rej() { local name=$1 want=$2; shift 2; ( "$@" > "$OUT/$name.verdict" 2>&1 ); local rc=$?; echo "rc=$rc abort=$( [ $rc = 2 ] && grep -qa '^ABORT:' "$OUT/$name.verdict" && echo 1 || echo 0) why=$( grep -qa "$want" "$OUT/$name.verdict" && echo named || echo unnamed)"; }
DECL=$(mxfs_dev_declared) || { echo "RESULT: INFRA label=$LABEL no declared LUN for this rig: $DECL"; exit 2; }
ck "11 MXFS_DEV=/dev/sda on the mounted node -> used, and it carries the declared WWID" "$( ( MXFS_DEV=/dev/sda; mxfs_dev_resolve "$N" > "$OUT/c11.verdict"; echo "$MXFS_DEV_RESOLVED wwid=$(mxfs_wwid_norm "$MXFS_DEV_WWID")" ) 2>&1 | tail -1)" "/dev/sda wwid=$DECL"
ck "11b ... its DEVICE line names the source and a filesystem uuid" "$(grep -ac '^DEVICE node='"$N"' path=/dev/sda source=MXFS_DEV wwid=naa\.[0-9a-f]* fsid=[0-9a-f-]\{36\} ' "$OUT/c11.verdict")" 1 # capture-adjudicated: c11 above already ABORTed if the resolver produced no line; this counts the shape of the line it did produce
ck "12 MXFS_DEV set to an absent path -> ABORT naming it" "$(rej c12 'not a block device' env MXFS_DEV=/dev/mapper/mpatha bash -c '. tests/lib/rig.sh; mxfs_dev_resolve '"$N")" "rc=2 abort=1 why=named"
ck "12b MXFS_DEV=/dev/vda (a valid block device, the root disk) on the mounted node -> ABORT: no SCSI identity" "$(rej c12b 'carries no SCSI identity' env MXFS_DEV=/dev/vda bash -c '. tests/lib/rig.sh; mxfs_dev_resolve '"$N")" "rc=2 abort=1 why=named"
ck "12c the real LUN under a different declaration (well-formed, valid WWID and uuid, wrong instrument) -> ABORT naming the mismatch" "$(rej c12c 'is not the declared LUN' env MXFS_DEV=/dev/sda MXFS_LUN_WWID=naa.0000000000000000000000000000dead bash -c '. tests/lib/rig.sh; mxfs_dev_resolve '"$N")" "rc=2 abort=1 why=named"
ck "12d ... and mxfs_dev_same over both nodes under that declaration ABORTs too (agreement on the wrong LUN is not identity)" "$(rej c12d 'is not the declared LUN' env MXFS_LUN_WWID=naa.0000000000000000000000000000dead bash -c '. tests/lib/rig.sh; mxfs_dev_same test1 test2')" "rc=2 abort=1 why=named"
ck "13 no MXFS_DEV, live mxfs mount -> its device, by identity" "$( ( unset MXFS_DEV; mxfs_dev_resolve "$N" > "$OUT/c13.verdict"; echo "$MXFS_DEV_RESOLVED $MXFS_DEV_SOURCE" ) 2>&1 | tail -1)" "/dev/sda live-mount"
ck "13b the by-id alias of the same LUN -> accepted, same WWID and uuid as the path" "$( ( unset MXFS_DEV; mxfs_dev_resolve "$N" > /dev/null; a="$MXFS_DEV_WWID $MXFS_DEV_FSID"; MXFS_DEV=/dev/disk/by-id/wwn-0x$DECL mxfs_dev_resolve "$N" > "$OUT/c13b.verdict"; [ "$MXFS_DEV_WWID $MXFS_DEV_FSID" = "$a" ] && echo same || echo "differ: $a vs $MXFS_DEV_WWID $MXFS_DEV_FSID" ) 2>&1 | tail -1)" "same"
ck "13c mxfs_dev_same test1 test2 -> one LUN, one filesystem generation" "$( ( mxfs_dev_same test1 test2 > "$OUT/c13c.verdict" 2>&1 && echo "ok fsid=$MXFS_DEV_FSID" ) 2>&1 | tail -1 | sed 's/fsid=[0-9a-f-]\{36\}/fsid=uuid/')" "ok fsid=uuid"
ck "13d mxfs_dev_check after a resolve -> unchanged" "$( ( unset MXFS_DEV; mxfs_dev_resolve "$N" > /dev/null; mxfs_dev_check "$N" > "$OUT/c13d.verdict" 2>&1 && echo unchanged ) 2>&1 | tail -1)" "unchanged"
ck "13e a binding whose path was swapped for another device -> mxfs_dev_check ABORTs (the stale-binding case)" "$(rej c13e 'the binding moved' bash -c '. tests/lib/rig.sh; unset MXFS_DEV; mxfs_dev_resolve '"$N"' > /dev/null; MXFS_DEV_RESOLVED=/dev/vda; mxfs_dev_check '"$N")" "rc=2 abort=1 why=named"
ck "13f a binding whose filesystem generation changed -> mxfs_dev_check ABORTs naming the format" "$(rej c13f 'a format this harness did not perform' bash -c '. tests/lib/rig.sh; unset MXFS_DEV; mxfs_dev_resolve '"$N"' > /dev/null; MXFS_DEV_FSID=00000000-0000-0000-0000-000000000000; mxfs_dev_check '"$N")" "rc=2 abort=1 why=named"
ck "13g an undeclared rig -> ABORT, never a transport default" "$(rej c13g 'declares no LUN' env MXFS_RIG_TAG=norig MXFS_TRANSPORT=tcp bash -c '. tests/lib/rig.sh; unset MXFS_DEV; mxfs_dev_resolve '"$N")" "rc=2 abort=1 why=named"
# the unmounted-node path: the LUN is found by its declared identifier, never
# by a spelling; the root disk and a wrong declaration are still refused.  A
# real unmount of the peer node (bounded: a clean departure behind a live
# peer measures 35-80 s on TCP) and a real remount afterwards.
N2=$( [ "$N" = test1 ] && echo test2 || echo test1 )
um=$(rsx 130 "$N2" "timeout 120 umount $MNT && echo UMOUNT_OK; grep -c ' $MNT mxfs ' /proc/mounts" | tr '\n' ' ')
case $um in *'UMOUNT_OK 0'*)
    ck "13h no MXFS_DEV, no live mount on $N2 -> the declared LUN by its own identifier" "$( ( unset MXFS_DEV; mxfs_dev_resolve "$N2" > "$OUT/c13h.verdict"; echo "$MXFS_DEV_SOURCE $MXFS_DEV_RESOLVED" ) 2>&1 | tail -1)" "declared-wwid /dev/disk/by-id/wwn-0x$DECL"
    ck "13i MXFS_DEV=/dev/vda on the unmounted node -> ABORT: no SCSI identity (prep would have formatted the root disk)" "$(rej c13i 'carries no SCSI identity' env MXFS_DEV=/dev/vda bash -c '. tests/lib/rig.sh; mxfs_dev_resolve '"$N2")" "rc=2 abort=1 why=named"
    ck "13j no live mount, a wrong declaration, the transport default as the candidate -> ABORT naming the mismatch" "$(rej c13j 'is not the declared LUN' env MXFS_LUN_WWID=naa.0000000000000000000000000000dead MXFS_TRANSPORT=tcp bash -c '. tests/lib/rig.sh; unset MXFS_DEV; mxfs_dev_resolve '"$N2")" "rc=2 abort=1 why=named"
    rm=$(rsx 100 "$N2" "timeout 90 mount -t mxfs /dev/sda $MNT && echo MOUNT_OK; grep -c ' $MNT mxfs ' /proc/mounts" | tr '\n' ' ')
    case $rm in *'MOUNT_OK 1'*) echo "  INFO $N2 remounted" ;; *) echo "RESULT: INFRA label=$LABEL $N2 did not remount after the unmounted-node cases ($rm); the rig needs a prep"; exit 2 ;; esac
    ;;
*) echo "RESULT: INFRA label=$LABEL $N2 did not unmount cleanly for the unmounted-node cases ($um)"; exit 2 ;;
esac
ck "14 unreachable host in the resolver -> ABORT, never a default" "$(rej c14 'could not read' env MXFS_TRANSPORT=tcp bash -c '. tests/lib/rig.sh; unset MXFS_DEV; mxfs_dev_resolve test99')" "rc=2 abort=1 why=named"
echo "--- parent-assigned counts and values (window_count_into / value_now_into / prep_require)"
# each primitive runs in a subshell so its ABORT (exit 2) is observed here;
# what it assigned is printed from inside that subshell.  The mark is written
# to the node's ring first, so a valid window exists.
CMARK="RLC-$LABEL-$$"
rs 12 "$N" "echo '$CMARK' > /dev/kmsg; echo '$CMARK-PAYLOAD-X15' > /dev/kmsg" > /dev/null
ck "15 window_count_into: valid window, pattern present -> the count, assigned in the parent" "$( ( window_count_into c "$N" 15 "$CMARK" 'PAYLOAD-X15' c15 > "$OUT/c15.verdict" 2>&1 && echo "rc=0 c=$c" ) 2>&1 | tail -1)" "rc=0 c=1"
ck "15b window_count_into: valid window, pattern absent -> a real zero, no ABORT" "$( ( window_count_into c "$N" 15 "$CMARK" 'NOPE_NOT_A_LINE_X15B' c15b > "$OUT/c15b.verdict" 2>&1 && echo "rc=0 c=$c" ) 2>&1 | tail -1)" "rc=0 c=0"
ck "16 window_count_into: mark never written -> ABORT, never zero" "$( ( window_count_into c "$N" 15 "RLC-NEVER-WRITTEN-$$" 'anything' c16 > "$OUT/c16.verdict" 2>&1 ); [ $? = 2 ] && grep -qa '^ABORT:' "$OUT/c16.verdict" && echo abort=1 || echo abort=0)" "abort=1"
ck "17 window_count_into: unreachable host -> ABORT" "$( ( window_count_into c test99 15 "$CMARK" 'anything' c17 > "$OUT/c17.verdict" 2>&1 ); [ $? = 2 ] && grep -qa '^ABORT:' "$OUT/c17.verdict" && echo abort=1 || echo abort=0)" "abort=1"
ck "18 value_now_into: exactly one result line -> assigned whole" "$( ( value_now_into v "$N" 15 "$OUT/c18.txt" '^size=[0-9]+$' 'case 18' 'echo size=4096' > "$OUT/c18.verdict" 2>&1 && echo "rc=0 v=$v" ) 2>&1 | tail -1)" "rc=0 v=size=4096"
ck "18b value_now_into: the value printed, then the producer fails -> ABORT" "$( ( value_now_into v "$N" 15 "$OUT/c18b.txt" '^size=[0-9]+$' 'case 18b' 'echo size=0; exit 1' > "$OUT/c18b.verdict" 2>&1 ); [ $? = 2 ] && grep -qa '^ABORT:' "$OUT/c18b.verdict" && echo abort=1 || echo abort=0)" "abort=1"
ck "18c value_now_into: two result lines -> ABORT (cardinality)" "$( ( value_now_into v "$N" 15 "$OUT/c18c.txt" '^size=[0-9]+$' 'case 18c' 'echo size=1; echo size=2' > "$OUT/c18c.verdict" 2>&1 ); [ $? = 2 ] && grep -qa '^ABORT:' "$OUT/c18c.verdict" && echo abort=1 || echo abort=0)" "abort=1"
ck "18d value_now_into: empty output -> ABORT, never an empty value that equals nothing" "$( ( value_now_into v "$N" 15 "$OUT/c18d.txt" '^size=[0-9]+$' 'case 18d' 'true' > "$OUT/c18d.verdict" 2>&1 ); [ $? = 2 ] && grep -qa '^ABORT:' "$OUT/c18d.verdict" && echo abort=1 || echo abort=0)" "abort=1"
printf 'NODE_PREP_OK transport=tcp\n' > "$OUT/c19.txt"
ck "19 prep_require: NODE_PREP_OK present -> allowed" "$( ( prep_require "$OUT/c19.txt" 'case 19' > "$OUT/c19.verdict" 2>&1 && echo ok ) 2>&1 | tail -1)" "ok"
printf 'some earlier line\nNODE_PREP_FAIL: mount failed rc=32\nlater successful command\n' > "$OUT/c19b.txt"
ck "19b prep_require: NODE_PREP_FAIL, masked by a later successful command -> ABORT" "$( ( prep_require "$OUT/c19b.txt" 'case 19b' > "$OUT/c19b.verdict" 2>&1 ); [ $? = 2 ] && grep -qa '^ABORT:.*NODE_PREP_FAIL' "$OUT/c19b.verdict" && echo abort=1 || echo abort=0)" "abort=1"
printf 'only later successful commands\n' > "$OUT/c19c.txt"
ck "19c prep_require: no preparation record at all -> ABORT" "$( ( prep_require "$OUT/c19c.txt" 'case 19c' > "$OUT/c19c.verdict" 2>&1 ); [ $? = 2 ] && grep -qa '^ABORT:' "$OUT/c19c.verdict" && echo abort=1 || echo abort=0)" "abort=1"
ck "20 MXFS_FAULT_RSX_NTH: the n-th measurement goes to an unresolvable host and says so" "$( ( export MXFS_FAULT_RSX_NTH=1; rm -f "$OUT/.rsx_seq"; rsx 15 "$N" 'echo slot 0' > "$OUT/c20.txt" 2> "$OUT/c20.err"; echo "rc=$? fault=$(grep -ac 'STAGE FAULT' "$OUT/c20.err") rec=$(grep -ac "^$RS_STATUS_TAG v=1 host=$N-unreachable.invalid rc=255" "$OUT/c20.txt")" ) | tail -1)" "rc=255 fault=1 rec=1" # capture-adjudicated: c20 is a failed capture BY DESIGN; the counts are of the library's own STAGE FAULT line and status record, and the rc is the parent's own observation of the injected failure
echo "--- the assertion itself"
ck "21 ck with an EMPTY got and a wanted value -> ABORT, never a FAIL about MXFS" "$( ( ck 'x' '' '1' > "$OUT/c21.verdict" 2>&1 ); [ $? = 2 ] && grep -qa '^ABORT:.*EMPTY value' "$OUT/c21.verdict" && echo abort=1 || echo abort=0)" "abort=1"
ck "21b ckge with an EMPTY got -> ABORT" "$( ( ckge 'x' '' '1' > "$OUT/c21b.verdict" 2>&1 ); [ $? = 2 ] && grep -qa '^ABORT:.*EMPTY value' "$OUT/c21b.verdict" && echo abort=1 || echo abort=0)" "abort=1"
ck "21c ck wanting the empty string with an empty got -> a PASS (asserting emptiness is legitimate)" "$( ( ck 'y' '' '' ) 2>&1 | grep -ac '^  PASS y')" 1
ck "21d a FAIL is still a FAIL and counts" "$( ( fails=0; ck 'z' 1 2 > /dev/null 2>&1; echo "fails=$fails" ) 2>&1 | tail -1)" "fails=1"
echo "RESULT: $( [ $fails = 0 ] && echo PASS || echo FAIL ) label=$LABEL fails=$fails wall=$(( $(date +%s) - s0 ))s evidence=$OUT"
[ $fails = 0 ]
