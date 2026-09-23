#!/bin/bash
# d0977_open_unlink_tcp.sh — cross-node open-unlink on the TCP transport
# (D-TCP-NO-OPEN-TRACKING-PEER-HELD-FD-READS-THE-REUSED-INODES-NEW-FILE-
# BYTES-0977, fixed 0.89.0: open-holder marks on the authority ledger).
#
# ARM A (tracking ON, the lifetime face):
#   A creates F (16 KiB of 'V', fsync).  B opens F twice — fd7 read-only,
#   fd8 read-write — reads 4 KiB through fd7 and HOLDS both.  A unlinks F and
#   creates 20 files of 'G' in the same directory.  Required:
#     - F's inode number is NOT reused (B's mark deferred A's free);
#     - B's next 4 KiB through fd7 are the ORIGINAL bytes (4096 'V');
#     - B's 4 KiB write of 'W' through fd8 at offset 12288 succeeds and
#       reads back through fd7 (the descriptor still names F);
#     - B closes fd8 (one of two): 20 more creates on A still do not reuse
#       the number (multi-opener: the mark stays until the LAST close);
#     - B closes fd7 (the last): A's reaper frees the zombie and the number
#       IS reused within the reap cadence (first retry 5 s, then every 30 s
#       — bound 70 s of polling creates);
#     - every 'G' file A created is intact afterwards (16384 bytes of 'G').
#   Kernel evidence required: P90-OPEN-PUBLISH on B (the mark rode B's
#   release), P87-OPEN-DEFER on A (the guard read it under EX),
#   P977-OPEN-CLEAR-RIDE on B (the last close drove the clearing release).
#
# ARM C (tracking OFF on both nodes, the containment face):
#   the registry is switched off (open_tracking=0), so A frees F2 under B's
#   held descriptors and reuses the number.  Required: B's held-fd read FAILS
#   (never the successor's 'G' bytes — the s62d defect), B's held-fd write
#   FAILS, the 'G' files are intact, and B's kernel log shows the shell was
#   poisoned (EVICT-RING-FLAG ... poisoned=1 or P977-RELOAD-EXPOSED-MISMATCH).
#   The knob is restored to 1 on both nodes whatever happens.
#
# ARM B (both master faces): up to eight short victims (hold, unlink + 20
#   creates, not reused, original bytes through the held fd, close) until one
#   mastered locally AND one mastered by the peer have passed; the master is
#   read from the kernel rings (the node carrying the victim's mark commit).
#   Victims 1 and 2 reuse the previous victim's number (the successor-on-a-
#   reused-number shape); from victim 3 a spacer file moves the victim to a
#   fresh number while a face is missing.  Required per victim, on B's ring:
#   no EVICT-RING-FLAG poisoned=1 for the number (the peer never freed the
#   incarnation B holds open); EVICT-RING-OTHER-INCARN with opens>=1 is the
#   counted exposure.
#
# the budget rule (derived): arm A ≈ setup 5 s + holder 2 s + unlink/20
# creates 10 s + read/write 2 s + 20 creates 8 s + last-close reap poll ≤ 70 s
# + integrity 5 s ≈ 105 s; arm B ≤ 8 × ~16 s = 128 s; arm D ≤ 45 s; arm C
# ≈ 25 s; dmesg 6 s ⇒ ~310 s.  Bound 340 s.
#
# Usage: tests/d0977_open_unlink_tcp.sh <label> [nodeA] [nodeB]  (default test1 test2)
set -u
LABEL=${1:?label}; A=${2:-test1}; B=${3:-test2}
cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
MNT=${MXFS_MNT:-/mnt/shared}
OUT=${D0977_OUT:-tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0977}
mkdir -p "$OUT"
fails=0
. "$(dirname "$0")/lib/rig.sh"

KNOB=/sys/module/mxfs/parameters/open_tracking
D="$MNT/.d0977_$LABEL"
F="$D/victim.dat"
F2="$D/victim2.dat"
GO=/tmp/d0977.go
echo "=== d0977_open_unlink_tcp label=$LABEL A=$A B=$B out=$OUT $(date -u +%FT%TZ) ==="
MARK="D0977-$LABEL-$$"
rs 20 "$A" "echo '$MARK' > /dev/kmsg" >/dev/null
rs 20 "$B" "echo '$MARK' > /dev/kmsg" >/dev/null

vmd5=$(dd if=/dev/zero bs=4096 count=1 2>/dev/null | tr '\0' 'V' | md5sum | cut -d' ' -f1)
wmd5=$(dd if=/dev/zero bs=4096 count=1 2>/dev/null | tr '\0' 'W' | md5sum | cut -d' ' -f1)
gmd5=$(dd if=/dev/zero bs=4096 count=1 2>/dev/null | tr '\0' 'G' | md5sum | cut -d' ' -f1)
g16md5=$(dd if=/dev/zero bs=4096 count=4 2>/dev/null | tr '\0' 'G' | md5sum | cut -d' ' -f1)

restore_knob() {
    rs 20 "$A" "echo 1 > $KNOB" >/dev/null
    rs 20 "$B" "echo 1 > $KNOB" >/dev/null
}
trap restore_knob EXIT

# the knob must be ON for arm A, on both nodes, and say so
value_now_into ka "$A" 20 "$OUT/knob_a0.txt" '^KNOB=[01]$' "open_tracking on $A" "echo 1 > $KNOB; echo KNOB=\$(cat $KNOB)"
value_now_into kb "$B" 20 "$OUT/knob_b0.txt" '^KNOB=[01]$' "open_tracking on $B" "echo 1 > $KNOB; echo KNOB=\$(cat $KNOB)"
ck "arm A: open_tracking=1 on both nodes" "$ka/$kb" "KNOB=1/KNOB=1"

# ---------- ARM A ----------
value_now_into vline "$A" 25 "$OUT/a_setup.txt" '^VINO=[0-9]+$' "A's victim create" \
  "mkdir -p '$D' && dd if=/dev/zero bs=4096 count=4 2>/dev/null | tr '\\0' 'V' > '$F' && sync -f '$F' && echo VINO=\$(stat -c %i '$F')"
vino=${vline#VINO=}
echo "arm A victim ino=$vino"

# B: open twice, read 4 KiB through fd7, hold; the go-file stages the rest
( timeout 150 $SSH "$B" "
    rm -f $GO.1 $GO.2 $GO.3
    exec 7<'$F' || { echo BOPEN7=fail; exit 1; }
    exec 8<>'$F' || { echo BOPEN8=fail; exit 1; }
    head -c 4096 <&7 >/dev/null 2>&1 && echo BREAD1=ok || echo BREAD1=fail
    n=0; while [ \$n -lt 120 ] && [ ! -e $GO.1 ]; do sleep 0.5; n=\$((n+1)); done
    # the next 4 KiB (offset 4096) through the held read fd: the POSIX claim
    head -c 4096 <&7 > /tmp/d0977.b2 2>/tmp/d0977.b2err; rc=\$?
    echo BREAD2_RC=\$rc BREAD2_MD5=\$(md5sum < /tmp/d0977.b2 | cut -d' ' -f1) BREAD2_LEN=\$(wc -c < /tmp/d0977.b2)
    # a write through the held rw fd at offset 12288: the descriptor names F
    tr '\\0' 'W' < /dev/zero | dd bs=4096 count=1 seek=3 conv=notrunc >&8 2>/tmp/d0977.werr; wrc=\$?
    echo BWRITE_RC=\$wrc
    # read it back through fd7 (position 8192 -> skip one block -> 12288)
    dd bs=4096 skip=1 count=1 <&7 > /tmp/d0977.b3 2>/tmp/d0977.b3err; rc3=\$?
    echo BREAD3_RC=\$rc3 BREAD3_MD5=\$(md5sum < /tmp/d0977.b3 | cut -d' ' -f1)
    n=0; while [ \$n -lt 120 ] && [ ! -e $GO.2 ]; do sleep 0.5; n=\$((n+1)); done
    exec 8<&-; echo BCLOSE8=done
    n=0; while [ \$n -lt 120 ] && [ ! -e $GO.3 ]; do sleep 0.5; n=\$((n+1)); done
    exec 7<&-; echo BCLOSE7=done
  " > "$OUT/b_holder.txt" 2> "$OUT/b_holder.err" ) &
BPID=$!
sleep 2
capture_require_bg "$OUT/b_holder.txt" "$OUT/b_holder.err" '^BREAD1=' "B's holder open and first read" || { echo "ABORT: B's holder has not reported its first read 2 s after launch (stdout=[$(tr '\n' ' ' < "$OUT/b_holder.txt" | cut -c1-120)])"; echo "RESULT: ABORT label=$LABEL stage=capture evidence=$OUT"; kill $BPID 2>/dev/null; exit 2; }
ck "arm A: B first read ok" "$(grep -ac 'BREAD1=ok' "$OUT/b_holder.txt")" "1"

# A: unlink F, then 20 creates — the number must NOT be reused
value_now_into r1 "$A" 60 "$OUT/a_arm1.txt" '^ARM_A1_REUSED=' "A's unlink + 20 creates" "
    rm -f '$F'
    reused=none; i=0
    while [ \$i -lt 20 ]; do
        i=\$((i+1)); g=\"$D/a1_\$i.dat\"
        dd if=/dev/zero bs=4096 count=4 2>/dev/null | tr '\\0' 'G' > \"\$g\"; sync -f \"\$g\"
        [ \"\$(stat -c %i \"\$g\")\" = \"$vino\" ] && reused=\$g
    done
    echo ARM_A1_REUSED=\$reused"
ck "arm A: ino NOT reused while B holds two fds" "${r1#ARM_A1_REUSED=}" "none"

# B: the held-fd read and write
rs 20 "$B" "touch $GO.1" >/dev/null
for i in $(seq 1 40); do grep -qa 'BREAD3_RC=' "$OUT/b_holder.txt" && break; sleep 0.5; done
capture_require_bg "$OUT/b_holder.txt" "$OUT/b_holder.err" '^BREAD3_RC=' "B's held-fd read/write round" || { echo "ABORT: B's holder never reported its read/write round"; echo "RESULT: ABORT label=$LABEL stage=capture evidence=$OUT"; kill $BPID 2>/dev/null; exit 2; }
brc=$(grep -ao 'BREAD2_RC=[0-9]*' "$OUT/b_holder.txt" | tail -1 | cut -d= -f2)
bmd5=$(grep -ao 'BREAD2_MD5=[0-9a-f]*' "$OUT/b_holder.txt" | tail -1 | cut -d= -f2)
blen=$(grep -ao 'BREAD2_LEN=[0-9]*' "$OUT/b_holder.txt" | tail -1 | cut -d= -f2)
ck "arm A: B held-fd read rc" "${brc:-none}" "0"
ck "arm A: B held-fd read returned 4096 bytes" "${blen:-none}" "4096"
ck "arm A: B held-fd read returned the ORIGINAL bytes (4096 'V')" "$([ "${bmd5:-none}" = "$vmd5" ] && echo original || echo other:${bmd5:-none})" "original"
wrc=$(grep -ao 'BWRITE_RC=[0-9]*' "$OUT/b_holder.txt" | tail -1 | cut -d= -f2)
ck "arm A: B held-fd write rc" "${wrc:-none}" "0"
b3=$(grep -ao 'BREAD3_MD5=[0-9a-f]*' "$OUT/b_holder.txt" | tail -1 | cut -d= -f2)
ck "arm A: B reads its own write back through the held fd (4096 'W')" "$([ "${b3:-none}" = "$wmd5" ] && echo own-write || echo other:${b3:-none})" "own-write"

# B closes fd8 (one of two): still deferred
rs 20 "$B" "touch $GO.2" >/dev/null
for i in $(seq 1 20); do grep -qa 'BCLOSE8=done' "$OUT/b_holder.txt" && break; sleep 0.5; done
ck "arm A: B closed fd8" "$(grep -ac 'BCLOSE8=done' "$OUT/b_holder.txt")" "1"
sleep 2
value_now_into r2 "$A" 60 "$OUT/a_arm2.txt" '^ARM_A2_REUSED=' "A's 20 creates after one close" "
    reused=none; i=0
    while [ \$i -lt 20 ]; do
        i=\$((i+1)); g=\"$D/a2_\$i.dat\"
        dd if=/dev/zero bs=4096 count=4 2>/dev/null | tr '\\0' 'G' > \"\$g\"; sync -f \"\$g\"
        [ \"\$(stat -c %i \"\$g\")\" = \"$vino\" ] && reused=\$g
    done
    echo ARM_A2_REUSED=\$reused"
ck "arm A: ino still NOT reused after B closed one of two fds" "${r2#ARM_A2_REUSED=}" "none"

# B closes fd7 (the last): the number must become reusable
rs 20 "$B" "touch $GO.3" >/dev/null
wait "$BPID"
ck "arm A: B closed fd7 (last)" "$(grep -ac 'BCLOSE7=done' "$OUT/b_holder.txt")" "1"
value_now_into r3 "$A" 110 "$OUT/a_arm3.txt" '^ARM_A3_REUSED=' "A's creates until reuse after the last close" "
    reused=none; t=0; n=0
    while [ \$t -lt 70 ] && [ \$reused = none ]; do
        k=0
        while [ \$k -lt 5 ]; do
            k=\$((k+1)); n=\$((n+1)); g=\"$D/a3_\$n.dat\"
            dd if=/dev/zero bs=4096 count=4 2>/dev/null | tr '\\0' 'G' > \"\$g\"; sync -f \"\$g\"
            [ \"\$(stat -c %i \"\$g\")\" = \"$vino\" ] && reused=\$g
        done
        [ \$reused = none ] || break
        sleep 5; t=\$((t+5))
    done
    echo ARM_A3_REUSED=\$reused ARM_A3_T=\$t ARM_A3_N=\$n"
echo "  $r3"
r3v=$(echo "$r3" | grep -ao 'ARM_A3_REUSED=[^ ]*' | cut -d= -f2)
ck "arm A: ino reused after B's LAST close (reaper freed the zombie)" "$([ -n "$r3v" ] && [ "$r3v" != none ] && echo yes || echo no)" "yes"

# every 'G' file intact on A (B's write through the held fd touched only F)
value_now_into gi "$A" 60 "$OUT/a_integrity.txt" '^GFILES=' "A's integrity sweep of the G files" "
    bad=0; n=0
    for g in $D/a1_*.dat $D/a2_*.dat $D/a3_*.dat; do
        n=\$((n+1))
        [ \"\$(md5sum < \"\$g\" | cut -d' ' -f1)\" = \"$g16md5\" ] || bad=\$((bad+1))
    done
    echo GFILES=\$n BAD=\$bad"
echo "  $gi"
ck "arm A: every G file on A intact" "$(echo "$gi" | grep -ao 'BAD=[0-9]*' | cut -d= -f2)" "0"

# ---------- ARM B: both master faces ----------
# Which node masters the victim's ledger record is fixed by the view (the page
# its resource hashes to, and that page's owner), so one victim exercises ONE
# of the two ways the guard's snapshot reaches the unlinker: a locally
# mastered victim reads the stamp finalize put on the master's own chain
# entry; a remotely mastered one reads the mask the LOCK_GRANT and its
# re-affirm carried — the path s64a measured empty (the re-affirm sent an
# unassigned mask, 0.89.1).  Both must pass.  Short ladder per victim, no reap
# poll: hold on B, unlink + 20 creates on A, the number not reused, the held
# read returns the original bytes, close.  The master is read from the kernel
# rings: the node whose ring carries the victim's mark commit
# (P977-REL-MARK ino=<v> ... op=1) is the master.  Up to 6 victims.
#
# The number: A's reaper frees each victim ~5 s after B's close, and the next
# create takes the lowest free number, so every victim lands on the SAME number
# and the same master face (s170f: six victims, all 2127, all local).  Victims
# 1 and 2 keep that reuse on purpose — it is the shape that recycles B's cached
# shell in place for the successor while the previous incarnation's free entry
# is still in the eviction ring (0.89.76: that entry must leave the successor
# alone; before, a successor whose random generation fell below the freed one
# was poisoned and the held fd read -ESTALE, s170f victims 2 and 4).  From
# victim 3 on, while one face is still missing, A creates a SPACER file first
# so it takes the freed number and the victim gets a fresh one, which hashes
# to the other master with probability 1/2 per victim.  Up to 8 victims.
seen_local=0; seen_remote=0; v=0; exposures=0
while [ $v -lt 8 ] && { [ $seen_local -eq 0 ] || [ $seen_remote -eq 0 ]; }; do
    v=$((v+1)); FV="$D/victim_b$v.dat"; spacer=""
    [ $v -ge 3 ] && spacer="dd if=/dev/zero bs=4096 count=1 2>/dev/null > '$D/spacer_b$v.dat' && sync -f '$D/spacer_b$v.dat' && echo SPACER=\$(stat -c %i '$D/spacer_b$v.dat');"
    value_now_into vl "$A" 25 "$OUT/b${v}_setup.txt" '^VINO=[0-9]+$' "A's arm-B victim $v create" \
      "$spacer dd if=/dev/zero bs=4096 count=4 2>/dev/null | tr '\\0' 'V' > '$FV' && sync -f '$FV' && echo VINO=\$(stat -c %i '$FV')"
    vb=${vl#VINO=}
    ( timeout 90 $SSH "$B" "
        rm -f $GO.b$v
        exec 7<'$FV' || { echo BOPEN7=fail; exit 1; }
        head -c 4096 <&7 >/dev/null 2>&1 && echo BREAD1=ok || echo BREAD1=fail
        n=0; while [ \$n -lt 120 ] && [ ! -e $GO.b$v ]; do sleep 0.5; n=\$((n+1)); done
        head -c 4096 <&7 > /tmp/d0977.bb 2> /tmp/d0977.bb.err; rc=\$?
        echo BREAD2_RC=\$rc BREAD2_MD5=\$(md5sum < /tmp/d0977.bb | cut -d' ' -f1) BREAD2_ERR=\$(sed 's/.*: //' /tmp/d0977.bb.err | tr ' ' '_' | tail -c 40)
        exec 7<&-; echo BCLOSE7=done
      " > "$OUT/b${v}_holder.txt" 2> "$OUT/b${v}_holder.err" ) &
    HPID=$!
    sleep 2
    capture_require_bg "$OUT/b${v}_holder.txt" "$OUT/b${v}_holder.err" '^BREAD1=' "B's arm-B holder $v open and first read" || { echo "ABORT: B's arm-B holder $v has not reported its first read"; echo "RESULT: ABORT label=$LABEL stage=capture evidence=$OUT"; kill $HPID 2>/dev/null; exit 2; }
    value_now_into rb "$A" 60 "$OUT/b${v}_arm.txt" '^ARM_B_REUSED=' "A's unlink + 20 creates (arm-B victim $v)" "
        rm -f '$FV'
        reused=none; i=0
        while [ \$i -lt 20 ]; do
            i=\$((i+1)); g=\"$D/b${v}_\$i.dat\"
            dd if=/dev/zero bs=4096 count=4 2>/dev/null | tr '\\0' 'G' > \"\$g\"; sync -f \"\$g\"
            [ \"\$(stat -c %i \"\$g\")\" = \"$vb\" ] && reused=\$g
        done
        echo ARM_B_REUSED=\$reused"
    rs 20 "$B" "touch $GO.b$v" >/dev/null
    wait "$HPID"
    capture_require_bg "$OUT/b${v}_holder.txt" "$OUT/b${v}_holder.err" '^BCLOSE7=done' "B's arm-B holder $v round" || { echo "ABORT: B's arm-B holder $v never finished"; echo "RESULT: ABORT label=$LABEL stage=capture evidence=$OUT"; exit 2; }
    value_now_into ma "$A" 20 "$OUT/b${v}_master_a.txt" '^MARKS=[0-9]+$' "A's mark commits for arm-B victim $v" "echo MARKS=\$(dmesg | sed -n '/$MARK/,\$p' | grep -ac 'P977-REL-MARK ino=$vb .*op=1 ')"
    value_now_into mb "$B" 20 "$OUT/b${v}_master_b.txt" '^MARKS=[0-9]+$' "B's mark commits for arm-B victim $v" "echo MARKS=\$(dmesg | sed -n '/$MARK/,\$p' | grep -ac 'P977-REL-MARK ino=$vb .*op=1 ')"
    ma=${ma#MARKS=}; mb=${mb#MARKS=}
    if [ "$ma" -gt 0 ] && [ "$mb" -eq 0 ]; then master=local
    elif [ "$mb" -gt 0 ] && [ "$ma" -eq 0 ]; then master=remote
    else master=unclassified; fi
    echo "arm B victim $v ino=$vb master=$master (mark commits: A=$ma B=$mb)"
    ck "arm B victim $v: the master is classifiable from the mark commit (A=$ma B=$mb)" "$([ $master = unclassified ] && echo no || echo yes)" "yes"
    ck "arm B victim $v ($master master): ino NOT reused while B holds the fd" "${rb#ARM_B_REUSED=}" "none"
    bbrc=$(grep -ao 'BREAD2_RC=[0-9]*' "$OUT/b${v}_holder.txt" | tail -1 | cut -d= -f2)
    bbmd5=$(grep -ao 'BREAD2_MD5=[0-9a-f]*' "$OUT/b${v}_holder.txt" | tail -1 | cut -d= -f2)
    bberr=$(grep -ao 'BREAD2_ERR=[^ ]*' "$OUT/b${v}_holder.txt" | tail -1 | cut -d= -f2)
    ck "arm B victim $v ($master master): B held-fd read rc (err=${bberr:-none})" "${bbrc:-none}" "0"
    ck "arm B victim $v ($master master): B held-fd read returned the ORIGINAL bytes" "$([ "${bbmd5:-none}" = "$vmd5" ] && echo original || echo other:${bbmd5:-none})" "original"
    value_now_into pd "$A" 20 "$OUT/b${v}_defer_a.txt" '^DEFERS=[0-9]+$' "A's guard defers for arm-B victim $v" "echo DEFERS=\$(dmesg | sed -n '/$MARK/,\$p' | grep -ac 'P87-OPEN-DEFER ino=$vb ')"
    ckge "arm B victim $v ($master master): A's guard deferred (P87-OPEN-DEFER ino=$vb)" "${pd#DEFERS=}" 1
    # the eviction ring on B: an entry for ANOTHER incarnation of the number
    # that lands while B holds this one open is the exposure (0.89.76 probe,
    # counted across the arm); an entry that poisons B's live shell of a
    # number the peer has NOT freed is the s170f defect and must be zero.
    value_now_into rg "$B" 20 "$OUT/b${v}_ring_b.txt" '^OTHER=[0-9]+ POISONED=[0-9]+$' "B's ring entries for arm-B victim $v" \
      "echo OTHER=\$(dmesg | sed -n '/$MARK/,\$p' | grep -a 'EVICT-RING-OTHER-INCARN ino=$vb ' | grep -ac 'opens=[1-9]') POISONED=\$(dmesg | sed -n '/$MARK/,\$p' | grep -a 'EVICT-RING-FLAG ino=$vb ' | grep -ac 'poisoned=1')"
    rgo=$(echo "$rg" | grep -ao 'OTHER=[0-9]*' | cut -d= -f2); rgp=$(echo "$rg" | grep -ao 'POISONED=[0-9]*' | cut -d= -f2)
    exposures=$((exposures + ${rgo:-0}))
    ck "arm B victim $v ($master master): the ring never poisoned B's live shell (EVICT-RING-FLAG ino=$vb poisoned=1)" "${rgp:-none}" "0"
    [ $master = local ] && seen_local=1
    [ $master = remote ] && seen_remote=1
done
echo "  arm B: ring entries for another incarnation that landed while B held the number open: $exposures"
ck "arm B: a LOCALLY mastered victim was exercised" "$seen_local" "1"
ck "arm B: a REMOTELY mastered victim was exercised (the LOCK_GRANT / re-affirm face)" "$seen_remote" "1"

# ---------- ARM D: a fresh open on a number the peer reused ----------
# B's shell of the last arm-B victim (number $vb) is still cached at NL with
# the OLD incarnation.  A's reaper frees the zombie and A creates until a
# file lands on that number (a new generation).  B then opens THAT file and
# reads it: the open must adopt the platter's incarnation and serve the new
# file's bytes.  Measured s65b (D-0979): the two descriptors of the open
# itself were counted as exposure of the old incarnation, the shell was
# poisoned, and the freshly opened valid file read -ESTALE.
value_now_into rd "$A" 110 "$OUT/d_reuse.txt" '^ARM_D_REUSED=' "A's creates until the last arm-B number is reused" "
    reused=none; t=0; n=0
    while [ \$t -lt 70 ] && [ \$reused = none ]; do
        k=0
        while [ \$k -lt 5 ]; do
            k=\$((k+1)); n=\$((n+1)); g=\"$D/d_\$n.dat\"
            dd if=/dev/zero bs=4096 count=4 2>/dev/null | tr '\\0' 'G' > \"\$g\"; sync -f \"\$g\"
            [ \"\$(stat -c %i \"\$g\")\" = \"$vb\" ] && reused=\$g
        done
        [ \$reused = none ] || break
        sleep 5; t=\$((t+5))
    done
    echo ARM_D_REUSED=\$reused ARM_D_T=\$t ARM_D_N=\$n"
echo "  $rd"
rdv=$(echo "$rd" | grep -ao 'ARM_D_REUSED=[^ ]*' | cut -d= -f2)
ck "arm D: A reused the last arm-B number ($vb) after B's close" "$([ -n "$rdv" ] && [ "$rdv" != none ] && echo yes || echo no)" "yes"
if [ -n "$rdv" ] && [ "$rdv" != none ]; then
    measure "$B" 30 "$OUT/d_open_b.txt" '^DREAD_RC=[0-9]+' "B's open and read of the reused number's new file" "exec 7<'$rdv' || { echo DOPEN=fail; echo DREAD_RC=99; exit 0; }; head -c 4096 <&7 > /tmp/d0977.d 2>/tmp/d0977.derr; rc=\$?; exec 7<&-; echo DREAD_RC=\$rc DREAD_MD5=\$(md5sum < /tmp/d0977.d | cut -d' ' -f1) DREAD_ERR=\$(tr '\n' ' ' < /tmp/d0977.derr | grep -ao 'Stale file handle\|Input/output error' | head -1 | tr ' ' '_')"
    drc=$(grep -ao 'DREAD_RC=[0-9]*' "$OUT/d_open_b.txt" | tail -1 | cut -d= -f2)
    dmd5=$(grep -ao 'DREAD_MD5=[0-9a-f]*' "$OUT/d_open_b.txt" | tail -1 | cut -d= -f2)
    echo "  arm D: B read rc=${drc:-none} md5=${dmd5:-none} err=$(grep -ao 'DREAD_ERR=[A-Za-z_/]*' "$OUT/d_open_b.txt" | tail -1 | cut -d= -f2)"
    ck "arm D: B's fresh open on the reused number reads (rc 0, no ESTALE)" "${drc:-none}" "0"
    ck "arm D: B's fresh open reads the NEW file's bytes (4096 'G')" "$([ "${dmd5:-none}" = "$gmd5" ] && echo new-file || echo other:${dmd5:-none})" "new-file"
    value_now_into dp "$B" 20 "$OUT/d_poison_b.txt" '^POISONS=[0-9]+$' "B's poison lines for the reused number" "echo POISONS=\$(dmesg | sed -n '/$MARK/,\$p' | grep -ac 'P977-RELOAD-EXPOSED-MISMATCH ino=$vb ')"
    ck "arm D: B's shell was NOT poisoned by its own open (P977-RELOAD-EXPOSED-MISMATCH ino=$vb since the marker)" "${dp#POISONS=}" "0"
fi

# ---------- ARM C: tracking OFF (containment) ----------
value_now_into ka "$A" 20 "$OUT/knob_a1.txt" '^KNOB=[01]$' "open_tracking off on $A" "echo 0 > $KNOB; echo KNOB=\$(cat $KNOB)"
value_now_into kb "$B" 20 "$OUT/knob_b1.txt" '^KNOB=[01]$' "open_tracking off on $B" "echo 0 > $KNOB; echo KNOB=\$(cat $KNOB)"
ck "arm C: open_tracking=0 on both nodes" "$ka/$kb" "KNOB=0/KNOB=0"
MARKC="D0977C-$LABEL-$$"
rs 20 "$B" "echo '$MARKC' > /dev/kmsg" >/dev/null

value_now_into vline2 "$A" 25 "$OUT/a_setup2.txt" '^VINO=[0-9]+$' "A's arm-C victim create" \
  "dd if=/dev/zero bs=4096 count=4 2>/dev/null | tr '\\0' 'V' > '$F2' && sync -f '$F2' && echo VINO=\$(stat -c %i '$F2')"
vino2=${vline2#VINO=}
echo "arm C victim ino=$vino2"

( timeout 120 $SSH "$B" "
    rm -f $GO.c1
    exec 7<'$F2' || { echo BOPEN7=fail; exit 1; }
    exec 8<>'$F2' || { echo BOPEN8=fail; exit 1; }
    head -c 4096 <&7 >/dev/null 2>&1 && echo BREAD1=ok || echo BREAD1=fail
    n=0; while [ \$n -lt 120 ] && [ ! -e $GO.c1 ]; do sleep 0.5; n=\$((n+1)); done
    dd bs=4096 count=1 <&7 > /tmp/d0977.c2 2>/tmp/d0977.c2err; rc=\$?
    echo CREAD2_RC=\$rc CREAD2_MD5=\$(md5sum < /tmp/d0977.c2 | cut -d' ' -f1) CREAD2_LEN=\$(wc -c < /tmp/d0977.c2) CREAD2_ERR=\$(tr '\n' ' ' < /tmp/d0977.c2err | grep -ao 'Stale file handle\|Input/output error' | head -1 | tr ' ' '_')
    tr '\\0' 'W' < /dev/zero | dd bs=4096 count=1 seek=3 conv=notrunc >&8 2>/tmp/d0977.cwerr; wrc=\$?
    echo CWRITE_RC=\$wrc CWRITE_ERR=\$(tr '\n' ' ' < /tmp/d0977.cwerr | grep -ao 'Stale file handle\|Input/output error' | head -1 | tr ' ' '_')
    exec 8<&-; exec 7<&-; echo CCLOSE=done
  " > "$OUT/c_holder.txt" 2> "$OUT/c_holder.err" ) &
CPID=$!
sleep 2
capture_require_bg "$OUT/c_holder.txt" "$OUT/c_holder.err" '^BREAD1=' "B's arm-C holder open and first read" || { echo "ABORT: B's arm-C holder has not reported its first read"; echo "RESULT: ABORT label=$LABEL stage=capture evidence=$OUT"; kill $CPID 2>/dev/null; exit 2; }
ck "arm C: B first read ok" "$(grep -ac 'BREAD1=ok' "$OUT/c_holder.txt")" "1"

value_now_into rc1 "$A" 60 "$OUT/a_armc.txt" '^ARM_C_REUSED=' "A's unlink + creates until reuse (tracking off)" "
    rm -f '$F2'
    reused=none; i=0
    while [ \$i -lt 40 ] && [ \$reused = none ]; do
        i=\$((i+1)); g=\"$D/c_\$i.dat\"
        dd if=/dev/zero bs=4096 count=4 2>/dev/null | tr '\\0' 'G' > \"\$g\"; sync -f \"\$g\"
        [ \"\$(stat -c %i \"\$g\")\" = \"$vino2\" ] && reused=\$g
    done
    echo ARM_C_REUSED=\$reused ARM_C_N=\$i"
echo "  $rc1"
rc1v=$(echo "$rc1" | grep -ao 'ARM_C_REUSED=[^ ]*' | cut -d= -f2)
ck "arm C: ino reused under B's held fds (registry off — the defect's precondition)" "$([ -n "$rc1v" ] && [ "$rc1v" != none ] && echo yes || echo no)" "yes"

rs 20 "$B" "touch $GO.c1" >/dev/null
wait "$CPID"
capture_require_bg "$OUT/c_holder.txt" "$OUT/c_holder.err" '^CCLOSE=done' "B's arm-C holder round" || { echo "ABORT: B's arm-C holder never finished its round"; echo "RESULT: ABORT label=$LABEL stage=capture evidence=$OUT"; exit 2; }
crc=$(grep -ao 'CREAD2_RC=[0-9]*' "$OUT/c_holder.txt" | tail -1 | cut -d= -f2)
cmd5=$(grep -ao 'CREAD2_MD5=[0-9a-f]*' "$OUT/c_holder.txt" | tail -1 | cut -d= -f2)
cerr=$(grep -ao 'CREAD2_ERR=[A-Za-z_/]*' "$OUT/c_holder.txt" | tail -1 | cut -d= -f2)
cwrc=$(grep -ao 'CWRITE_RC=[0-9]*' "$OUT/c_holder.txt" | tail -1 | cut -d= -f2)
cwerr=$(grep -ao 'CWRITE_ERR=[A-Za-z_/]*' "$OUT/c_holder.txt" | tail -1 | cut -d= -f2)
echo "  arm C held-fd read rc=$crc err=${cerr:-none} md5=$cmd5; write rc=$cwrc err=${cwerr:-none}"
ck "arm C: B held-fd read FAILS (never the successor's bytes)" "$([ "${crc:-0}" != 0 ] && echo refused || echo served)" "refused"
ck "arm C: B held-fd read did not return 4096 'G'" "$([ "${cmd5:-none}" = "$gmd5" ] && echo successor-bytes || echo not-successor)" "not-successor"
ck "arm C: B held-fd read refused with ESTALE" "${cerr:-none}" "Stale_file_handle"
ck "arm C: B held-fd write FAILS" "$([ "${cwrc:-0}" != 0 ] && echo refused || echo accepted)" "refused"

value_now_into gi2 "$A" 60 "$OUT/a_integrity2.txt" '^GFILES=' "A's integrity sweep of the arm-C G files" "
    bad=0; n=0
    for g in $D/c_*.dat; do
        n=\$((n+1))
        [ \"\$(md5sum < \"\$g\" | cut -d' ' -f1)\" = \"$g16md5\" ] || bad=\$((bad+1))
    done
    echo GFILES=\$n BAD=\$bad"
echo "  $gi2"
ck "arm C: every G file on A intact (no write through the poisoned shell)" "$(echo "$gi2" | grep -ao 'BAD=[0-9]*' | cut -d= -f2)" "0"

restore_knob
value_now_into ka "$A" 20 "$OUT/knob_a2.txt" '^KNOB=[01]$' "open_tracking restored on $A" "echo KNOB=\$(cat $KNOB)"
value_now_into kb "$B" 20 "$OUT/knob_b2.txt" '^KNOB=[01]$' "open_tracking restored on $B" "echo KNOB=\$(cat $KNOB)"
ck "knob restored: open_tracking=1 on both nodes" "$ka/$kb" "KNOB=1/KNOB=1"

# ---------- kernel evidence ----------
measure "$B" 25 "$OUT/b_dmesg.txt" '^DMESG_END$' "the kernel log on $B from the lap marker" "dmesg | sed -n \"/$MARK/,\\\$p\"; echo DMESG_END"
measure "$A" 25 "$OUT/a_dmesg.txt" '^DMESG_END$' "the kernel log on $A from the lap marker" "dmesg | sed -n \"/$MARK/,\\\$p\"; echo DMESG_END"
awk "/$MARKC/{p=1} p" "$OUT/b_dmesg.txt" > "$OUT/b_dmesg_armc.txt"
ckge "arm A: B published its mark (P90-OPEN-PUBLISH ino=$vino)" "$(grep -ac "P90-OPEN-PUBLISH ino=$vino " "$OUT/b_dmesg.txt")" 1
ckge "arm A: A's guard deferred on B's mark (P87-OPEN-DEFER ino=$vino)" "$(grep -ac "P87-OPEN-DEFER ino=$vino " "$OUT/a_dmesg.txt")" 1
ck "arm A: no unreadable-bitmap defer (P87-OPEN-DEFER-ERR)" "$(grep -ac 'P87-OPEN-DEFER-ERR' "$OUT/a_dmesg.txt")" 0
ckge "arm A: B's last close drove the clearing release (P977-OPEN-CLEAR-RIDE ino=$vino)" "$(grep -ac "P977-OPEN-CLEAR-RIDE ino=$vino " "$OUT/b_dmesg.txt")" 1
ckge "arm A: A's reaper retried the zombie (P88-REAP-RETRY ino=$vino)" "$(grep -ac "P88-REAP-RETRY ino=$vino " "$OUT/a_dmesg.txt")" 1
ckge "arm C: B's shell was poisoned (EVICT-RING poisoned=1 or P977-RELOAD-EXPOSED-MISMATCH ino=$vino2)" "$(grep -aE "(EVICT-RING-FLAG ino=$vino2 .*poisoned=1|P977-RELOAD-EXPOSED-MISMATCH ino=$vino2 )" "$OUT/b_dmesg_armc.txt" | wc -l)" 1
splb=$(grep -aEc 'BUG:|Oops|WARNING:.*lockdep' "$OUT/b_dmesg.txt")
spla=$(grep -aEc 'BUG:|Oops|WARNING:.*lockdep' "$OUT/a_dmesg.txt")
ck "zero splats on B" "$splb" "0"
ck "zero splats on A" "$spla" "0"

rs 40 "$A" "rm -rf '$D'" >/dev/null
if [ "$fails" -eq 0 ]; then echo "VERDICT PASS: d0977 arms A (lifetime) + B (both master faces) + D (fresh open on a reused number) + C (containment)"; echo "RESULT: PASS label=$LABEL evidence=$OUT"; exit 0; fi
echo "VERDICT FAIL: $fails assertion(s)"; echo "RESULT: FAIL label=$LABEL fails=$fails evidence=$OUT"; exit 1
