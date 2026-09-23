#!/bin/bash
# (bash: tests/lib/rig.sh uses indirect expansion and printf -v; under sh
#  the lap died with "Bad substitution" before its first verdict, s59h)
# d512_t1_reuse.sh — D-512 cycle-2 verification T1 (sess415 ruling): clean
# lazy shell + exact inode-number reuse, cross-node.  TWO ARMS (the ruling's
# single-arm T1 presumed reuse can proceed while B holds an open fd; MXFS's
# open-unlink deferred-reap machinery is STRONGER — it blocks the free, and
# therefore reuse, until the cluster-wide last close.  Measured sess415: 20
# same-dir creates after the unlink, zero reuse while B's fd was open):
#
# ARM 1 (fd OPEN — the deferral face):
#   A creates F (fsync).  B opens F, reads, HOLDS the fd.  A unlinks F and
#   creates 20 files in the same dir.  Required: the victim ino is NOT
#   reused (deferred reap pins it) AND B's held fd still reads the ORIGINAL
#   bytes (POSIX open-unlink semantics, cluster-wide).
#
# ARM 2 (fd CLOSED — the stale-shell face, the ruling's actual target):
#   B opens/reads/CLOSES (shell + pagecache stay in B's icache, no fd, no
#   deferral).  A unlinks + creates until the ino is reused as G (new
#   di_gen, distinct content).  Required: B's fresh lookup of the old name
#   is ENOENT; B reads G's name and gets G's FULL fresh content (the iget
#   cache-hit on the same-ino dead shell must retire it — poison + re-iget
#   — never serve old bytes); G identical on A and B; zero splats.
#
# s62d on the 2/tcp rig: arm 1 FAILed — the TCP transport had no open-holder
# registry, so A freed and reused the number under B's open fd and B's
# held-fd read returned the successor file's 4096 'G' (D-TCP-NO-OPEN-
# TRACKING-PEER-HELD-FD-READS-THE-REUSED-INODES-NEW-FILE-BYTES-0977, fixed
# 0.89.0/0.89.1: open-holder marks on the authority ledger; PASS s65e).  The
# held-fd read's bytes are digested for that reason: an rc of 0 said nothing
# about whose bytes they were.
#
# the budget rule (derived): arm1 ~15s + arm2 ~15s + dmesg 6s => ~36s.  Bound 90s.
#
# Usage: tests/d512_t1_reuse.sh <label> [nodeA] [nodeB]  (default test1 test2)
set -u
LABEL=${1:?label}; A=${2:-test1}; B=${3:-test2}
cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
MNT=${MXFS_MNT:-/mnt/shared}
OUT=${D512_OUT:-tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d512t1}
mkdir -p "$OUT"
fails=0
ck() { if [ "$2" = "$3" ]; then echo "  PASS $1 ($2)"; else echo "  FAIL $1 got=$2 want=$3"; fails=$((fails+1)); fi; }
ckge() { if [ "${2:-0}" -ge "$3" ]; then echo "  PASS $1 ($2)"; else echo "  FAIL $1 got=${2:-0} want>=$3"; fails=$((fails+1)); fi; }
# rsx/measure/capture_require/capture_require_bg (tests/lib/rig.sh): every
# capture a verdict is counted from crosses the boundary in the parent shell
# first; a failed acquisition is an ABORT, never a count of zero.
. "$(dirname "$0")/lib/rig.sh"

D="$MNT/.d512t1_$LABEL"
F="$D/victim.dat"
echo "=== d512_t1_reuse label=$LABEL A=$A B=$B out=$OUT $(date -u +%FT%TZ) ==="
MARK="D512T1-$LABEL-$$"
timeout 20 $SSH "$A" "echo '$MARK' > /dev/kmsg" >/dev/null 2>&1
timeout 20 $SSH "$B" "echo '$MARK' > /dev/kmsg" >/dev/null 2>&1

# A: baseline F (16K of 'V'), fsync, report ino
timeout 25 $SSH "$A" \
  "mkdir -p '$D' && dd if=/dev/zero bs=4096 count=4 2>/dev/null | tr '\\0' 'V' > '$F' && sync -f '$F' && stat -c %i '$F'" \
  2>/dev/null | filt > "$OUT/a_setup.txt"
vino=$(tr -dc 0-9 < "$OUT/a_setup.txt")
[ -z "$vino" ] && { echo "VERDICT FAIL: A setup failed"; exit 2; }
echo "victim ino=$vino"

# B: open F, read it fully, HOLD the fd open in a background shell that
# waits for a go-file, then re-reads through the SAME fd and reports.
( timeout 60 $SSH "$B" "
    exec 7<'$F' || { echo BOPEN=fail; exit 1; }
    head -c 4096 <&7 >/dev/null 2>&1 && echo BREAD1=ok || echo BREAD1=fail
    rm -f /tmp/d512t1.go
    n=0; while [ \$n -lt 40 ] && [ ! -e /tmp/d512t1.go ]; do sleep 0.5; n=\$((n+1)); done
    # rewind not possible on <&7 redirection portably; read the NEXT bytes
    # (offset 4096..8191 of the original: 4096 'V's) and digest them — the
    # bytes, not just the read's status, are the POSIX open-unlink claim
    head -c 4096 <&7 > /tmp/d512t1.b2 2>/dev/null; rc=\$?
    echo BREAD2_RC=\$rc
    echo BREAD2_MD5=\$(md5sum < /tmp/d512t1.b2 | cut -d' ' -f1) BREAD2_LEN=\$(wc -c < /tmp/d512t1.b2)
    exec 7<&-
  " > "$OUT/b_holder.txt" 2> "$OUT/b_holder.err" ) &
BPID=$!
sleep 2
# the holder is still running (it parks on the go-file); its first-read line
# must be there by now, and an ssh that failed says so in its own stderr
capture_require_bg "$OUT/b_holder.txt" "$OUT/b_holder.err" '^BREAD1=' "B's holder open and first read" || { echo "ABORT: B's holder has not reported its first read 2 s after launch (stdout=[$(tr '\n' ' ' < "$OUT/b_holder.txt" | cut -c1-120)])"; echo "RESULT: ABORT label=$LABEL stage=capture evidence=$OUT"; kill $BPID 2>/dev/null; exit 2; }
ck "B first read ok" "$(grep -ac 'BREAD1=ok' "$OUT/b_holder.txt")" "1"

# ARM 1: A unlinks F, then creates 20 files — the ino must NOT be reused
# while B's fd pins it (deferred reap)
timeout 40 $SSH "$A" "
    rm -f '$F'
    reused=none
    i=0
    while [ \$i -lt 20 ]; do
        i=\$((i+1))
        g=\"$D/a1_\$i.dat\"
        dd if=/dev/zero bs=4096 count=4 2>/dev/null | tr '\\0' 'G' > \"\$g\"
        sync -f \"\$g\"
        gi=\$(stat -c %i \"\$g\")
        [ \"\$gi\" = \"$vino\" ] && reused=\$g
    done
    echo ARM1_REUSED=\$reused
  " 2>/dev/null | filt > "$OUT/a_arm1.txt"
ck "arm1: ino NOT reused while B's fd open" \
   "$(grep -a '^ARM1_REUSED=' "$OUT/a_arm1.txt" | cut -d= -f2)" "none"

# B: held-fd re-read must return ORIGINAL bytes (POSIX open-unlink)
timeout 20 $SSH "$B" "touch /tmp/d512t1.go" >/dev/null 2>&1
wait "$BPID"
brc=$(grep -a 'BREAD2_RC=' "$OUT/b_holder.txt" | tail -1 | cut -d= -f2)
ck "arm1: B held-fd read still succeeds (rc=0)" "${brc:-none}" "0"
vmd5=$(dd if=/dev/zero bs=4096 count=1 2>/dev/null | tr '\0' 'V' | md5sum | cut -d' ' -f1)
bmd5=$(grep -a 'BREAD2_MD5=' "$OUT/b_holder.txt" | tail -1 | grep -ao 'BREAD2_MD5=[0-9a-f]*' | cut -d= -f2)
blen=$(grep -a 'BREAD2_LEN=' "$OUT/b_holder.txt" | tail -1 | grep -ao 'BREAD2_LEN=[0-9]*' | cut -d= -f2)
ck "arm1: B held-fd read returned 4096 bytes" "${blen:-none}" "4096"
ck "arm1: B held-fd read returned the ORIGINAL bytes (4096 'V')" "$([ "${bmd5:-none}" = "$vmd5" ] && echo original || echo other:${bmd5:-none})" "original"

# ---------- ARM 2: fd CLOSED shell ----------
F2="$D/victim2.dat"
timeout 25 $SSH "$A" \
  "dd if=/dev/zero bs=4096 count=4 2>/dev/null | tr '\\0' 'W' > '$F2' && sync -f '$F2' && stat -c %i '$F2'" \
  2>/dev/null | filt > "$OUT/a_setup2.txt"
vino2=$(tr -dc 0-9 < "$OUT/a_setup2.txt")
[ -z "$vino2" ] && { echo "VERDICT FAIL: arm2 setup failed"; exit 2; }
echo "arm2 victim ino=$vino2"
# B: open, read, CLOSE — shell cached, no fd
measure "$B" 25 "$OUT/b_read2.txt" '^B2READ=' "B's read of the arm-2 victim" "md5sum '$F2' >/dev/null 2>&1 && echo B2READ=ok || echo B2READ=fail"
ck "arm2: B cached the shell (read ok)" "$(grep -ac 'B2READ=ok' "$OUT/b_read2.txt")" "1"

# A: unlink + create until reuse
timeout 40 $SSH "$A" "
    rm -f '$F2'
    got=none
    i=0
    while [ \$i -lt 20 ]; do
        i=\$((i+1))
        g=\"$D/g\$i.dat\"
        dd if=/dev/zero bs=4096 count=4 2>/dev/null | tr '\\0' 'G' > \"\$g\"
        sync -f \"\$g\"
        gi=\$(stat -c %i \"\$g\")
        if [ \"\$gi\" = \"$vino2\" ]; then got=\$g; break; fi
    done
    echo ARM2_REUSED=\$got
  " 2>/dev/null | filt > "$OUT/a_reuse2.txt"
gpath=$(grep -a '^ARM2_REUSED=' "$OUT/a_reuse2.txt" | cut -d= -f2)
ck "arm2: ino reused by A" "$([ "$gpath" != "none" ] && [ -n "$gpath" ] && echo yes || echo no)" "yes"
if [ "$gpath" = "none" ] || [ -z "$gpath" ]; then
    echo "VERDICT FAIL: arm2 exact-ino reuse did not occur in 20 creates — inconclusive"
    exit 1
fi

# B: old name ENOENT; G (same ino, new incarnation) reads FULL fresh content
timeout 25 $SSH "$B" "
    [ -e '$F2' ] && echo OLDNAME=present || echo OLDNAME=absent
    sz=\$(stat -c %s '$gpath' 2>/dev/null)
    first=\$(head -c1 '$gpath' 2>/dev/null)
    echo GSTAT=\${sz:-none}:\${first:-none}
  " 2>/dev/null | filt > "$OUT/b_fresh.txt"
ck "arm2: old name absent on B" "$(grep -a '^OLDNAME=' "$OUT/b_fresh.txt" | cut -d= -f2)" "absent"
ck "arm2: G reads fresh on B (16384:G)" "$(grep -a '^GSTAT=' "$OUT/b_fresh.txt" | cut -d= -f2)" "16384:G"

# G identical on A and B
value_now_into ga "$A" 20 "$OUT/rv_ga_1.txt" '^[0-9a-f]{32}$' "ga on $A" "md5sum '$gpath' | cut -d' ' -f1"
value_now_into gb "$B" 20 "$OUT/rv_gb_1.txt" '^[0-9a-f]{32}$' "gb on $B" "md5sum '$gpath' | cut -d' ' -f1"
ck "arm2: G content identical A/B" "$([ -n "$ga" ] && [ "$ga" = "$gb" ] && echo same || echo differ)" "same"

# splats on both nodes (poison markers on B are expected only if B's shell
# survived long enough to cache-hit — dontcache may retire it silently;
# do not require them, only forbid splats and stale bytes)
measure "$B" 25 "$OUT/b_dmesg.txt" '^DMESG_END$' "the kernel log on $B from the lap marker" "dmesg | sed -n \"/$MARK/,\\\$p\"; echo DMESG_END"
measure "$A" 25 "$OUT/a_dmesg.txt" '^DMESG_END$' "the kernel log on $A from the lap marker" "dmesg | sed -n \"/$MARK/,\\\$p\"; echo DMESG_END"
splb=$(grep -aEc 'BUG:|Oops|WARNING:.*lockdep' "$OUT/b_dmesg.txt")
spla=$(grep -aEc 'BUG:|Oops|WARNING:.*lockdep' "$OUT/a_dmesg.txt")
ck "zero splats on B" "$splb" "0"
ck "zero splats on A" "$spla" "0"

timeout 25 $SSH "$A" "rm -rf '$D'" >/dev/null 2>&1
if [ "$fails" -eq 0 ]; then echo "VERDICT PASS: T1 both arms (deferral + stale-shell reuse)"; exit 0; fi
echo "VERDICT FAIL: $fails assertion(s)"; exit 1
