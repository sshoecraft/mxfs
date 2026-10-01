#!/bin/bash
# quiesce_remount_access.sh — does a record a clean full-cluster unmount left
# in the TCP authority ledger hang a later request?
#
# The board's chk_clean row unmounts every node at once, audits cold, and
# mounts every node again.  Its ledger census (tools/tauth_page_auth.py
# --holders) measured 1 to 145 records still naming an exclusive holder after
# every node had unmounted cleanly (12 laps on 0.90.18), every one of them an
# inode EX record on a page left PREPARED.  Nothing in that row touches the
# inodes those records name after the remount, so the row cannot say what a
# request for one of them meets.  This harness does:
#
#   1  workload   every node creates FILES files of its own and reads half of
#                 its neighbour's, so each node leaves with cached exclusive
#                 grants on some inodes and shared ones on others
#   2  quiesce    every node unmounts at one instant (clock rendezvous)
#   3  census     the platter is read cold: the offline checker, then every
#                 ledger record that still names a holder
#   4  remount    every node mounts at one instant
#   5  access     each node in turn stats every file, touches every file
#                 (an exclusive request per inode) and creates FILES new ones
#   6  quiesce    every node unmounts again, and the census is read again:
#                 a record of the first census that is still there outlived a
#                 whole mounted era
#   7  remount    the rig is left mounted
#
# Verdict: every unmount and mount returns inside its bound, every access
# step returns 0 inside its bound with the expected count, no node logs a
# lock timeout, a refused lock or a hung task from the remount on, no page
# import installs a holder with an unknown owner or one no mounted node
# answers for, and no record of the first census outlives a request for its
# own inode.  A record is retired when its page is next imported, so the ones
# on inodes nothing asked for are still there at the second census: they are
# counted and reported.  The census counts themselves are reported, not
# judged: a release that never reached the platter is its own defect, and
# what this harness judges is what such a record does next.
#
# Bounds.  A lone unmount measures about 3 s and a four-way remount about 5 s
# on this rig; a mount behind a holder nobody can ask measured 17 to 87 s.
# MOUNT_BOUND (10 s) is the mount wall that still counts as healthy and
# UMOUNT_BOUND (10 s) the unmount wall; the hard stops (100 s for a mount, as
# chk_clean; 60 s for an unmount) only end the wait.  ACCESS_BOUND (30 s) is
# per step and per node: below the lock layer's own 60-retry budget, so a
# request parked behind a holder is seen here as a step that did not return.
#
# The control arm.  SETTLED_RETIRE=0 switches off, on every node, the
# retirement of records whose holder has left for good (module parameter
# tauth_settled_retire), so the same build imports them as live holders the
# way every build before 0.90.21 did.  That arm is EXPECTED to fail at step 5;
# it then switches the retirement back on and repeats the stat sweep, which
# shows the release tick ending the same wait on a mounted cluster.  The arm
# prints a CONTROL line; its exit status is non-zero whenever step 5 failed.
# The parameter is set explicitly in both arms and left at 1 on exit.
#
# The tenant arms.  A shared holder bit names a heartbeat slot, and a page
# imported before the monitor's tracking has sampled that slot's tenant used
# to install the bit with no owner (1 lap in 15 on 0.90.21, natural timing).
# INJECT_UNRESOLVABLE=N arms, on every node before the first remount, the
# module's own test injection that answers the next N slot lookups of a page
# import as unresolvable (dl_inject_import_unresolvable), which is that timing
# made to happen at every import.  TENANT_ATTRIBUTE=0 switches off the
# attribution from the heartbeat table (tauth_tenant_attribute), so the same
# build installs such a bit with no owner the way every build before 0.90.22
# did: that arm is EXPECTED to fail the unknown-owner check and nothing else.
# Every arm prints a TENANT line with what the imports did; a lap whose line
# reads injected=0 met no shared bit at an import and verified nothing about
# this path.  Both parameters are set explicitly and left at 1 and 0 on exit.
#
# budget: workload 60 + 2 x (unmount 60 + census 40 + mount 100) + access
# 4 x 3 x 30 + captures 60 => 880 s worst case; a healthy lap measures about
# 100 s.  The control arm adds 4 x 30 for its second sweep.
# Usage: tests/quiesce_remount_access.sh <label> [node ...]   (default test1..test4)
# Env:   FILES (default 200), MXFS_MNT, MXFS_DEV, MXFS_CONFIG (default 2/net/mesh/direct),
#        ACCESS_BOUND, MOUNT_BOUND, UMOUNT_BOUND, SETTLED_RETIRE (default 1),
#        TENANT_ATTRIBUTE (default 1), INJECT_UNRESOLVABLE (default 0),
#        UNHELD_ANSWER (default 1; 0 switches off the lock layer's own answer
#        to a notification for a grant the node does not hold, module
#        parameter tauth_unheld_answer: the arm in which a named residue bit
#        stands until a budget ends the wait behind it)
set -u
LABEL=${1:?label}
shift
NODES=("$@")
[ ${#NODES[@]} -ge 1 ] || NODES=(test1 test2 test3 test4)
cd "$(dirname "$0")/.." || exit 2
MNT=${MXFS_MNT:-/mnt/shared}
export MXFS_CONFIG=${MXFS_CONFIG:-2/net/mesh/direct}
TRANSPORT=$(python3 tools/configuration.py get "$MXFS_CONFIG" transport) || exit 2
FILES=${FILES:-200}
ACCESS_BOUND=${ACCESS_BOUND:-30}
MOUNT_BOUND=${MOUNT_BOUND:-10}
UMOUNT_BOUND=${UMOUNT_BOUND:-10}
SETTLED_RETIRE=${SETTLED_RETIRE:-1}
case $SETTLED_RETIRE in 0|1) ;; *) echo "SETTLED_RETIRE must be 0 or 1"; exit 2 ;; esac
TENANT_ATTRIBUTE=${TENANT_ATTRIBUTE:-1}
case $TENANT_ATTRIBUTE in 0|1) ;; *) echo "TENANT_ATTRIBUTE must be 0 or 1"; exit 2 ;; esac
INJECT_UNRESOLVABLE=${INJECT_UNRESOLVABLE:-0}
UNHELD_ANSWER=${UNHELD_ANSWER:-1}
case $UNHELD_ANSWER in 0|1) ;; *) echo "UNHELD_ANSWER must be 0 or 1"; exit 2 ;; esac
case $INJECT_UNRESOLVABLE in ''|*[!0-9]*) echo "INJECT_UNRESOLVABLE must be a count"; exit 2 ;; esac
RUNID=$(date -u +%Y%m%dT%H%M%SZ)
OUT=tests/evidence/quiesce_remount_access/${LABEL}_$RUNID
mkdir -p "$OUT"
fails=0
. "$(dirname "$0")/lib/rig.sh"
D=$MNT/qra_$LABEL
NN=${#NODES[@]}
EXPECT_FILES=$(( NN * FILES + NN * (FILES / 4) ))

note() { echo "$(date -u +%T) $*"; }
field() { grep -ao "$2=[^ ]*" "$1" | tail -1 | cut -d= -f2; }

# every node runs <cmd> at once; each capture is its own file and crosses the
# boundary afterwards in the parent shell
fan() { # <tag> <timeout> <shape> <cmd with NODE_INDEX and RENDEZVOUS substituted by the caller>
    local tag=$1 t=$2 shape=$3 cmd=$4 i n pids=()
    for i in "${!NODES[@]}"; do
        n=${NODES[$i]}
        rsx "$t" "$n" "I=$((i + 1)); $cmd" > "$OUT/${tag}_$n.txt" &
        pids+=($!)
    done
    wait "${pids[@]}"
    for n in "${NODES[@]}"; do
        capture_require "$OUT/${tag}_$n.txt" "$shape" "$tag on $n"
    done
}

# the instant every node acts at: the host's clock plus 4 s, waited for on
# each node's own clock (the skew is measured and printed at the start)
rendezvous() { echo $(( $(date +%s) + 4 )); }
WAIT_T='while [ $(date +%s) -lt $T ]; do sleep 0.05; done'

kmark() { # <text>: a line in every node's kernel log
    local n
    for n in "${NODES[@]}"; do
        rs 15 "$n" "echo 'QRA-MARK $LABEL $1' > /dev/kmsg" &
    done
    wait
}

quiesce() { # <tag>
    local tag=$1 T n ms
    T=$(rendezvous)
    kmark "$tag"
    fan "$tag" 90 '^(UMOUNT_DONE|UMOUNT_STUCK|NOT_MOUNTED_BEFORE)' \
        "T=$T; grep -q ' $MNT mxfs ' /proc/mounts || { echo NOT_MOUNTED_BEFORE; exit 0; }; sync; $WAIT_T; u0=\$(date +%s%3N); ( umount $MNT 2>/dev/null; echo UMOUNT_RC=\$? UMOUNT_MS=\$(( \$(date +%s%3N) - u0 )) > /root/qra_umount.txt ) > /dev/null 2>&1 < /dev/null & up=\$!; for t in \$(seq 1 60); do kill -0 \$up 2>/dev/null || break; sleep 1; done; if kill -0 \$up 2>/dev/null || grep -q ' $MNT mxfs ' /proc/mounts; then echo UMOUNT_STUCK after=\${t}s; else wait \$up; cat /root/qra_umount.txt; echo UMOUNT_DONE; fi"
    for n in "${NODES[@]}"; do
        ck "$tag: $n unmounted" "$(grep -ac '^UMOUNT_DONE' "$OUT/${tag}_$n.txt")" 1
        ms=$(field "$OUT/${tag}_$n.txt" UMOUNT_MS)
        ckge "$tag: $n's unmount returned inside ${UMOUNT_BOUND}s (umount_ms=${ms:-none})" "$(( UMOUNT_BOUND * 1000 - ${ms:-999999} ))" 0
    done
}

remount() { # <tag>
    local tag=$1 T n ms
    T=$(rendezvous)
    kmark "$tag"
    fan "$tag" 130 '^(MOUNTED|NOT_MOUNTED)$' \
        "T=$T; $WAIT_T; r0=\$(date +%s%3N); timeout 100 mount -t mxfs $DEV $MNT; echo MOUNT_RC=\$? MOUNT_MS=\$(( \$(date +%s%3N) - r0 )); grep -q ' $MNT mxfs ' /proc/mounts && echo MOUNTED || echo NOT_MOUNTED"
    for n in "${NODES[@]}"; do
        ck "$tag: $n mounted (rc=$(field "$OUT/${tag}_$n.txt" MOUNT_RC))" "$(grep -ac '^MOUNTED$' "$OUT/${tag}_$n.txt")" 1
        ms=$(field "$OUT/${tag}_$n.txt" MOUNT_MS)
        ckge "$tag: $n's mount returned inside ${MOUNT_BOUND}s (mount_ms=${ms:-none})" "$(( MOUNT_BOUND * 1000 - ${ms:-999999} ))" 0
    done
}

census() { # <tag>: cold, on the first node
    local tag=$1 n=${NODES[0]} tbase
    measure "$n" 60 "$OUT/${tag}_chk.txt" '^CHK_RC=[0-9]+ ms=[0-9]+$' "the offline checker on $n ($tag)" \
        "s=\$(date +%s%N); /src/mxfs/tools/chk_mxfs -v $DEV 2>&1; rc=\$?; e=\$(date +%s%N); echo CHK_RC=\$rc ms=\$(( (e-s)/1000000 ))"
    ck "$tag: the cold audit found the volume clean (rc)" "$(mxfs_chk_rc "$OUT/${tag}_chk.txt")" 0
    tbase=$(sed -n 's/^.*tauth_offset=\([0-9][0-9]*\) .*/\1/p' "$OUT/${tag}_chk.txt" | head -1)
    case $tbase in ''|*[!0-9]*|0)
        echo "ABORT: the checker on $n printed no tauth_offset, so the ledger region cannot be located"
        echo "RESULT: ABORT label=$LABEL stage=census evidence=$OUT"; exit 2 ;;
    esac
    measure "$n" 40 "$OUT/${tag}.txt" '^HOLDERS records=[0-9]+ ' "the ledger census on $n ($tag)" \
        "python3 /src/mxfs/tools/tauth_page_auth.py $DEV $tbase --holders --limit 100000"
    # one line per record, the identity a later census can be compared on:
    # page type ag ino ex(node/inc) slot mode shared_mode slots
    awk '$1 == "holder" {
            r = ""
            for (i = 2; i <= NF; i++)
                if ($i ~ /^(page|type|ag|ino|ex|slot|mode|shared_mode|slots)=/) {
                    v = $i; sub(/^[a-z_]*=/, "", v); r = r (r == "" ? "" : " ") v
                }
            print r
        }' "$OUT/${tag}.txt" | sort > "$OUT/${tag}_records.txt"
    note "$tag: $(grep -a '^HOLDERS ' "$OUT/${tag}.txt" | tail -1)"
}

klog() { # <tag>: every node's kernel ring, gzipped, for tools/kernlog_digest.py
    local tag=$1 n
    mkdir -p "$OUT/$tag"
    for n in "${NODES[@]}"; do
        ( timeout 60 "$SSH" "$n" "dmesg -T" < /dev/null 2>/dev/null | filt | gzip -1 > "$OUT/$tag/kernlog_$n.gz" ) &
    done
    wait
    for n in "${NODES[@]}"; do
        if [ "$(zcat "$OUT/$tag/kernlog_$n.gz" 2>/dev/null | grep -ac "QRA-MARK $LABEL ")" -lt 1 ]; then
            echo "ABORT: the kernel log pulled from $n ($tag) carries none of this lap's marks, so nothing can be counted in it"
            echo "RESULT: ABORT label=$LABEL stage=klog evidence=$OUT"; exit 2
        fi
    done
}

# count <pattern> in <node>'s pulled log from the mark <text> on
kcount() { # <tag> <node> <mark text> <pattern>
    zcat "$OUT/$1/kernlog_$2.gz" | sed -n "/QRA-MARK $LABEL $3/,\$p" | grep -ac -- "$4"
}
# the same, leaving out the lines that also match <except>
kcount_except() { # <tag> <node> <mark text> <pattern> <except>
    zcat "$OUT/$1/kernlog_$2.gz" | sed -n "/QRA-MARK $LABEL $3/,\$p" | grep -a -- "$4" | grep -avc -- "$5"
}
# A lock request the lock layer refuses so that two sides cannot deadlock
# (rc=-35: an upgrade behind another shared holder, which the caller answers
# by giving up its own grant and asking again) and a fallible request that
# declines (rc=-11) are the design working: the module logs both at debug
# level and the caller retries.  They are counted and printed, not judged;
# every other code on that line is a request that failed.
RETRIED='rc=-\(35\|11\)\b'

# the settled-owner retirement on every node, read back
knob() { # <0|1>
    local v=$1 n
    for n in "${NODES[@]}"; do
        rsx 15 "$n" "echo $v > /sys/module/mxfs/parameters/tauth_settled_retire; echo KNOB=\$(cat /sys/module/mxfs/parameters/tauth_settled_retire)" > "$OUT/knob${v}_$n.txt" &
    done
    wait
    for n in "${NODES[@]}"; do
        capture_require "$OUT/knob${v}_$n.txt" '^KNOB=[01]$' "tauth_settled_retire on $n"
        ck "knob: $n reads tauth_settled_retire=$v" "$(field "$OUT/knob${v}_$n.txt" KNOB)" "$v"
    done
}
# one module parameter on every node, read back
param() { # <name> <value>
    local p=$1 v=$2 n
    for n in "${NODES[@]}"; do
        rsx 15 "$n" "echo $v > /sys/module/mxfs/parameters/$p; echo PARAM=\$(cat /sys/module/mxfs/parameters/$p)" > "$OUT/param_${p}_${v}_$n.txt" &
    done
    wait
    for n in "${NODES[@]}"; do
        capture_require "$OUT/param_${p}_${v}_$n.txt" '^PARAM=[0-9]+$' "$p on $n"
        ck "param: $n reads $p=$v" "$(field "$OUT/param_${p}_${v}_$n.txt" PARAM)" "$v"
    done
}
knob_restore() {
    local n
    for n in "${NODES[@]}"; do
        rs 15 "$n" "echo 1 > /sys/module/mxfs/parameters/tauth_settled_retire; echo 1 > /sys/module/mxfs/parameters/tauth_tenant_attribute; echo 1 > /sys/module/mxfs/parameters/tauth_unheld_answer; echo 0 > /sys/module/mxfs/parameters/dl_inject_import_unresolvable" > /dev/null &
    done
    wait
}
trap knob_restore EXIT

for n in "${NODES[@]}"; do
    pre=$(rs 15 "$n" "grep -q ' $MNT mxfs ' /proc/mounts && echo M")
    if [ "$pre" != M ]; then
        echo "INFRA: precondition not met ($n has no mxfs mount on $MNT) — prep first"; exit 2
    fi
done
mxfs_dev_resolve "${NODES[0]}"
DEV=$MXFS_DEV_RESOLVED
echo "=== quiesce_remount_access label=$LABEL nodes=${NODES[*]} dev=$DEV files=$FILES settled_retire=$SETTLED_RETIRE tenant_attribute=$TENANT_ATTRIBUTE inject=$INJECT_UNRESOLVABLE sv=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p') out=$OUT $(date -u +%FT%TZ) ==="
fan loaded 20 '^LOADED_SV=[0-9A-F]+$' "echo LOADED_SV=\$(cat /sys/module/mxfs/srcversion)"
for n in "${NODES[@]}"; do
    ck "build: $n runs this tree's module" "$(field "$OUT/loaded_$n.txt" LOADED_SV)" "$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')"
done
knob "$SETTLED_RETIRE"
param tauth_tenant_attribute "$TENANT_ATTRIBUTE"
param tauth_unheld_answer "$UNHELD_ANSWER"
param dl_inject_import_unresolvable 0
if [ "$fails" != 0 ]; then
    echo "INFRA: the fleet does not run this tree's module, or the parameter could not be set — deploy first"
    echo "RESULT: ABORT label=$LABEL stage=build evidence=$OUT"; exit 2
fi
h0=$(date +%s%3N)
fan clock 20 '^CLOCK_MS=[0-9]+$' "echo CLOCK_MS=\$(date +%s%3N)"
h1=$(date +%s%3N)
for n in "${NODES[@]}"; do
    note "clock: $n is $(( $(field "$OUT/clock_$n.txt" CLOCK_MS) - (h0 + h1) / 2 )) ms from this host (read took $(( h1 - h0 )) ms)"
done
# how many cluster buffers the fresh-grant walk has kept so far on each node;
# read again after the access sweeps (the module stays loaded across the
# remount, so the difference is this lap's)
fan walk0 20 '^WALK_KEPT=[0-9]+$' "echo WALK_KEPT=\$(cat /sys/module/mxfs/parameters/walk_kept_queued_n)"

note "--- 1 workload: $FILES files per node, half of the neighbour's read back"
kmark workload
fan workload 60 '^WORKLOAD_(OK|FAIL)' \
    "mkdir -p $D/own_\$I $D/shared || { echo WORKLOAD_FAIL mkdir; exit 0; }; w0=\$(date +%s%3N); for k in \$(seq 1 $FILES); do head -c 4096 /dev/urandom > $D/own_\$I/f\$k || { echo WORKLOAD_FAIL write f\$k; exit 0; }; done; for k in \$(seq 1 $(( FILES / 4 ))); do echo \$I > $D/shared/n\${I}_\$k || { echo WORKLOAD_FAIL shared \$k; exit 0; }; done; sync -f $D; echo WORKLOAD_OK ms=\$(( \$(date +%s%3N) - w0 ))"
for n in "${NODES[@]}"; do
    ck "1: $n's creates returned ($(grep -a '^WORKLOAD_' "$OUT/workload_$n.txt" | tail -1))" "$(grep -ac '^WORKLOAD_OK' "$OUT/workload_$n.txt")" 1
done
fan crossread 60 '^CROSSREAD_(OK|FAIL)' \
    "J=\$(( I % $NN + 1 )); c0=\$(date +%s%3N); for k in \$(seq 1 2 $FILES); do cat $D/own_\$J/f\$k > /dev/null || { echo CROSSREAD_FAIL f\$k; exit 0; }; done; echo CROSSREAD_OK ms=\$(( \$(date +%s%3N) - c0 ))"
for n in "${NODES[@]}"; do
    ck "1: $n read its neighbour's files ($(grep -a '^CROSSREAD_' "$OUT/crossread_$n.txt" | tail -1))" "$(grep -ac '^CROSSREAD_OK' "$OUT/crossread_$n.txt")" 1
done

note "--- 2 quiesce: every node unmounts at one instant"
quiesce quiesce1
if [ "$fails" != 0 ]; then
    klog stall
    echo "=== quiesce_remount_access $LABEL: fails=$fails (stopped: the first quiesce did not complete) out=$OUT $(date -u +%FT%TZ) ==="
    exit 1
fi

note "--- 3 census: the platter, cold"
census census1
C1=$(grep -ac . "$OUT/census1_records.txt")

note "--- 4 remount: every node mounts at one instant"
if [ "$INJECT_UNRESOLVABLE" -gt 0 ]; then
    # armed while nothing is mounted, so no import consumes it before the
    # read-back
    param dl_inject_import_unresolvable "$INJECT_UNRESOLVABLE"
fi
R1_AT=$(date -u +%Y-%m-%dT%H:%M:%S)
remount remount1
mounted=0
for n in "${NODES[@]}"; do
    [ "$(grep -ac '^MOUNTED$' "$OUT/remount1_$n.txt")" = 1 ] && mounted=$((mounted + 1))
done

if [ "$mounted" = "$NN" ]; then
    note "--- 5 access: stat, touch and create, one node at a time"
    kmark access
    for i in "${!NODES[@]}"; do
        n=${NODES[$i]}
        I=$((i + 1))
        rsx $(( ACCESS_BOUND + 15 )) "$n" "a0=\$(date +%s%3N); timeout $ACCESS_BOUND find $D -type f -exec stat -c 'INO %i %n' {} + ; r=\$?; echo; echo STAT_RC=\$r STAT_MS=\$(( \$(date +%s%3N) - a0 ))" > "$OUT/access_stat_$n.txt"
        capture_require "$OUT/access_stat_$n.txt" '^STAT_RC=[0-9]+ ' "the stat sweep on $n"
        ck "5: $n's stat sweep returned 0 inside ${ACCESS_BOUND}s (ms=$(field "$OUT/access_stat_$n.txt" STAT_MS))" "$(field "$OUT/access_stat_$n.txt" STAT_RC)" 0
        # every node before this one has already added its create burst
        ck "5: $n's stat sweep saw every file" "$(grep -ac '^INO ' "$OUT/access_stat_$n.txt")" "$(( EXPECT_FILES + i * FILES ))"
        rsx $(( ACCESS_BOUND + 15 )) "$n" "a0=\$(date +%s%3N); timeout $ACCESS_BOUND find $D -type f -exec touch -c {} + ; echo TOUCH_RC=\$? TOUCH_MS=\$(( \$(date +%s%3N) - a0 ))" > "$OUT/access_touch_$n.txt"
        capture_require "$OUT/access_touch_$n.txt" '^TOUCH_RC=[0-9]+ ' "the touch sweep on $n"
        ck "5: $n's touch sweep returned 0 inside ${ACCESS_BOUND}s (ms=$(field "$OUT/access_touch_$n.txt" TOUCH_MS))" "$(field "$OUT/access_touch_$n.txt" TOUCH_RC)" 0
        rsx $(( ACCESS_BOUND + 15 )) "$n" "a0=\$(date +%s%3N); timeout $ACCESS_BOUND sh -c 'mkdir -p $D/new_$I && for k in \$(seq 1 $FILES); do echo $I > $D/new_$I/g\$k || exit 1; done'; echo CREATE_RC=\$? CREATE_MS=\$(( \$(date +%s%3N) - a0 ))" > "$OUT/access_create_$n.txt"
        capture_require "$OUT/access_create_$n.txt" '^CREATE_RC=[0-9]+ ' "the create burst on $n"
        ck "5: $n's create burst returned 0 inside ${ACCESS_BOUND}s (ms=$(field "$OUT/access_create_$n.txt" CREATE_MS))" "$(field "$OUT/access_create_$n.txt" CREATE_RC)" 0
    done
    # which of the first census's inodes the sweeps reached by name
    if [ "$C1" -gt 0 ]; then
        awk '{print $4}' "$OUT/census1_records.txt" | sort -u > "$OUT/census1_inos.txt"
        grep -a '^INO ' "$OUT/access_stat_${NODES[0]}.txt" | awk '{print $2}' | sort -u > "$OUT/swept_inos.txt"
        note "5: $(comm -12 "$OUT/census1_inos.txt" "$OUT/swept_inos.txt" | grep -c .) of the $(grep -c . "$OUT/census1_inos.txt") inodes the first census named are files the sweeps reached"
    fi
else
    note "--- 5 access: skipped, $mounted of $NN nodes mounted"
fi

klog era1
python3 tools/kernlog_digest.py "$OUT/era1" imports --since "$R1_AT" > "$OUT/era1_imports.txt" 2>&1
grep -a '^IMPORTS ' "$OUT/era1_imports.txt" | sed "s/^/$(date -u +%T) since the remount: /"
access_fails=$fails
for n in "${NODES[@]}"; do
    ck "4-5: zero holders imported for an owner no mounted node answers for, on $n" "$(grep -a "^IMPORTS $n " "$OUT/era1_imports.txt" | grep -ao 'departed=[0-9]*' | cut -d= -f2)" 0
    ck "4-5: zero holders imported with an unknown owner on $n" "$(kcount era1 "$n" remount1 'P-TAUTH-IMPORT-ACTIVE .*owner=4294967295 ')" 0
    ck "4-5: zero P-LKTIMEOUT-REMOTE on $n" "$(kcount era1 "$n" remount1 'P-LKTIMEOUT-REMOTE')" 0
    ck "4-5: zero P-LKTIMEOUT-HOLDER on $n" "$(kcount era1 "$n" remount1 'P-LKTIMEOUT-HOLDER')" 0
    ck "4-5: zero 'lock request failed after' on $n" "$(kcount era1 "$n" remount1 'lock request failed after')" 0
    ck "4-5: zero 'DLM inode lock failed' on $n (refusals the caller retried: $(kcount era1 "$n" remount1 "DLM inode lock failed.*$RETRIED"))" "$(kcount_except era1 "$n" remount1 'DLM inode lock failed' "$RETRIED")" 0
    ck "4-5: zero hung-task reports on $n" "$(kcount era1 "$n" remount1 'blocked for more than')" 0
    ck "4-5: zero filesystem shutdowns on $n" "$(kcount era1 "$n" remount1 'hutting down filesystem')" 0
    # An inode item left flushing behind a cluster buffer whose write was
    # cancelled costs a release drain 5 s (its wedge reports, then its
    # rescue) and an unmount its whole wait; a lap that met one failed even
    # when every access step came back inside its bound.
    ck "4-5: zero release drains wedged on $n (P113-DRAIN-WEDGE)" "$(kcount era1 "$n" remount1 'P113-DRAIN-WEDGE')" 0
    ck "4-5: zero release drains rescued on $n (P136-DRAIN-RESCUE)" "$(kcount era1 "$n" remount1 'P136-DRAIN-RESCUE')" 0
    ck "4-5: zero stuck-item reports on $n (P128-AILSTUCK)" "$(kcount era1 "$n" remount1 'P128-AILSTUCK')" 0
    ck "4-5: zero stales of a buffer queued for write with items attached on $n (kept by the walk instead: $(kcount era1 "$n" remount1 'P91-WALK-PROTECT'))" "$(kcount era1 "$n" remount1 'P-STALE-WITH-ITEMS .*delwri=1')" 0
done

retired=0
for n in "${NODES[@]}"; do
    retired=$(( retired + $(kcount era1 "$n" remount1 'P-TAUTH-SETTLED-RETIRE ') ))
done
note "4-5: $retired holders that had left for good were retired instead of imported (census1=$C1)"

# what the imports of shared bits did, summed over the nodes
t_inj=0; t_named=0; t_unk=0; t_tick=0; t_req=0; t_ans=0; t_park=0
for n in "${NODES[@]}"; do
    t_inj=$(( t_inj + $(kcount era1 "$n" remount1 'P-TAUTH-IMPORT-INJECT-UNRESOLVABLE ') ))
    t_named=$(( t_named + $(kcount era1 "$n" remount1 'P-TAUTH-IMPORT-TENANT ') ))
    t_unk=$(( t_unk + $(kcount era1 "$n" remount1 'P-TAUTH-IMPORT-ACTIVE .*owner=4294967295 ') ))
    t_tick=$(( t_tick + $(kcount era1 "$n" remount1 'P-TAUTH-IMPORT-RESOLVED-ONTICK ') ))
    t_req=$(( t_req + $(kcount era1 "$n" remount1 'P-TAUTH-IMPORT-RESOLVED-ONREQUEST ') ))
    t_ans=$(( t_ans + $(kcount era1 "$n" remount1 'P-BAST-ANSWER-UNHELD ') ))
    t_park=$(( t_park + $(kcount era1 "$n" remount1 'P-BAST-PARKED ') ))
done
echo "TENANT label=$LABEL tenant_attribute=$TENANT_ATTRIBUTE inject=$INJECT_UNRESOLVABLE injected=$t_inj named_at_import=$t_named unknown_imports=$t_unk named_by_tick=$t_tick named_on_request=$t_req unheld_answer=$UNHELD_ANSWER answered=$t_ans parked=$t_park access_fails=$access_fails"
# A lap with no inode item stranded behind a cancelled write verifies the
# walk's rule only if the walk met a buffer queued for write in it: the
# counter says whether it did.  Reported, not judged; a lap that reads 0 met
# none and says nothing about the rule.
fan walk1 20 '^WALK_KEPT=[0-9]+$' "echo WALK_KEPT=\$(cat /sys/module/mxfs/parameters/walk_kept_queued_n)"
w_kept=0; w_nodes=""
for n in "${NODES[@]}"; do
    w_d=$(( $(field "$OUT/walk1_$n.txt" WALK_KEPT) - $(field "$OUT/walk0_$n.txt" WALK_KEPT) ))
    w_kept=$(( w_kept + w_d )); w_nodes="$w_nodes $n:$w_d"
done
echo "WALK label=$LABEL kept_queued=$w_kept by_node=${w_nodes# }"
if [ "$INJECT_UNRESOLVABLE" -gt 0 ]; then
    param dl_inject_import_unresolvable 0
fi

if [ "$SETTLED_RETIRE" = 0 ] && [ "$mounted" = "$NN" ]; then
    note "--- 5b control: the retirement is switched on under the mounted cluster"
    before=$fails
    kmark control-on
    knob 1
    sleep 5     # the release tick judges once a second; the workers run every 500 ms
    for n in "${NODES[@]}"; do
        rsx $(( ACCESS_BOUND + 15 )) "$n" "a0=\$(date +%s%3N); timeout $ACCESS_BOUND find $D -type f -exec stat -c 'INO %i %n' {} + ; r=\$?; echo; echo STAT_RC=\$r STAT_MS=\$(( \$(date +%s%3N) - a0 ))" > "$OUT/control_stat_$n.txt"
        capture_require "$OUT/control_stat_$n.txt" '^STAT_RC=[0-9]+ ' "the control arm's second stat sweep on $n"
        ck "5b: $n's stat sweep returned 0 inside ${ACCESS_BOUND}s once switched on (ms=$(field "$OUT/control_stat_$n.txt" STAT_MS))" "$(field "$OUT/control_stat_$n.txt" STAT_RC)" 0
    done
    klog era1b
    dropped=0
    for n in "${NODES[@]}"; do
        dropped=$(( dropped + $(kcount era1b "$n" control-on 'P-TAUTH-SETTLED-DROP ') ))
    done
    echo "CONTROL label=$LABEL reproduced=$access_fails second_sweep_fails=$(( fails - before )) tick_dropped=$dropped census1=$C1"
fi

if [ "$mounted" = "$NN" ] && [ "$fails" = 0 ]; then
    note "--- 6 quiesce and census again"
    quiesce quiesce2
    if [ "$fails" = 0 ]; then
        census census2
        # A record is retired when its page is next imported, and a page is
        # imported when something asks for a resource on it.  What is judged
        # is the record that outlived a request for its own inode; the ones
        # nobody asked for are counted and reported.
        comm -12 "$OUT/census1_records.txt" "$OUT/census2_records.txt" > "$OUT/survivors.txt"
        survivors=$(grep -c . "$OUT/survivors.txt")
        touched=0
        if [ "$C1" -gt 0 ]; then
            touched=$(awk '{print $4}' "$OUT/survivors.txt" | sort -u | comm -12 - "$OUT/swept_inos.txt" | grep -c .)
        fi
        ck "6: zero records of the first census outlived a request for their own inode (census1=$C1 census2=$(grep -ac . "$OUT/census2_records.txt") reached=$(comm -12 "$OUT/census1_inos.txt" "$OUT/swept_inos.txt" 2>/dev/null | grep -c .))" "$touched" 0
        note "6: $survivors records of the first census are still on the platter, on inodes nothing asked for in this era"
        note "--- 7 remount: the rig is left mounted"
        remount remount2
    else
        # an unmount that did not return is the finding: keep every node's
        # log of it (the unmount's own stuck-item reports are in there)
        klog stall2
        note "6: the second quiesce did not complete; logs in $OUT/stall2"
    fi
else
    note "--- 6/7 skipped: the lap already failed, the rig is left as it is for the evidence"
fi

echo "=== quiesce_remount_access $LABEL: fails=$fails census1=$C1 out=$OUT $(date -u +%FT%TZ) ==="
[ "$fails" = 0 ]
