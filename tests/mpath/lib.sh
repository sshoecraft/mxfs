#!/bin/bash
# tests/mpath/lib.sh — what every path-fault row of docs/mpath-verification.md
# shares: the starting-state gate, the load on every node, the judgement of a
# fault window, and the end-of-row audit.  Sourced by the host-coordinated rows
# in this directory after they set:
#   ROW   the row's name (its evidence directory and RESULT line carry it)
# and with the environment run.sh hands a host row (MXFS_NODES, MXFS_NODE_LIST,
# MXFS_RUN_ID, MXFS_MNT).  A row then reads as its fault schedule and nothing
# else.
#
# Every measurement that feeds a verdict is taken with rsx and validated with
# capture_require (tests/lib/rig.sh): a node that did not answer aborts the
# row, it does not read as zero.  What is asked of every node is asked of all
# of them at once, so a row's wall does not grow with the node count.
N=${MXFS_NODES:?}
RUN=${MXFS_RUN_ID:-local$(date -u +%H%M%S)}
MNT=${MXFS_MNT:-/mnt/shared}
cd /src/mxfs || { echo "RESULT: FAIL src=test | measured=setup | reason=not-on-clyde"; exit 1; }
NODES_CSV=${MXFS_NODE_LIST:-$(seq -f 'test%g' 1 "$N" | paste -sd,)}
NODES=${NODES_CSV//,/ }
V=${NODES_CSV##*,}
W=${NODES_CSV%%,*}
OUT=tests/evidence/board_${RUN}_$ROW
LABEL="${ROW}_$RUN"
mkdir -p "$OUT"
# shellcheck source=tests/lib/rig.sh
. tests/lib/rig.sh
. tools/mxfs_lab.sh
BOUND_MS=$(( $(tools/mpath_settings.sh stall-bound) * 1000 ))
DEV=${MXFS_DEV:-/dev/mapper/mpatha}
VIRSH="virsh -c qemu:///system"
# A row in which a node dies: what the others may wait for it.  Peers declare
# a silent node dead after the death window (62 s) and then fence it and
# replay its journal (measured 15-25 s); an operation that needs a lock the
# dead node held waits for all of that.
DEATH_BOUND_MS=120000
# The stop file is LOCAL to each node: a file made on the shared tree reaches a
# node's NFS client only when its cached negative lookup expires, up to a
# minute later, and the load ran on past the row that had stopped it.
STOP=/run/mxfs_pathload.$RUN.$ROW.stop
# LOAD_NODES: the nodes that run the load.  Every node, unless the row takes
# one out of the cluster and says so before pf_load_start.
LOAD_NODES=$NODES
stop_loads() { local n; for n in ${1:-$LOAD_NODES}; do ( rs 15 "$n" "touch $STOP" >/dev/null 2>&1 ) & done; wait; }
T_START=$(date +%s)
T_START_ISO=$(date '+%Y-%m-%d %H:%M:%S')
fails=0
why=""
acked=0

ck() {  # <what> <got> <want>
    if [ "$2" = "$3" ]; then echo "  PASS $1"; else echo "  FAIL $1 got=$2 want=$3"; fails=$((fails + 1)); why="${why}${why:+; }$1 (got $2)"; fi
}
cklt() {  # <what> <got> <bound>: got < bound
    if [ "${2:-x}" -lt "$3" ] 2>/dev/null; then echo "  PASS $1 ($2 < $3)"; else echo "  FAIL $1 got=$2 bound=$3"; fails=$((fails + 1)); why="${why}${why:+; }$1 (got $2)"; fi
}
finish() { echo "RESULT: $1 src=test | measured=$2 | reason=${why} (evidence $OUT)"; }
now_ms() { date +%s%3N; }
portal_of() { local v; v=$(lab_need san "$1") || exit 2; echo "${v##*,}.1"; }
link() {  # <node> <a|b> <up|down>: the cable, logged with its time
    scripts/san_net.sh link "$1" "$2" "$3" >> "$OUT/links.log" \
        || { why="could not set $1's path $2 $3"; finish FAIL "stage=link"; exit 1; }
}
links() {  # <a|b> <up|down> [<nodes>]: that network's cable on every node at once
    local n p pids=() bad=0
    for n in ${3:-$NODES}; do
        scripts/san_net.sh link "$n" "$1" "$2" >> "$OUT/links.log" &
        pids+=($!)
    done
    for p in "${pids[@]}"; do wait "$p" || bad=1; done
    [ "$bad" = 0 ] || { why="could not set network $1 $2 on every node"; finish FAIL "stage=link"; exit 1; }
}
links_all_up() { local n k; for n in $NODES; do for k in a b; do scripts/san_net.sh link "$n" "$k" up >/dev/null 2>&1; [ -z "${PF_MUTED:-}" ] || scripts/san_net.sh mute "$n" "$k" off >/dev/null 2>&1; done; done; }

# state <node> <tag>: that node's paths into $OUT/state_<node>_<tag>.txt
state() {
    rsx 25 "$1" "sh /src/mxfs/tests/mpath/pathstate.sh" > "$OUT/state_$1_$2.txt"
    capture_require "$OUT/state_$1_$2.txt" '^PATHS map=dm-[0-9]+ ' "the path state of $1 ($2)"
}
# states <tag> [<nodes>]: the same, from every node at once
states() {
    local tag=$1 n pids=()
    for n in ${2:-$NODES}; do
        rsx 25 "$n" "sh /src/mxfs/tests/mpath/pathstate.sh" > "$OUT/state_${n}_$tag.txt" &
        pids+=($!)
    done
    wait "${pids[@]}"
    for n in ${2:-$NODES}; do
        capture_require "$OUT/state_${n}_$tag.txt" '^PATHS map=dm-[0-9]+ ' "the path state of $n ($tag)"
    done
}
pfield() {  # <file> <portal> <field> -> the field of the path on that portal
    grep -a "^PATH .* portal=$2 " "$1" | head -1 | sed -n "s/.* $3=\([^ ]*\).*/\1/p"
}
usable() { sed -n 's/^PATHS .* usable=\([0-9]*\).*/\1/p' "$1" | tail -1; }
keys() {  # <tag>: the reservation keys the target holds, sorted, into $OUT/keys_<tag>.txt
    rsx 30 "${2:-$W}" "sg_persist -n -k \$(awk '\$2 == \"$MNT\" && \$3 == \"mxfs\" {print \$1}' /proc/mounts | head -1) 2>&1" | grep -aoE '^ +0x[0-9a-f]+' | tr -d ' ' | sort > "$OUT/keys_$1.txt"
}
wait_usable() {  # <node> <tag> [<bound_s>] -> seconds until 2 usable paths, or 999
    local s=$SECONDS u b=${3:-60}
    while [ $((SECONDS - s)) -lt "$b" ]; do
        state "$1" "$2"
        u=$(usable "$OUT/state_$1_$2.txt")
        [ "${u:-0}" -ge 2 ] && { echo $((SECONDS - s)); return 0; }
        sleep 2
    done
    echo 999
}
wait_usable_all() {  # <tag> [<bound_s>] [<nodes>] -> seconds until every node has 2 usable paths, or 999
    local tag=$1 b=${2:-60} s=$SECONDS n ok
    while [ $((SECONDS - s)) -lt "$b" ]; do
        states "$tag" "${3:-$NODES}"
        ok=1
        for n in ${3:-$NODES}; do [ "$(usable "$OUT/state_${n}_$tag.txt")" -ge 2 ] 2>/dev/null || ok=0; done
        [ "$ok" = 1 ] && { echo $((SECONDS - s)); return 0; }
        sleep 2
    done
    echo 999
}

# The gate every row starts at: 2 usable paths on 2 different bound NICs on
# every node, and the target holding each node's key on both paths.
pf_start_gate() {
    local n i pids=() stray
    # No load may be running when a row starts.  A chain stopped from
    # outside never touches its stop file, and its load keeps looping (it
    # counts errors and goes on) through the next prep — on a node whose
    # mount released cleanly it is not rebooted, resumes on the new mount,
    # adds its traffic to the next rows and holds the mount open: on
    # 4/net/mesh/mpath one ran 7.3M operations into the next lap and that
    # lap's first unmount answered busy.  Matched by its own command line
    # (tools/mxfs_pgrep.sh skips tasks in D state, so this cannot wedge).
    for n in $NODES; do
        stray=$(rs 20 "$n" "p=\$(/src/mxfs/tools/mxfs_pgrep.sh '^python3 /src/mxfs/tests/mpath/pathload[.]py run '); [ -n \"\$p\" ] && kill \$p 2>/dev/null; sleep 1; echo STRAY killed=\$(echo \$p | wc -w) left=\$(/src/mxfs/tools/mxfs_pgrep.sh '^python3 /src/mxfs/tests/mpath/pathload[.]py run ' | wc -l)" 2>/dev/null | grep -a '^STRAY ' | tail -1)
        [ "${stray:-}" = "STRAY killed=0 left=0" ] || echo "  INFO $n: load left running by an earlier run: ${stray:-unread}"
        case "$stray" in
            *" left=0") ;;
            *) echo "RESULT: ABORT label=$LABEL stage=stray-load node=$n ${stray:-unread} evidence=$OUT"; exit 2 ;;
        esac
    done
    states start
    for n in $NODES; do
        ck "$n starts on 2 usable paths" "$(usable "$OUT/state_${n}_start.txt")" 2
        ck "$n's paths are bound to 2 different NICs (a session that is not bound reconnects over any route)" "$(grep -a '^PATH ' "$OUT/state_${n}_start.txt" | sed -n 's/.* nic=\([^ ]*\).*/\1/p' | grep -v '^unbound$' | sort -u | grep -c .)" 2
    done
    keys start
    ck "the target holds every node's key on both paths at the start ($(( 2 * N )) registrations)" "$(grep -c . "$OUT/keys_start.txt")" "$(( 2 * N ))"
    [ "$fails" = 0 ] || { finish FAIL "stage=start"; exit 1; }
    # Each node's kernel log is followed into a file on the node from here on.
    # Asking the journal for the row's window at the end took over a minute on
    # a node whose journal had grown, and the ring holds about a second of this
    # module's output under load.  A follower that cannot show its mark aborts
    # the row (kmsg_follow_start), here as in the subshell it ran in.
    # A failed row leaves its followed log on the node (tens of MB, in /run,
    # which is memory): four of them filled test1's /run and the next row's
    # follower could not start.  Each is copied into its row's evidence when
    # the row ends, so one older than half an hour is a duplicate.
    for n in $NODES; do ( rs 15 "$n" "find /run -maxdepth 1 -name 'mxfs_pf_kmsg.*' -mmin +30 -delete" >/dev/null 2>&1 ) & done; wait
    for n in $NODES; do
        ( kmsg_follow_start "$n" "$PFMARK" "$KFILE" ) > "$OUT/follow_$n.txt" 2>&1 &
        pids+=($!)
    done
    i=0
    for n in $NODES; do
        if ! wait "${pids[$i]}"; then
            cat "$OUT/follow_$n.txt"
            echo "RESULT: ABORT label=$LABEL stage=follow evidence=$OUT"; exit 2
        fi
        i=$((i + 1))
    done
    trap 'kmsg_stop' EXIT
    # PF_KNOBS="name=value ...": test-only module parameters written on every
    # node once its log is being followed, so the row runs a path that its
    # natural faults reach only rarely.  Each node's read-back goes to
    # $OUT/knobs.txt; a parameter a node does not have fails the row, since
    # a row that ran without its knob measured something else.
    if [ -n "${PF_KNOBS:-}" ]; then
        local kv
        for n in $NODES; do
            for kv in $PF_KNOBS; do
                echo "$n ${kv%%=*} want=${kv#*=} got=$(rs 15 "$n" "echo ${kv#*=} > /sys/module/mxfs/parameters/${kv%%=*} && cat /sys/module/mxfs/parameters/${kv%%=*}" 2>/dev/null | tr -d '\r\n')" >> "$OUT/knobs.txt"
            done
        done
        ck "every node took PF_KNOBS ($PF_KNOBS)" "$(awk '{w=$3; g=$4; sub(/^want=/,"",w); sub(/^got=/,"",g); if (w != g) bad++} END {print bad+0}' "$OUT/knobs.txt")" 0
        [ "$fails" = 0 ] || { finish FAIL "stage=knobs"; exit 1; }
    fi
}
PFMARK="PF-MARK-$ROW-$RUN"
KFILE=/run/mxfs_pf_kmsg.$RUN.$ROW
kmsg_stop() { local n; for n in $NODES; do ( rs 15 "$n" "kill \$(cat $KFILE.pid 2>/dev/null) 2>/dev/null; rm -f $KFILE.pid" >/dev/null 2>&1 ) & done; wait; }

# The load on every node (or on the nodes named), and a trap that stops it and
# restores every link however the row ends.  pf_load_stop and pf_verify take
# the same optional list.  PF_VERIFY_ON names one node to read every manifest
# from (the first node reads that node's own).
pf_load_start() {
    local n warm=${PF_WARM_S:-20} on=${1:-$LOAD_NODES} pids=()
    for n in $on; do
        mkdir -p "$OUT/load_$n"
        rs 20 "$n" "rm -f $STOP; nohup setsid python3 /src/mxfs/tests/mpath/pathload.py run $n $MNT /src/mxfs/$OUT/load_$n $STOP > /src/mxfs/$OUT/load_$n/run.out 2>&1 < /dev/null &" >/dev/null &
        pids+=($!)
    done
    wait "${pids[@]}"
    trap 'stop_loads "$NODES"; links_all_up; kmsg_stop' EXIT
    sleep "$warm"
    for n in $on; do
        ck "$n's load is running before the first fault (completed operations > 0)" "$([ "$(grep -ac ' ok$' "$OUT/load_$n/ops.log" 2>/dev/null)" -gt 0 ] && echo yes || echo no)" yes
    done
    [ "$fails" = 0 ] || { finish FAIL "stage=load"; exit 1; }
}

# pf_window <tag> <T0 ms> <T1 ms> [<nodes>]: for each node, the longest stall
# overlapping the window (T1 the last completion before it, T2 the first
# after, from the load's own log), that operations kept completing, and that
# none returned an error.  Every value goes to $OUT/stalls.txt.
pf_window() {
    local tag=$1 T0=$2 T1=$3 n line
    sleep 2     # the load pushes its log to the server twice a second
    for n in ${4:-$LOAD_NODES}; do
        line=$(python3 tests/mpath/pathload.py stall "$OUT/load_$n/ops.log" "$T0" "$T1")
        echo "  INFO $tag: $n $line"
        echo "$tag $n t0_ms=$T0 $line" >> "$OUT/stalls.txt"
        cklt "$tag: $n's longest stall, ms" "$(sed -n 's/.*max_ms=\([0-9]*\).*/\1/p' <<<"$line")" "${PF_BOUND_MS:-$BOUND_MS}"
        ck "$tag: $n's load kept completing operations through the window" "$([ "$(sed -n 's/.*completed_in_window=\([0-9]*\).*/\1/p' <<<"$line")" -gt 0 ] && echo yes || echo no)" yes
        ck "$tag: no operation on $n returned an error" "$(sed -n 's/.*errors_in_window=\([0-9]*\).*/\1/p' <<<"$line")" 0
    done
}
stall_of() { awk -v t="$1" -v n="$2" '$1 == t && $2 == n' "$OUT/stalls.txt" 2>/dev/null | sed -n 's/.*max_ms=\([0-9]*\).*/\1/p' | tail -1; }

# pf_carried <node> <tag> <kept net> <down net>: between the _mid and _end
# states of a window, the kept path completed writes and the removed one none.
pf_carried() {
    local n=$1 tag=$2 pk pd w0 w1 d0 d1
    pk=$(portal_of "$3"); pd=$(portal_of "$4")
    w0=$(pfield "$OUT/state_${n}_${tag}_mid.txt" "$pk" writes); w1=$(pfield "$OUT/state_${n}_${tag}_end.txt" "$pk" writes)
    d0=$(pfield "$OUT/state_${n}_${tag}_mid.txt" "$pd" writes); d1=$(pfield "$OUT/state_${n}_${tag}_end.txt" "$pd" writes)
    ck "$tag: $n's path on $4 is not usable (dm=$(pfield "$OUT/state_${n}_${tag}_end.txt" "$pd" dm) chk=$(pfield "$OUT/state_${n}_${tag}_end.txt" "$pd" chk))" "$(usable "$OUT/state_${n}_${tag}_end.txt")" 1
    ck "$tag: $n's path left standing ($3) completed writes in the second half of the window (${w0:-?} -> ${w1:-?})" "$([ "${w1:-0}" -gt "${w0:-0}" ] && echo yes || echo no)" yes
    ck "$tag: $n's path taken away ($4) completed none (${d0:-?} -> ${d1:-?})" "$([ -n "$d0" ] && [ "${d1:-x}" = "$d0" ] && echo yes || echo no)" yes
}

# A load that was told to stop and did not report has an operation that never
# returned.  What it is blocked on exists only on that node and only until the
# next row reforms the cluster: path_fenced_return on 2/net/mesh/mpath left a
# write hung for 133 s, the node was rebooted by the row after it, and nothing
# of the hang was kept.  So, at the moment it is noticed: the load's own kernel
# stack, every task in uninterruptible sleep with its stack, and the tail of
# the node's followed kernel log, into the row's evidence.
pf_stuck_capture() {  # <node>
    local n=$1
    rs 40 "$n" "
        p=\$(cat /src/mxfs/$OUT/load_$n/pid 2>/dev/null)
        echo \"== load pid=\$p state=\$(cut -d' ' -f3 /proc/\$p/stat 2>/dev/null) at \$(date -u +%FT%TZ)\"
        cat /proc/\$p/stack 2>/dev/null
        for d in /proc/[0-9]*; do
            [ \"\$(cut -d' ' -f3 \$d/stat 2>/dev/null)\" = D ] || continue
            echo \"== \$d comm=\$(cat \$d/comm 2>/dev/null) state=D\"; cat \$d/stack 2>/dev/null
        done
    " > "$OUT/stuck_stacks_$n.txt" 2>&1
    rs 60 "$n" "tail -n 60000 $KFILE 2>/dev/null" > "$OUT/stuck_kmsg_$n.txt" 2>/dev/null
    echo "  INFO $n: its load did not report; kernel stacks in $OUT/stuck_stacks_$n.txt, the last 60000 lines of its kernel log in $OUT/stuck_kmsg_$n.txt"
}

# Stop the load; what every node says about its own run.
pf_load_stop() {
    local n i pl on=${1:-$LOAD_NODES}
    stop_loads "$on"
    for n in $on; do
        i=0; while [ $i -lt 45 ] && ! grep -aq '^PATHLOAD ' "$OUT/load_$n/run.out" 2>/dev/null; do sleep 1; i=$((i + 1)); done
        pl=$(grep -a '^PATHLOAD ' "$OUT/load_$n/run.out" 2>/dev/null | tail -1)
        echo "  INFO $n: ${pl:-no PATHLOAD line} $(grep -av '^PATHLOAD ' "$OUT/load_$n/run.out" 2>/dev/null | tail -2 | tr '\n' ' ' | cut -c1-200)"
        [ -n "$pl" ] || pf_stuck_capture "$n"
        ck "$n's load ended by itself and reported" "$([ -n "$pl" ] && echo yes || echo no)" yes
        ck "$n: no operation returned an error in the whole run" "$(sed -n 's/.* err=\([0-9]*\).*/\1/p' <<<"$pl")" 0
        ck "$n: the mutual-exclusion witness saw no double grant" "$(sed -n 's/.*double_grant=\([0-9]*\).*/\1/p' <<<"$pl")" 0
    done
}

# Every acknowledged file, read from another node: each node's manifest by
# the node before it in the list (or all of them by PF_VERIFY_ON), every read
# at once.
pf_verify() {
    local n i prev vl f on=${1:-$LOAD_NODES} pids=() readers=() nf vt
    set -- $on
    prev=${PF_VERIFY_ON:-${!#}}
    for n in $on; do
        [ "$prev" != "$n" ] || [ -z "${PF_VERIFY_ON:-}" ] || prev=$W
        # The bound follows the manifest: a node whose peer is down runs the
        # load several times faster (43209 files in one row against the usual
        # 1000-5000), and reading a file another node wrote costs a lock round
        # trip, measured 330-690 files/s with these 16 readers.  60 s plus the
        # files at 200/s.
        nf=$(grep -ac . "$OUT/load_$n/manifest" 2>/dev/null)
        vt=$(( 60 + ${nf:-0} / 200 ))
        rsx "$vt" "$prev" "python3 /src/mxfs/tests/mpath/pathload.py verify /src/mxfs/$OUT/load_$n/manifest" > "$OUT/verify_${n}_on_$prev.txt" &
        pids+=($!); readers+=("$prev")
        # One reader for every node's files (PF_VERIFY_ON) is one ssh login
        # per node to the same host, all at once.  sshd stops accepting past
        # ten unauthenticated connections (MaxStartups 10:30:100): at 16 nodes
        # it dropped one ("Connection closed by ... port 22", sshd: "exited
        # MaxStartups throttling ... 1 connections dropped") and three rows
        # of a 16/disk/caw/mpath board ended ABORT at this read-back with
        # every file they had read verified.  Eight at a time.
        if [ -n "${PF_VERIFY_ON:-}" ] && [ $(( ${#pids[@]} % 8 )) -eq 0 ]; then
            wait "${pids[@]}"
        fi
        [ -n "${PF_VERIFY_ON:-}" ] || prev=$n
    done
    wait "${pids[@]}"
    i=0
    for n in $on; do
        prev=${readers[$i]}; i=$((i + 1))
        capture_require "$OUT/verify_${n}_on_$prev.txt" '^VERIFY files=[0-9]+ ' "the read-back of $n's files on $prev"
        vl=$(grep -a '^VERIFY ' "$OUT/verify_${n}_on_$prev.txt" | tail -1)
        echo "  INFO $n's files read on $prev: $vl"
        f=$(sed -n 's/.*files=\([0-9]*\).*/\1/p' <<<"$vl"); acked=$((acked + f))
        ck "$n acknowledged files (> 0) and $prev reads every one with its checksum" "$([ "${f:-0}" -gt 0 ] && echo "$vl" | grep -q " ok=$f bad=0 missing=0" && echo yes || echo no)" yes
    done
}

# Nobody left, nothing broke (PF_LEAVES=1: the row itself unmounts a node, so
# an orderly departure and the smaller membership it leaves are not faults):
# each node's kernel log since the row's mark (the follower pf_start_gate
# started), its paths, and the target's keys.
pf_health() {
    local n pids=()
    for n in $NODES; do
        rsx 60 "$n" "sed -n '/$PFMARK/,\$p' $KFILE 2>/dev/null | grep -aE 'shutting down filesystem|Shutting down filesystem|Corruption of in-memory|P-WITHDRAW|P-SESSION-POISON|declaring dead|is no longer responding|did not reconnect within|has left the cluster|BUG:|Oops|blocked for more than|soft lockup|MXFS-MEMBERSHIP' | cut -c1-240; echo JOURNAL_READ" > "$OUT/kern_$n.txt" &
        pids+=($!)
    done
    wait "${pids[@]}"
    states end
    for n in $NODES; do
        capture_require "$OUT/kern_$n.txt" '^JOURNAL_READ$' "the kernel log of $n"
        if [ "$n" = "${PF_STOPS:-}" ]; then
            echo "  INFO $n is the node this row stops: its kernel log is judged by the row, not here"
        else
            ck "$n logged no shutdown, withdrawal, ${PF_DEATH:+unexpected }death declaration, BUG, oops or hung task" "$(grep -avE "MXFS-MEMBERSHIP|^JOURNAL_READ\$${PF_LEAVES:+|has left the cluster}${PF_DEATH:+|has left the cluster|declaring dead|is no longer responding|did not reconnect within}" "$OUT/kern_$n.txt" | grep -c .)" 0
        fi
        [ -n "${PF_LEAVES:-}${PF_DEATH:-}" ] || ck "$n saw no membership below $N" "$(grep -a 'MXFS-MEMBERSHIP' "$OUT/kern_$n.txt" | grep -aoE 'active_count=[0-9]+' | cut -d= -f2 | awk -v n="$N" '$1 < n' | grep -c .)" 0
        ck "$n ends on 2 usable paths" "$(usable "$OUT/state_${n}_end.txt")" 2
    done
    kmsg_stop
    keys end
    [ -n "${PF_NO_KEYCMP:-}" ] || ck "the target holds the same reservation keys at the end as at the start" "$(cmp -s "$OUT/keys_start.txt" "$OUT/keys_end.txt" && echo same || echo "differ($(grep -c . "$OUT/keys_end.txt"))")" same
}

# ---- rows in which a node is fenced (F5, F6, F7) ----
# pf_wait_keys <count> <bound_s> <tag> [<node>] -> seconds until the target
# holds exactly <count> registrations, or 999.  A fence removes the victim's
# key from every path at once, so the count is what says it happened.  The
# target is asked through <node> (default the first node); a row whose first
# node is the one frozen must name a survivor, or every sample reads empty.
pf_wait_keys() {
    local want=$1 b=$2 tag=$3 on=${4:-} s=$SECONDS
    while [ $((SECONDS - s)) -lt "$b" ]; do
        keys "$tag" "$on"
        [ "$(grep -c . "$OUT/keys_$tag.txt")" = "$want" ] && { echo $((SECONDS - s)); return 0; }
        sleep 3
    done
    echo 999
}
# pf_keys_hold <count> <seconds> <tag>: the count stays there, sampled every 5 s
pf_keys_hold() {
    local want=$1 dur=$2 tag=$3 s=$SECONDS i=0 bad=0 c
    while [ $((SECONDS - s)) -lt "$dur" ]; do
        keys "${tag}_$i"; c=$(grep -c . "$OUT/keys_${tag}_$i.txt")
        [ "$c" = "$want" ] || { bad=$((bad + 1)); echo "  INFO $tag sample $i: $c registrations, want $want"; }
        i=$((i + 1)); sleep 5
    done
    ck "$tag: the target held exactly $want registrations at every one of $i samples over ${dur}s" "$bad" 0
}
# pf_resumed <since_ms> <bound_s> <nodes> -> seconds until every one of those
# nodes' loads completed an operation that ended after <since_ms>, or 999
pf_resumed() {
    local since=$1 b=$2 s=$SECONDS n ok
    while [ $((SECONDS - s)) -lt "$b" ]; do
        ok=1
        for n in $3; do
            [ "$(tail -c 4096 "$OUT/load_$n/ops.log" 2>/dev/null | tr -d '\000' | awk -v t="$since" 'NF >= 4 && $4 == "ok" && $2 ~ /^[0-9]+$/ && $2 > t {f = 1} END {print f + 0}')" = 1 ] || ok=0
        done
        [ "$ok" = 1 ] && { echo $((SECONDS - s)); return 0; }
        sleep 2
    done
    echo 999
}
# pf_last_op_ms <node>: the end time of the last operation in that node's log,
# on the node's own clock
pf_last_op_ms() {
    tr -d '\000' < "$OUT/load_$1/ops.log" 2>/dev/null | awk 'NF >= 4 && $2 ~ /^[0-9]+$/ {t = $2} END {print t + 0}'
}
# pf_acked_after <node> <ms>: fsynced writes of that node's load that STARTED
# after <ms> (on the node's clock) and were acknowledged
pf_acked_after() {
    tr -d '\000' < "$OUT/load_$1/ops.log" 2>/dev/null | awk -v t="$2" 'NF >= 4 && $3 == "write" && $4 == "ok" && $1 ~ /^[0-9]+$/ && $1 >= t' | grep -c .
}
# pf_victim_stopped <tag> <since_ms>: the fenced node stopped by itself and
# nothing it wrote afterwards was acknowledged
pf_victim_stopped() {
    local tag=$1 since=$2 i=0
    rsx 30 "$V" "sed -n '/$PFMARK/,\$p' $KFILE 2>/dev/null | grep -aE 'P290-AUTH-CLOSED|P131-SELF-FENCE|hutting down filesystem|P-WITHDRAW|P277' | cut -c1-220 | tail -40; echo RESERVATION_CONFLICTS=\$(sed -n '/$PFMARK/,\$p' $KFILE 2>/dev/null | grep -ac 'reservation conflict'); echo STOP_READ" > "$OUT/stopped_${V}_$tag.txt"
    capture_require "$OUT/stopped_${V}_$tag.txt" '^STOP_READ$' "the kernel log of $V ($tag)"
    ck "$tag: $V stopped by itself (authority closed, self-fence or shutdown in its kernel log)" "$([ "$(grep -acE 'P290-AUTH-CLOSED|P131-SELF-FENCE|hutting down filesystem|P-WITHDRAW' "$OUT/stopped_${V}_$tag.txt")" -gt 0 ] && echo yes || echo no)" yes
    ck "$tag: no fsynced write that $V started after it was fenced was acknowledged" "$(pf_acked_after "$V" "$since")" 0
    rsx 30 "$V" "timeout 15 sh -c 'echo x > $MNT/pathload/$V/after_fence_$RUN && sync $MNT/pathload/$V/after_fence_$RUN'; echo PROBE_RC=\$?" > "$OUT/probe_${V}_$tag.txt"
    capture_require "$OUT/probe_${V}_$tag.txt" '^PROBE_RC=[0-9]+$' "a write on $V after its fence ($tag)"
    ck "$tag: a write on $V is refused, and returns (it does not hang)" "$(grep -a '^PROBE_RC=' "$OUT/probe_${V}_$tag.txt" | grep -vc 'PROBE_RC=0$')" 1
    # its load ends when told; the operations it could not do are the point
    stop_loads "$V"
    while [ $i -lt 45 ] && ! grep -aq '^PATHLOAD ' "$OUT/load_$V/run.out" 2>/dev/null; do sleep 1; i=$((i + 1)); done
    ck "$tag: $V's load ended when told (no operation of it is hung)" "$(grep -ac '^PATHLOAD ' "$OUT/load_$V/run.out" 2>/dev/null)" 1
    mv "$OUT/load_$V/run.out" "$OUT/load_$V/run_fenced.out" 2>/dev/null
}
# pf_remount <node> <tag>: leave and join again, both bounded
pf_remount() {
    local n=$1 tag=$2
    measure "$n" 100 "$OUT/remount_${n}_$tag.txt" '^REMOUNT umount_rc=[0-9]+ mount_rc=[0-9]+ ms=[0-9]+ mounted=[01]$' "the remount of $n ($tag)" \
        "s=\$(date +%s%3N); timeout 40 umount $MNT; u=\$?; timeout 45 mount -t mxfs $DEV $MNT; m=\$?; e=\$(date +%s%3N); grep -q ' $MNT mxfs ' /proc/mounts && k=1 || k=0; echo REMOUNT umount_rc=\$u mount_rc=\$m ms=\$((e-s)) mounted=\$k"
    echo "  INFO $tag: $n $(grep -a '^REMOUNT ' "$OUT/remount_${n}_$tag.txt" | head -1)"
    ck "$tag: $n unmounted and mounted again (rc 0, 0)" "$(grep -a '^REMOUNT ' "$OUT/remount_${n}_$tag.txt" | head -1 | sed 's/ ms=[0-9]*//')" "REMOUNT umount_rc=0 mount_rc=0 mounted=1"
}
# pf_boot_rejoin <node> <tag>: start a killed node and bring it back into the
# cluster: it logs in on its paths by itself (node.startup automatic), then
# the module the prep left on it is loaded and the filesystem mounted
pf_boot_rejoin() {
    local n=$1 tag=$2 i=0 up=0 args
    args=$(mxfs_rig_modargs) || { why="no module arguments for ${MXFS_CONFIG:-?}"; finish FAIL "stage=rejoin"; exit 1; }
    timeout 60 $VIRSH start "$n" >/dev/null 2>&1
    while [ $i -lt 180 ]; do
        [ "$(rs 8 "$n" "test -e /run/nologin || echo SSH_UP" | tail -1)" = SSH_UP ] && { up=1; break; }
        sleep 4; i=$((i + 4))
    done
    ck "$tag: $n booted and answers (within 180 s)" "$up" 1
    [ "$up" = 1 ] || return 1
    measure "$n" 200 "$OUT/rejoin_${n}_$tag.txt" '^REJOIN dev=[01] insmod_rc=[0-9]+ mount_rc=[0-9]+ ms=[0-9]+ mounted=[01]$' "the rejoin of $n ($tag)" \
        "mountpoint -q /src || { mkdir -p /src; mount -t nfs 192.168.120.1:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp; }
         j=0; while [ \$j -lt 90 ] && ! [ -e $DEV ]; do multipath >/dev/null 2>&1; sleep 3; j=\$((j+3)); done
         [ -e $DEV ] && d=1 || d=0
         j=0; while [ \$j -lt 40 ] && [ \"\$(multipathd show paths format '%t %T' 2>/dev/null | grep -c 'active ready')\" -lt 2 ]; do sleep 2; j=\$((j+2)); done
         modprobe libcrc32c 2>/dev/null; lsmod | grep -q '^mxfs ' || insmod /root/mxfs.ko.prep dyndbg=+p $args; i=\$?
         s=\$(date +%s%3N); timeout 60 mount -t mxfs $DEV $MNT; m=\$?; e=\$(date +%s%3N)
         grep -q ' $MNT mxfs ' /proc/mounts && k=1 || k=0
         echo REJOIN dev=\$d insmod_rc=\$i mount_rc=\$m ms=\$((e-s)) mounted=\$k"
    echo "  INFO $tag: $n $(grep -a '^REJOIN ' "$OUT/rejoin_${n}_$tag.txt" | head -1)"
    ck "$tag: $n rejoined (map present, module loaded, mount rc 0)" "$(grep -a '^REJOIN ' "$OUT/rejoin_${n}_$tag.txt" | head -1 | sed 's/ ms=[0-9]*//')" "REJOIN dev=1 insmod_rc=0 mount_rc=0 mounted=1"
    ( kmsg_follow_start "$n" "$PFMARK" "$KFILE" ) > "$OUT/follow_${n}_$tag.txt" 2>&1
}

# pf_done <measured>: the RESULT line and the exit status
pf_done() {
    trap - EXIT
    local n c m="$1 acked=$acked elapsed=$(( $(date +%s) - T_START ))s fails=$fails"
    # disk/caw: how often a lock wait found its registration gone and
    # registered again, and how often a handed-over grant was refused under a
    # local clear (the event that takes the registration away).  Counted here
    # because the followed log is removed when the row passes.
    case "${MXFS_CONFIG:-}" in */disk/caw/*)
        for n in $NODES; do
            c=$(rs 20 "$n" "grep -ac 'P-WAIT-REG-LOST' $KFILE; grep -ac 'P250-LREQ-CLR-REFUSE.*arm=adopt' $KFILE" 2>/dev/null | grep -aE '^[0-9]+$' | tr '\n' ' ')
            echo "  INFO $n: lock waits that registered again, adoptions refused under a local clear (rate-limited line): ${c:-unread}"
        done ;;
    esac
    # A lookup whose entry named an inode a peer had freed since: how often it
    # read the parent again, and how often a lookup ended unresolved (ESTALE
    # to the caller).  Any configuration; the same reason to count it here.
    for n in $NODES; do
        c=$(rs 20 "$n" "grep -ac 'P201-RELOOKUP' $KFILE; grep -ac 'P201-TYPEFLIP-UNRESOLVED-FAIL' $KFILE; grep -ac 'P95B-TYPEFLIP-WAIT' $KFILE" 2>/dev/null | grep -aE '^[0-9]+$' | tr '\n' ' ')
        echo "  INFO $n: lookups that read the parent again, lookups left unresolved, type changes waited out: ${c:-unread}"
    done
    # The followed kernel log stays on each node when the row failed (it is the
    # only copy: the journal rotates within minutes under this load) and is
    # removed when it passed, since /run is memory.
    if [ "$fails" = 0 ]; then
        # PF_KEEP_KMSG=1: a passing row's logs are copied into its evidence
        # first (2-4 MB a node, compressed).  A wrong directory entry found by
        # the cold audit at the end of a lap was written rows earlier, in a row
        # that had passed and whose logs were gone (8/net/mesh/mpath, the
        # entry of a file left by the row before the one that tripped on it).
        if [ -n "${PF_KEEP_KMSG:-}" ]; then
            for n in $NODES; do ( rs 90 "$n" "gzip -c $KFILE > /src/mxfs/$OUT/kmsg_${n}_fromnode.gz" >/dev/null 2>&1 ) & done; wait
            echo "  INFO each node's kernel log of this row is in $OUT/kmsg_<node>_fromnode.gz (PF_KEEP_KMSG)"
        fi
        for n in $NODES; do ( rs 15 "$n" "rm -f $KFILE" >/dev/null 2>&1 ) & done; wait
        finish PASS "$m"; exit 0
    fi
    # A failed row's log is copied into its evidence as well: /run is memory,
    # and the rows that follow reboot their victims.  Two failed rows on
    # 0.90.52 (a node's filesystem shut down in path_failover on
    # 4/net/mesh/mpath, a 72 s stall on 2/net/mesh/mpath) lost the only copy
    # to the reboot of the next row's victim before anyone read it.
    for n in $NODES; do ( rs 90 "$n" "gzip -c $KFILE > /src/mxfs/$OUT/kmsg_${n}_fromnode.gz" >/dev/null 2>&1 ) & done; wait
    echo "  INFO each node's kernel log of this row is in $OUT/kmsg_<node>_fromnode.gz and kept on the node: $KFILE"
    finish FAIL "$m"
    exit 1
}
