#!/bin/bash
# storm_ab_pass.sh — ONE pass of a paired storm A/B, as a single line of result.
#
# WHY A SEPARATE PASS RUNNER
#   A 60-round storm plus its two census passes runs ~5 minutes, so a 3-pair
#   A/B is ~30 minutes — longer than one foreground command may run here.  The
#   A/B design (one prep, one discarded warm-up, then ALTERNATING passes on the
#   same cluster state) requires that NO prep happens between passes: the
#   storm's failure rate falls monotonically with time since prep, so a prep
#   mid-series silently re-randomises the comparison.  Splitting the series into
#   individually-invocable passes is the only way to satisfy both constraints.
#
#   Therefore: this script NEVER preps.  The caller preps once, runs one warm-up
#   pass, and then calls this alternately, appending each line to a tally file.
#
# USAGE
#   tests/storm_ab_pass.sh <arm-label> <param=val[,param=val...]> [rounds] [nodes] [tally]
#     e.g. tests/storm_ab_pass.sh A p6_epoch_override=1,create_baseline_trackers=1
#
# OUTPUT (one line, also appended to the tally file):
#   PASS-RESULT arm=A durable_rounds=0 durable_list= p195=1 p194=1 p188=0 late_ok=270 rc=0
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd -- "$SCRIPT_DIR/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"

ARM="${1:?usage: storm_ab_pass.sh <arm-label> <param=val,...> [rounds] [nodes] [tally]}"
SPEC="${2:?}"
ROUNDS="${3:-60}"
N="${4:-32}"
TALLY="${5:-$REPO/tests/logs/storm_ab_tally.txt}"

for kv in ${SPEC//,/ }; do
    k="${kv%%=*}"; v="${kv##*=}"
    for i in $(seq 1 "$N"); do
        ( timeout 20 "$SSH" "test$i" \
            "echo $v > /sys/module/mxfs/parameters/$k" >/dev/null 2>&1 ) &
    done
    wait
    got=$(timeout 20 "$SSH" test1 "cat /sys/module/mxfs/parameters/$k" 2>/dev/null | tr -dc '0-9-')
    [ "$got" = "$v" ] || { echo "PARAM SET FAILED: $k wanted=$v got=$got" >&2; exit 2; }
done

out=$(timeout $(( ROUNDS * 2 + 300 )) "$SCRIPT_DIR/sf_mkdir_storm.sh" "$ROUNDS" "$N" 2 1 2>&1)
rc=$?
logdir=$(printf '%s\n' "$out" | sed -n 's/.*logs: \(.*\)$/\1/p' | tail -1)
[ -n "$logdir" ] || logdir=$(printf '%s\n' "$out" | sed -n 's/.*evidence: \(.*\)$/\1/p' | tail -1)

if [ "$rc" = 2 ]; then
    line="PASS-RESULT arm=$ARM INFRA-FAIL (not a data point) log=$logdir"
    echo "$line" | tee -a "$TALLY"; exit 2
fi

dlist=$(printf '%s\n' "$out" | sed -n 's/.*DURABLE (identical in both census passes[^)]*): //p' | tr -s ' ')
dn=$(printf '%s\n' $dlist | sed '/^$/d' | wc -l)
lateok=$(printf '%s\n' "$out" | sed -n 's/.*retired as LATE-OK: \([0-9]*\).*/\1/p')

# The precursor probes come from the rings, which sf_mkdir_storm.sh cleared at
# its start — so these counts belong to THIS pass alone.  A passing storm does
# NOT harvest dmesg (only markers_*.log), so harvest here or the precursor half
# of the comparison is silently missing (that exact gap produced a fictitious
# "everything -> 0" table in sess21).
tmp=$(mktemp -d)
for i in $(seq 1 "$N"); do
    ( timeout 30 "$SSH" "test$i" \
        "dmesg | grep -E 'P195-STALE-BASE|P194-EPOCH-STALE|P188-REL-OBLIG|P193-P6-EPOCH|P32E-DIREPOCH-FENCE|P51-HANDOFF-UNDERFIRE|P198-RELOAD-DEMOTE-WAITED|P34J-RELOAD-DEMOTE-BAIL|P177-OBLIGATION-DROPPED|P196-UNLOCK-OBLIGATION'" \
        > "$tmp/t$i" 2>/dev/null ) &
done
wait
p195=$(cat "$tmp"/t* 2>/dev/null | grep -c 'P195-STALE-BASE')
p194=$(cat "$tmp"/t* 2>/dev/null | grep -c 'P194-EPOCH-STALE')
p188=$(cat "$tmp"/t* 2>/dev/null | grep -c 'P188-REL-OBLIG')
p193=$(cat "$tmp"/t* 2>/dev/null | grep -c 'P193-P6-EPOCH')
p32e=$(cat "$tmp"/t* 2>/dev/null | grep -c 'P32E-DIREPOCH-FENCE')
p51u=$(cat "$tmp"/t* 2>/dev/null | grep -c 'P51-HANDOFF-UNDERFIRE')
p198=$(cat "$tmp"/t* 2>/dev/null | grep -c 'P198-RELOAD-DEMOTE-WAITED')
p34j=$(cat "$tmp"/t* 2>/dev/null | grep -c 'P34J-RELOAD-DEMOTE-BAIL')
p177=$(cat "$tmp"/t* 2>/dev/null | grep -c 'P177-OBLIGATION-DROPPED')
[ -n "$logdir" ] && [ -d "$logdir" ] && cp -r "$tmp" "$logdir/precursors" 2>/dev/null
rm -rf "$tmp"

line="PASS-RESULT arm=$ARM durable_rounds=$dn durable_list=[$dlist] p195=$p195 p194=$p194 p188=$p188 p193=$p193 p32e=$p32e p51underfire=$p51u p198waited=$p198 p34jbail=$p34j p177dropped=$p177 late_ok=${lateok:-0} rc=$rc log=$logdir"
echo "$line" | tee -a "$TALLY"
exit 0
