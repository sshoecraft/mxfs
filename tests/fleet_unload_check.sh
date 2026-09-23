#!/bin/bash
# fleet_unload_check.sh — unmount and unload mxfs on every node with the
# kernel window of each step captured at the time it happens.  Two-node TCP.
#
# Why: the 0.75.62 -> 0.75.63 prep on 2026-09-08 (tests/evidence/
# sess544_unmount_check_test1.txt) showed a kernel WARNING from
# kmem_cache_destroy at rmmod on test1 — a slab cache still holding objects,
# i.e. something allocated for the mount was never freed — and both nodes
# waited the whole 3 s release-ack bound at unmount (P-TAUTH-RELEASE-WAIT
# unacked=26 / 221).  By the time the WARNING was looked at, the node's dmesg
# ring had wrapped past it (the create laps log ~700 lines/s) and the cache
# name was gone.  The window is saved here, per node, per step, before the
# next thing runs.
#
# Nodes are torn down CONCURRENTLY by default (the shape prep_cluster uses,
# and the one that makes each node the master its peer's releases cannot
# reach): MODE=serial tears them down one at a time instead, which is the
# control for the release-ack wait.
#
# the budget rule (derived): umount 5-15 s each (the 3 s ack bound + the quiesce),
# rmmod ~2 s, captures ~3 s; concurrent -> ~25 s, serial ~40 s.
#
# Usage: tests/fleet_unload_check.sh <label> [node...]     (default test1 test2)
# Env:   MODE=serial|parallel (default parallel), MNT=/mnt/shared
set -u
LABEL=${1:?label}
shift
NODES=("$@")
[ ${#NODES[@]} -gt 0 ] || NODES=(test1 test2)
MODE=${MODE:-parallel}
MNT=${MNT:-/mnt/shared}
cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_unload_$LABEL
mkdir -p "$OUT"
filt() { grep -av '^Unauthorized\|^Warning:\|^If you\|^$'; }
NOISE='P-TAUTH-PREPARED\|P-TAUTH-ACTIVATE\|PAGE-MINE\|HANDOFF\|TAKEOVER-RETIRE\|bdev_io'
fails=0
ck() { if [ "$2" = "$3" ]; then echo "  PASS $1 ($2)"; else echo "  FAIL $1 got=$2 want=$3"; fails=$((fails+1)); fi; }
MK="UNLOAD-$LABEL"

echo "=== fleet_unload_check label=$LABEL nodes=${NODES[*]} mode=$MODE $(date -u +%FT%TZ) ==="
s=$(date +%s)
# One remote script per node: marker, timed umount, timed rmmod, then the
# kernel window since the marker with only the ledger-page noise dropped.
unload_one() {  # <node>
    local n=$1
    timeout 120 $SSH "$n" "echo '$MK' > /dev/kmsg; sv=\$(cat /sys/module/mxfs/srcversion 2>/dev/null); t0=\$(date +%s%N); mountpoint -q $MNT && timeout 60 umount $MNT; urc=\$?; t1=\$(date +%s%N); lsmod | grep -q '^mxfs ' && timeout 30 rmmod mxfs; rrc=\$?; t2=\$(date +%s%N); sleep 2; echo UNLOAD node=$n sv=\$sv umount_rc=\$urc umount_ms=\$(( (t1 - t0) / 1000000 )) rmmod_rc=\$rrc rmmod_ms=\$(( (t2 - t1) / 1000000 )) loaded=\$(lsmod | grep -c '^mxfs '); dmesg | sed -n '/$MK/,\$p' | grep -av '$NOISE'" 2>/dev/null | filt > "$OUT/unload_$n.txt"
}
if [ "$MODE" = serial ]; then
    for n in "${NODES[@]}"; do unload_one "$n"; done
else
    for n in "${NODES[@]}"; do unload_one "$n" & done
    wait
fi
for n in "${NODES[@]}"; do
    f="$OUT/unload_$n.txt"
    echo "  INFO $(grep -a '^UNLOAD node=' "$f" | head -1)"
    ck "$n: unmounted and unloaded" "$(grep -ao 'umount_rc=[0-9]* ' "$f" | head -1 | tr -d ' ')_$(grep -ao 'loaded=[0-9]*' "$f" | head -1)" "umount_rc=0_loaded=0"
    warn=$(grep -ac 'WARNING:\|BUG:\|Oops\|Slab cache\|kmem_cache_destroy\|Internal error\|Corruption\|xg_ref\|refcount_t\|use-after-free\|KASAN' "$f")
    ck "$n: no kernel warning, slab leak or corruption line in the unload window" "$warn" "0"
    [ "$warn" != 0 ] && grep -a -B2 -A14 'WARNING:\|Slab cache\|Internal error\|Corruption' "$f" | cut -c1-180 | head -40 | sed 's/^/      /'
    rw=$(grep -ao 'P-TAUTH-RELEASE-WAIT unacked=[0-9]* after [0-9]*ms' "$f" | head -1)
    echo "  INFO $n release-ack wait: ${rw:-none}"
    # 0.75.65 (D-0925): the departure worker's cost for the peer that left
    # first — the purge and takeover passes are what the unmount wall was.
    echo "  INFO $n departure work: $(grep -a 'P-DEPART-WORK ' "$f" | grep -ao 'purge_ms=[0-9]* table_ms=[0-9]* takeover_ms=[0-9]* total_ms=[0-9]*' | tr '\n' ' ')purge=[$(grep -a 'P-TAUTH-PURGE node' "$f" | grep -ao 'cleared=[0-9]*\|cand=[0-9]*\|scan_ms=[0-9]*\|total_ms=[0-9]*' | tr '\n' ' ')] takeover=[$(grep -a 'P-TAUTH-TAKEOVER departed' "$f" | grep -ao 'pages_prepared=[0-9]*\|cand=[0-9]*\|scan_ms=[0-9]*\|total_ms=[0-9]*' | tr '\n' ' ')]"
    echo "  INFO $n unmount window lines=$(grep -ac . "$f") teardown_drops=$(grep -ac 'P-TEARDOWN-MSG-DROP' "$f") release_unacked=$(grep -ac 'P-TAUTH-RELEASE-UNACKED' "$f")"
    # 0.75.66 (D-0925 mechanism 2): what the clean departure released over
    # the wire and how its acks went (P-RELALL-WIRED), and how many of the
    # PEER's releases this node served after its own teardown began
    # (P-GOODBYE-SENT counters).
    echo "  INFO $n departure releases: $(grep -a 'P-RELALL-WIRED' "$f" | grep -ao 'released=[-0-9]*\|ack_rc=[-0-9]*\|held_after=[0-9]*' | tr '\n' ' ')$(grep -a 'P-GOODBYE-SENT' "$f" | grep -ao 'teardown_releases_served=[0-9]*\|teardown_local_basts_dropped=[0-9]*' | tr '\n' ' ')"
done
wall=$(( $(date +%s) - s ))
echo "  UNLOAD-MEASURE label=$LABEL mode=$MODE wall_s=$wall $(for n in "${NODES[@]}"; do grep -ao "umount_ms=[0-9]*" "$OUT/unload_$n.txt" | head -1 | sed "s/^/${n}_/"; done | tr '\n' ' ')"
if [ $fails = 0 ]; then echo "RESULT: PASS label=$LABEL wall=${wall}s evidence=$OUT"; else echo "RESULT: FAIL label=$LABEL fails=$fails wall=${wall}s evidence=$OUT"; fi
exit $fails
