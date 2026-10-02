#!/bin/bash
# stress_rmdir_mkdir_race.sh — every node of a rig group mkdirs into fresh
# shared parents while rank 1 removes the parent two slots back; then the cold
# audit, and the dead-parent probe's hits collected from every node.
#
# WHY.  Directory corruption on 8/net/mesh/direct (defect
# D-8TCP-CONCURRENT-RMDIR-AND-MKDIR-LOSE-SHORTFORM-DIRECTORY-UPDATES) came
# from ag_strand_repair's round shape: children created by other nodes inside a
# parent rank 1's rm -rf had already removed and freed, and an entry kept in a
# surviving parent after its inode was freed.  In ag_strand_repair the parents
# change every 2 s and rank 1 removes the parent three rounds back, so the
# collision needs a node lagging rounds behind (the host load of a parallel
# wave stalls guests for seconds); the damage appeared in 1 of 4 parallel
# waves.  Here the removal and the creates are forced to overlap: every slot
# rank 1 removes that slot's parent halfway through it, while every other rank
# creates in it at a random point of the slot.
#
# The lap preps the group itself (a fresh format and a formed cluster); the
# audit is run.sh's chk_clean, which unmounts, audits cold and remounts.  The module must carry the P-DEADPARENT probe for
# the per-node counts to mean anything (they read 0 otherwise).
#
# ARMS.  What the other ranks do in each slot's parent:
#   mkdir    mkdir n$R and n$R/c (the shape above)
#   link     hard-link a file from the rank's own directory in as n$R
#   symlink  symlink n$R
#   rename   move a file from the rank's own directory in as n$R
# Those four each put a name into a parent rank 1 is removing: a name that
# lands after the removal is lost with the parent, and only the audit's link
# counts see it (the file keeps its nlink, nothing names it).
#   child    the parent is NOT removed.  Rank 1 makes four children at the
#            start of the slot and removes them halfway through it, while every
#            other rank mkdirs one entry beside them in each half of the slot:
#            removals and adds on one live shortform parent at once, with each
#            adding node touching the parent before and after the removal.
#
# RANK1_SYSFS (default none): "name=value ..." module parameters written on rank
# 1 only, after the prep and just before the load starts, and set back to 0 when
# the load ends, so a test-only injector acts on the remover's load and on
# nothing the prep or the audit runs (alloc_witness's rm -f used up an
# injector's whole budget when it was set at module load).  BASEINO in a value
# is replaced by the base directory's inode number.
#
# Every node also records each kernel line that names the lap's base directory
# by inode number (base_<node>.txt): the base is the busiest shared parent, and
# a lost update of it (a link count that disagrees with its entries) can only be
# traced from every node's writes and adopts of it, in time order.
#
# Usage: [RANK1_SYSFS="..."] tests/stress_rmdir_mkdir_race.sh <configuration> <group> <seconds> [slot_ms] [arm]
#   e.g. tests/stress_rmdir_mkdir_race.sh 8/net/mesh/direct g8 60 200 link
# Exit 0 iff the audit is CLEAN; 1 if CORRUPT (the group's image is copied);
# 2 if the lap produced no verdict.
set -u
REPO=$(cd "$(dirname "$0")/.." && pwd)
CONFIG=${1:?configuration}
GROUP=${2:?group}
SECS=${3:?seconds}
SLOT_MS=${4:-200}
ARM=${5:-mkdir}
case "$ARM" in
    mkdir|link|symlink|rename|child) ;;
    *) echo "unknown arm '$ARM' (mkdir|link|symlink|rename|child)"; exit 2 ;;
esac
SSH="$REPO/tools/mxfs_sshpass.sh"
NODES=$("$REPO/tools/mxfs_lab.sh" group "$GROUP") || exit 2
OUT="$REPO/tests/evidence/stress_rmrace_$(date -u +%Y%m%dT%H%M%SZ)-$GROUP-$ARM"
mkdir -p "$OUT"
# A fresh format and a formed cluster: a board does not leave its group mounted.
"$REPO/run.sh" "$CONFIG" --group "$GROUP" prep_cluster > "$OUT/prep.log" 2>&1 \
    || { echo "prep failed — see $OUT/prep.log"; exit 2; }
TAG=$(date +%s)
START=$(( $(date +%s%3N) + 5000 ))
echo "stress: $CONFIG on $GROUP [$NODES] ${SECS}s slot=${SLOT_MS}ms arm=$ARM evidence $OUT"

# One remote loop per node.  Slots come from a shared wall-clock start, so every
# node works on the same parent at the same time; rank 1 alone removes, detached,
# so a slow rm never delays its own creates.
LOOP='
B=/mnt/shared/.rmrace.TAG; R=RANK; S=START; SL=SLOT; E=$(( S + SECS * 1000 )); A=ARM
mountpoint -q /mnt/shared || { echo "RMRACE rank=$R notmounted"; exit 0; }
echo "RMRACE rank=$R started"
# failure lines from the kernel log as they happen: a guest journal keeps about
# two minutes under this load, so a withdraw early in the lap is gone by the end;
# the injector, no-grant and dropped-obligation lines too, because the dmesg ring
# wraps long before the lap ends and a later dmesg count reads 0 whatever happened
setsid bash -c "journalctl -k -f -n 0 -o short-iso 2>/dev/null | grep --line-buffered -aE \"WITHDRAW|[Ss]hut ?down|LKTIMEOUT|HOLDERTASK|[Cc]orrupt|force_shutdown|blocked for more|P-INSERT-DEADPARENT|P-CREATE-DEADPARENT|P-DEMOTER-NOGRANT|P-DEMOTER-KEEP-INJECT|P-DEMOTER-DEAD-REAP|P177-OBLIGATION-DROPPED|P-INODE-WEDGE|P-WITHDRAW\" > /root/rmrace_watch.TAG.txt" </dev/null >/dev/null 2>&1 &
W=$!; echo "$W" > /root/rmrace_watch.TAG.pid
[ "$R" = 1 ] && mkdir -p "$B"
while [ "$(date +%s%3N)" -lt "$S" ] && [ ! -d "$B" ]; do sleep 0.01; done
BI=$(stat -c %i "$B" 2>/dev/null)
if [ -n "$BI" ]; then
    setsid bash -c "journalctl -k -f -n 0 -o short-iso 2>/dev/null | grep --line-buffered -aE \"(ino|pino|dp)=$BI \" > /root/rmrace_base.TAG.txt" </dev/null >/dev/null 2>&1 &
    echo "$!" > /root/rmrace_base.TAG.pid
    # out of the job table of this shell: the wait at the end of the load must
    # not wait for a follower that runs until the collection step stops it
    disown
fi
if [ "$R" = 1 ]; then
    for kv in RANK1SYSFS; do
        [ "$kv" = none ] && continue
        kv=${kv//BASEINO/$BI}
        echo "${kv#*=}" > "/sys/module/mxfs/parameters/${kv%%=*}" && echo "RMRACE rank=1 sysfs ${kv%%=*}=$(cat /sys/module/mxfs/parameters/${kv%%=*})"
    done
fi
while [ "$(date +%s%3N)" -lt "$S" ]; do sleep 0.01; done
mkdir -p "$B/own$R"
# one name into the slot parent, by this lap arm
add() {
    case "$A" in
        link)    : > "$B/own$R/f$K" && ln "$B/own$R/f$K" "$B/d$K/n$R" ;;
        symlink) ln -s "own$R/f$K" "$B/d$K/n$R" ;;
        rename)  : > "$B/own$R/f$K" && mv -T "$B/own$R/f$K" "$B/d$K/n$R" ;;
        *)       mkdir "$B/d$K/n$R" && mkdir "$B/d$K/n$R/c" ;;
    esac
}
last=-1; mk=0; mkfail=0; rm=0
while :; do
    now=$(date +%s%3N); [ "$now" -ge "$E" ] && break
    K=$(( (now - S) / SL ))
    if [ "$K" != "$last" ]; then
        if [ "$R" = 1 ] && [ "$A" = child ]; then
            mkdir -p "$B/d$K" 2>/dev/null
            if mkdir "$B/d$K/c1" "$B/d$K/c2" "$B/d$K/c3" "$B/d$K/c4" 2>/dev/null; then mk=$((mk+1)); else mkfail=$((mkfail+1)); fi
            # remove this slot own children halfway through it, while the other
            # ranks, each at a random point in the slot, add beside them; the
            # parent itself stays
            ( sleep "$(awk -v m=$(( SL / 2 )) "BEGIN{print m/1000}")"; rmdir "$B/d$K/c1" "$B/d$K/c2" "$B/d$K/c3" "$B/d$K/c4" 2>/dev/null ) & rm=$((rm+1))
        elif [ "$R" = 1 ]; then
            mkdir -p "$B/d$K" 2>/dev/null
            if mkdir "$B/d$K/n$R" 2>/dev/null && mkdir "$B/d$K/n$R/c" 2>/dev/null; then mk=$((mk+1)); else mkfail=$((mkfail+1)); fi
            # remove the parent of this slot halfway through it, while the other
            # ranks, each at a random point in the slot, are creating in it
            ( sleep "$(awk -v m=$(( SL / 2 )) "BEGIN{print m/1000}")"; rm -rf "$B/d$K" 2>/dev/null ) & rm=$((rm+1))
        elif [ "$A" = child ]; then
            # one add at a random point of each half of the slot, so the node
            # modifies the parent before rank 1 removal and again after it (a
            # stale in-core parent needs both); two adds from each of seven
            # ranks plus four children keep the parent shortform
            t=0
            for at in $(( RANDOM % (SL / 2) )) $(( SL / 2 + RANDOM % (SL / 2) )); do
                sleep "$(awk -v m=$(( at - t )) "BEGIN{print m/1000}")"; t=$at
                mkdir -p "$B/d$K" 2>/dev/null
                if mkdir "$B/d$K/n$R.$at" 2>/dev/null; then mk=$((mk+1)); else mkfail=$((mkfail+1)); fi
            done
        else
            sleep "$(awk -v m=$(( RANDOM % SL )) "BEGIN{print m/1000}")"
            mkdir -p "$B/d$K" 2>/dev/null
            if add 2>/dev/null; then mk=$((mk+1)); else mkfail=$((mkfail+1)); fi
        fi
        last=$K
    fi
    sleep 0.01
done
kill -- -$W 2>/dev/null
if [ "$R" = 1 ]; then
    for kv in RANK1SYSFS; do
        [ "$kv" = none ] && continue
        echo 0 > "/sys/module/mxfs/parameters/${kv%%=*}"
    done
fi
wait
echo "RMRACE rank=$R arm=$A mk=$mk mkfail=$mkfail rm=$rm dead=$(dmesg | grep -c "P-DEADPARENT ino") refused=$(dmesg | grep -c P-CREATE-DEADPARENT-REFUSED) insert_refused=$(dmesg | grep -c P-INSERT-DEADPARENT-REFUSED) insert_dead=$(dmesg | grep -c P-INSERT-DEADPARENT-SEEN) postdialloc=$(dmesg | grep -c P-CREATE-DEADDIR-POSTDIALLOC)"'

i=0
for n in $NODES; do
    i=$((i + 1))
    s=${LOOP//RANK1SYSFS/${RANK1_SYSFS:-none}}
    s=${s//TAG/$TAG}; s=${s//RANK/$i}; s=${s//START/$START}; s=${s//SLOT/$SLOT_MS}; s=${s//SECS/$SECS}; s=${s//=ARM/=$ARM}
    ( timeout $(( SECS + 60 )) "$SSH" "$n" "$s" </dev/null 2>/dev/null | grep -a '^RMRACE' > "$OUT/$n.txt" ) &
done
wait
for n in $NODES; do echo "  $n $(grep -v started "$OUT/$n.txt" 2>/dev/null || echo "NO RESULT ($(grep -c started "$OUT/$n.txt" 2>/dev/null) start line)")"; done
# the watchers: a node whose loop hung never killed its own, so stop it here
for n in $NODES; do
    ( timeout 30 "$SSH" "$n" "p=\$(cat /root/rmrace_watch.$TAG.pid 2>/dev/null); [ -n \"\$p\" ] && kill -- -\$p 2>/dev/null; cat /root/rmrace_watch.$TAG.txt 2>/dev/null" </dev/null 2>/dev/null > "$OUT/$n.watch"
      timeout 60 "$SSH" "$n" "p=\$(cat /root/rmrace_base.$TAG.pid 2>/dev/null); [ -n \"\$p\" ] && kill -- -\$p 2>/dev/null; cat /root/rmrace_base.$TAG.txt 2>/dev/null" </dev/null 2>/dev/null | gzip > "$OUT/base_$n.txt.gz" ) &
done
wait
for n in $NODES; do
    w=$(wc -l < "$OUT/$n.watch" 2>/dev/null || echo 0)
    [ "$w" -gt 0 ] && echo "  $n kernel failure lines: $w ($OUT/$n.watch)"
done

since=$(date -u +%FT%TZ)
"$REPO/run.sh" "$CONFIG" --group "$GROUP" chk_clean > "$OUT/chk.log" 2>&1
v=$(python3 - "$REPO/data/criteria.json" "$CONFIG" "$since" <<'PY'
import json, re, sys
d = json.load(open(sys.argv[1]))
for e in d["criteria"]:
    if e.get("id") == "chk_clean":
        cell = (e.get("per_config") or {}).get(sys.argv[2]) or {}
        if str(cell.get("iso", "")) < sys.argv[3]:
            print("STALE"); break
        m = re.search(r"verdict=([A-Z]+).*?errors=(\d+)", str(cell.get("measured", "")))
        print("%s errors=%s" % m.groups() if m else "NONE")
PY
)
echo "audit: $v"
for n in $NODES; do
    "$SSH" "$n" "dmesg | grep -E 'P-DEADPARENT ino|P-CREATE-DEADDIR-POSTDIALLOC'" </dev/null 2>/dev/null | grep -aE 'P-DEADPARENT ino|P-CREATE-DEADDIR-POSTDIALLOC' | sed "s/^/$n /"
done > "$OUT/deadparent_lines.txt"
echo "probe lines (dead parent, create into dead dir): $(wc -l < "$OUT/deadparent_lines.txt") ($OUT/deadparent_lines.txt)"
case "$v" in
    CLEAN*) exit 0 ;;
    CORRUPT*)
        # the group's pool LUN: the next run on it formats it
        lun=$("$REPO/tools/lun_pool.sh" lookup --nodes "$(tr ' ' ',' <<<"$NODES")" | sed -n 's/.* id=\([0-9]*\) .*/\1/p')
        snap=$([ -n "$lun" ] && "$REPO/tools/lun_pool.sh" snapshot "$lun" "$GROUP-rmrace-corrupt") \
            && echo "image kept: $snap" || echo "image NOT kept: no pool LUN bound to [$NODES]"
        exit 1 ;;
    *) exit 2 ;;
esac
