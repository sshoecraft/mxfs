#!/bin/bash
# drc4_repro.sh — fast N-node standalone reproducer for the dir_reuse_coherency
# readdir-ENUMERATION miss seen at 4-node TCP (sess59): a peer-written+synced
# entry is absent from a cold-cache readdir (399/400) but is lookup-able
# (lookup_fail=0), on ALL nodes incl. the creator.  No MQTT coord — test1 owns
# the dir lifecycle, all N nodes concurrently write NF data+NF md5 each round,
# a wall barrier (ssh `wait` + sync), then EVERY node cold-reads (drop_caches)
# and checks readdir-count + per-entry lookup.  On the FIRST round any node is
# short, dumps the dir-inode-scoped reload/leaf/evict probes from ALL nodes
# BEFORE the dmesg ring rolls (the EVICT-RING storm is large, so we clear dmesg
# per-round and grep by the dir inode number).
#
# Usage: tests/tcp/drc4_repro.sh [N_NODES] [NFILES] [ROUNDS]
#   default: 4 nodes, 50 files/node/wave, 24 rounds (matches the suite test).
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"; PF=/tmp/.mxfs_pass
MNT=/mnt/shared
N="${1:-4}"; NF="${2:-50}"; ROUNDS="${3:-24}"
D="$MNT/.drc4"
EXP=$(( 2 * N * NF ))
mapfile -t NODES < <(seq 1 "$N" | sed 's/^/test/')
N1="${NODES[0]}"

r() { local n="$1"; shift; timeout 90 bash "$SSH" "$n" "$PF" "$*" 2>&1 | grep -vE '^Warning:|^Unauthorized|^If you'; }

# write-wave body: NF data files (1..8 blocks) then NF md5 sidecars; sync after each.
mkfiles='D="$1"; R="$2"; NF="$3";
  for i in $(seq 1 $NF); do dd if=/dev/urandom of=$D/node${R}_f$i bs=4096 count=$(((i%8)+1)) 2>/dev/null; done; sync;
  for i in $(seq 1 $NF); do md5sum $D/node${R}_f$i 2>/dev/null | awk "{print \$1}" > $D/node${R}_f$i.md5; done; sync'

# cold-read verify body: drop_caches, readdir count, list names missing from readdir,
# and per-listed-name lookup failures.
verify='D="$1"; N="$2"; NF="$3";
  sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null; sleep 1;
  ls "$D" 2>/dev/null | grep -c . | sed "s/^/RD=/";
  ls "$D" 2>/dev/null | sort > /tmp/got.$$;
  for rr in $(seq 1 $N); do for ii in $(seq 1 $NF); do echo node${rr}_f${ii}; echo node${rr}_f${ii}.md5; done; done | sort > /tmp/exp.$$;
  echo -n "RDMISS=["; comm -13 /tmp/got.$$ /tmp/exp.$$ | tr "\n" " "; echo "]";
  lf=0; while IFS= read -r nm; do [ -e "$D/$nm" ] || lf=$((lf+1)); done < /tmp/got.$$; echo "LF=$lf";
  rm -f /tmp/got.$$ /tmp/exp.$$'

echo "drc4_repro: N=$N NF=$NF ROUNDS=$ROUNDS EXP=$EXP nodes=${NODES[*]}"

for it in $(seq 1 "$ROUNDS"); do
    for n in "${NODES[@]}"; do r "$n" "dmesg -C" >/dev/null 2>&1 & done; wait
    r "$N1" "mkdir -p $D; sync" >/dev/null
    DINO=$(r "$N1" "stat -c%i $D" | tr -dc '0-9')

    # concurrent write wave from all nodes
    for idx in "${!NODES[@]}"; do
        n="${NODES[$idx]}"; rank=$((idx+1))
        r "$n" "bash -c '$mkfiles' x $D $rank $NF" >/dev/null &
    done
    wait
    for n in "${NODES[@]}"; do r "$n" "sync" >/dev/null & done; wait

    # every node cold-reads and verifies — CONCURRENTLY (matches the suite's
    # coord_barrier release: all nodes drop_caches+readdir at the same instant,
    # during peak reload churn).  Sequential reads let the dir inode settle and
    # mask the transient miss.
    tmpd=$(mktemp -d)
    for n in "${NODES[@]}"; do
        ( r "$n" "bash -c '$verify' x $D $N $NF" > "$tmpd/$n" 2>&1 ) &
    done
    wait
    short=0; report=""
    for n in "${NODES[@]}"; do
        out=$(cat "$tmpd/$n")
        rd=$(echo "$out"  | sed -n 's/^RD=//p'   | tr -dc 0-9)
        lf=$(echo "$out"  | sed -n 's/^LF=//p'   | tr -dc 0-9)
        miss=$(echo "$out"| sed -n 's/^RDMISS=\[//p' | sed 's/\]$//')
        eval "miss_$n=\"\$miss\""
        report="$report  $n: readdir=${rd:-?}/$EXP lookup_fail=${lf:-?} rdmiss=[$miss]\n"
        { [ "${rd:-0}" -lt "$EXP" ] || [ "${lf:-0}" -gt 0 ]; } && short=1
    done
    rm -rf "$tmpd"
    echo "round $it: ino=$DINO"
    echo -e "$report"

    if [ "$short" = 1 ]; then
        echo ">>>>> FAIL round $it ino=$DINO <<<<<"
        # CLASSIFY the miss (no writes between): for each node's missing names,
        # is the entry lookup-able (stat) and does a SECOND readdir show it?
        #   lookup OK + re-readdir shows  => transient stale-block read (reader-side)
        #   lookup OK + re-readdir misses => persistent enumeration miss
        #   lookup ENOENT                 => durable loss / leaf-hash hole
        for n in "${NODES[@]}"; do
            eval "nm=\"\$miss_$n\""
            [ -z "$nm" ] && continue
            echo "  ===== $n classify missing=[$nm] ====="
            r "$n" "for f in $nm; do
                if [ -e \"$D/\$f\" ]; then st=LOOKUP_OK; else st=LOOKUP_ENOENT; fi
                if ls \"$D\" 2>/dev/null | grep -qx \"\$f\"; then rr=REREAD_SHOWS; else rr=REREAD_MISS; fi
                echo \"    \$f: \$st \$rr\"
            done"
        done
        for n in "${NODES[@]}"; do
            echo "  ===== $n probes (ino=$DINO) ====="
            r "$n" "dmesg | grep -aE 'ino=$DINO' | grep -aE 'EVICT-RING|P62-RELOAD|P56-RELOAD|P-SFDIR|P31E|P54-DIRBLK|P119-NONEX|leaf_read_verify|P25-RESURRECT|RELFLUSH|FMTREVERT|SPLIT|DATAINIT' | tail -40"
        done
        echo "=== probe stop (cluster left mounted for inspection) ==="
        exit 0
    fi
    r "$N1" "rm -rf $D; sync" >/dev/null
done
echo "=== no failure in $ROUNDS rounds ==="
