#!/bin/bash
# drc_probe2.sh — characterize the dir_reuse_coherency divergence at REAL timing
# by capturing BOTH nodes' dir-inode state every round (sess26/27).
#
# Unlike drc_probe.sh (test1-only cold read), this mirrors the real suite test:
# both nodes write concurrently, both SYNC, then BOTH cold-read and we compare
# their views.  sess27: the REAL failure is readdir=EXP (all names present, same
# names every round) but lookup_fail>0 (per-entry [ -e ] fails because the in-core
# DATA block holding the peer's entries is STALE — prior-round inums).  So this
# probe now triggers on lookup_fail (not just readdir count) and dumps the evict/
# consumer-refresh/iget detector timeline on the first divergence.
#   usage: tests/drc_probe2.sh [rounds] [nfiles]
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/..
SSH="$REPO/tools/mxfs_sshpass.sh"; PF=/tmp/.mxfs_pass
MNT=/mnt/shared; ROUNDS="${1:-24}"; NF="${2:-50}"
D="$MNT/.drcp"
EXP=$((4*NF))   # 2 nodes * (NF data + NF md5)
r() { local n="$1"; shift; timeout 90 bash "$SSH" "$n" "$PF" "$*" 2>&1 | grep -vE '^Warning:|^Unauthorized|^If you'; }
mkfiles='D="$1"; R="$2"; NF="$3"; for i in $(seq 1 $NF); do dd if=/dev/urandom of=$D/node${R}_f$i bs=4096 count=$(((i%8)+1)) 2>/dev/null; done; sync; for i in $(seq 1 $NF); do md5sum $D/node${R}_f$i 2>/dev/null | awk "{print \$1}" > $D/node${R}_f$i.md5; done; sync'
# view: cold-reload, then report readdir count AND per-entry lookup_fail (the real
# suite check) + a few of the failing names.  lf = count of listed names that fail
# [ -e ]; miss = first few such names.
view='D="$1"; sync; echo 3 > /proc/sys/vm/drop_caches; sleep 1; rd=$(ls $D 2>/dev/null|grep -c .); lf=0; miss=""; while IFS= read -r nm; do [ -n "$nm" ] || continue; if [ ! -e "$D/$nm" ]; then lf=$((lf+1)); [ ${#miss} -lt 80 ] && miss="$miss $nm"; fi; done < <(ls $D 2>/dev/null); ino=$(stat -c%i $D 2>/dev/null); echo "ino=$ino rd=$rd lf=$lf miss=[$miss]"'

for n in test1 test2; do r "$n" "dmesg -C" >/dev/null; done

for it in $(seq 1 "$ROUNDS"); do
    r test1 "mkdir -p $D; sync" >/dev/null
    DINO=$(r test1 "stat -c%i $D" | tr -dc '0-9')
    # concurrent same-dir create wave from both nodes
    r test1 "bash -c '$mkfiles' x $D 1 $NF" >/dev/null &
    r test2 "bash -c '$mkfiles' x $D 2 $NF" >/dev/null &
    wait
    # ensure BOTH nodes' writes are on the LUN before EITHER reads (= the barrier)
    r test1 "sync" >/dev/null; r test2 "sync" >/dev/null
    # both cold-read concurrently (temp files; subshell vars don't survive &)
    TD=$(mktemp -d)
    r test1 "bash -c '$view' x $D" > "$TD/v1" &
    r test2 "bash -c '$view' x $D" > "$TD/v2" &
    wait
    v1=$(cat "$TD/v1"); v2=$(cat "$TD/v2"); rm -rf "$TD"
    echo "round $it: mkino=$DINO  T1[$v1]  T2[$v2]"
    lf1=$(echo "$v1" | grep -oE 'lf=[0-9]+' | tr -dc 0-9)
    lf2=$(echo "$v2" | grep -oE 'lf=[0-9]+' | tr -dc 0-9)
    rd1=$(echo "$v1" | grep -oE 'rd=[0-9]+' | tr -dc 0-9)
    rd2=$(echo "$v2" | grep -oE 'rd=[0-9]+' | tr -dc 0-9)
    if [ "${lf1:-0}" != 0 ] || [ "${lf2:-0}" != 0 ] || [ "${rd1:-0}" != "$EXP" ] || [ "${rd2:-0}" != "$EXP" ]; then
        echo ">>>>> DIVERGENCE round $it: T1 rd=$rd1 lf=$lf1 | T2 rd=$rd2 lf=$lf2 exp=$EXP <<<<<"
        for n in test1 test2; do
            echo "  ===== $n evict/refresh/iget detector timeline (last 40) ====="
            r "$n" "dmesg | grep -aiE 'P26-IGET-FAIL|P26-RDDIR|P-EVICT-DONE|P-EVICT-SKIP|P15-EVICT-INCARN-ABA|P104-CONSUMER-REFRESH|P21S-EVICTSKIP|P91-FUA-SKIP|EFSBADCRC|Corruption|shutdown' | tail -40"
        done
        echo "=== probe stop (cluster left mounted) ==="
        exit 0
    fi
    r test1 "rm -rf $D; sync" >/dev/null
done
echo "=== no divergence in $ROUNDS rounds ==="
