#!/bin/bash
# drc_phantom_diag.sh — ONE clean-reboot 8/tcp dir_reuse run; on the first
# failing round, grep EACH node's FULL fail-dmesg for the decisive
# phantom-vs-read-staleness signatures and correlate them with the lost dirent:
#   P42-STALEEX-SERVE   — fast-path served cached dir-EX with held=0 (PHANTOM:
#                         a peer holds the real grant while we RMW) => broken
#                         mutual exclusion; read-side evict CANNOT fix it.
#   P51-HANDOFF-UNDERFIRE — grant token advanced (lock changed hands) but the
#                         handoff bit was FALSE => fast-path EX served an
#                         UN-REFRESHED base => pure READ-staleness; the
#                         read/acquire epoch-evict is the right fix.
#   MX-DOUBLEGRANT / P-STALEMASTER-GRANT — master-level serialization break.
#   P63-FASTEX-HANDOFF / P-FASTEX-EPOCH — handoff detector DID fire (refreshed).
# Usage: tests/tcp/drc_phantom_diag.sh [modargs]
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd); cd "$REPO"
MODARGS="${1:-}"
SSH=tools/mxfs_sshpass.sh; PASS=/tmp/.mxfs_pass
NODES="test1 test2 test3 test4 test5 test6 test7 test8"
flt() { grep -vE '^Warning:|^Unauthorized|^If you'; }

echo "########## drc_phantom_diag reboot @ $(date -u +%T) modargs=[$MODARGS] ##########"
for d in $NODES; do virsh -c qemu:///system destroy $d >/dev/null 2>&1; done
sleep 3
for d in $NODES; do virsh -c qemu:///system start $d >/dev/null 2>&1; done
for t in $(seq 1 50); do
  ok=1
  for n in $NODES; do timeout 6 $SSH $n $PASS true 2>/dev/null || ok=0; done
  [ $ok = 1 ] && break
  sleep 3
done
sleep 20
for n in $NODES; do timeout 8 $SSH $n $PASS "rm -f /root/drc_fail_r*.dmesg /root/drc_failverify_r*.dmesg /root/drc_failrounds.txt; dmesg -C" >/dev/null 2>&1; done

OUT=$(env MXFS_EXTRA_MODARGS="$MODARGS" ./run.sh 8 tcp dir_reuse_coherency 2>&1)
res=$(echo "$OUT" | flt | grep -E 'dir_reuse_coherency' | tail -1)
echo "RESULT: $res"
if echo "$res" | grep -q PASS; then echo "PASSED — no fail to diagnose"; exit 0; fi

echo "===== PHANTOM DIAGNOSIS (full fail-dmesg grep, all nodes) ====="
for n in $NODES; do
  echo "----- $n -----"
  timeout 25 $SSH $n $PASS '
    FR=$(ls -1 /root/drc_fail_r*.dmesg 2>/dev/null | sed -E "s/.*_r([0-9]+)_.*/\1 &/" | sort -n | head -1 | cut -d" " -f2-)
    [ -z "$FR" ] && FR=$(ls -1 /root/drc_failverify_r*.dmesg 2>/dev/null | sed -E "s/.*_r([0-9]+)_.*/\1 &/" | sort -n | head -1 | cut -d" " -f2-)
    echo "[snapshot=$FR]"
    echo "[failrounds]"; head -2 /root/drc_failrounds.txt 2>/dev/null
    [ -z "$FR" ] && exit 0
    echo "[lost name (RDMISS)]"; grep -aoE "missing_from_readdir=\[[^]]*\]" "$FR" | tail -1
    echo "[P42-STALEEX-SERVE count]";        grep -ac "P42-STALEEX-SERVE" "$FR"
    echo "[P51-HANDOFF-UNDERFIRE count]";     grep -ac "P51-HANDOFF-UNDERFIRE" "$FR"
    echo "[MX-DOUBLEGRANT count]";            grep -ac "MX-DOUBLEGRANT" "$FR"
    echo "[P-STALEMASTER-GRANT count]";       grep -ac "P-STALEMASTER-GRANT" "$FR"
    echo "[P63-FASTEX-HANDOFF count]";        grep -ac "P63-FASTEX-HANDOFF" "$FR"
    echo "[P-FASTEX-EPOCH count]";            grep -ac "P-FASTEX-EPOCH" "$FR"
    echo "[P42 samples]";  grep -a "P42-STALEEX-SERVE" "$FR" | tail -3
    echo "[P51-UF samples]"; grep -a "P51-HANDOFF-UNDERFIRE" "$FR" | tail -3
    echo "[P-DGEX ino=131 total]";      grep -ac "P-DGEX ino=131 " "$FR"
    echo "[P-DGEX ino=131 handoff=1]";  grep -a "P-DGEX ino=131 " "$FR" | grep -c "handoff=1"
    echo "[P-DGEX ino=131 handoff=0]";  grep -a "P-DGEX ino=131 " "$FR" | grep -c "handoff=0"
    echo "[P-DGEX ino=131 active_b4=1 (re-grant while prior ACTIVE)]"; grep -a "P-DGEX ino=131 " "$FR" | grep -c "active_b4=1"
    echo "[P-DGEX-NEWSLOT ino=131 (eviction under-fire)]"; grep -ac "P-DGEX-NEWSLOT ino=131 " "$FR"
    echo "[P64-MASTER-HANDOFF ino=131]"; grep -ac "P64-MASTER-HANDOFF ino=131 " "$FR"
    echo "[P-DGEX ino=131 handoff=0 samples]"; grep -a "P-DGEX ino=131 " "$FR" | grep "handoff=0" | tail -4
    echo "[P54-KEEPGUARD-STALE count]";   grep -ac "P54-KEEPGUARD-STALE" "$FR"
    echo "[P54-MEPZERO count]";           grep -ac "P54-MEPZERO" "$FR"
    echo "[P28-ADDNAME-EPOCHSTALE count (refreshes that DID fire)]"; grep -ac "P28-ADDNAME-EPOCHSTALE" "$FR"
    echo "[P22-FREESLOT-STALE count]";    grep -ac "P22-FREESLOT-STALE" "$FR"
    echo "[P28E total (coherent platter compare reached)]"; grep -ac "P28E ino=131 " "$FR"
    echo "[P28E pcur=0 (in-core daddr NOT a valid dir block = EXTENT-MAP DIVERGENCE)]"; grep -a "P28E ino=131 " "$FR" | grep -c "pcur=0"
    echo "[P28E pcur=1 diff=1 (content stale, refreshed)]"; grep -a "P28E ino=131 " "$FR" | grep -c "pcur=1 .*diff=1"
    echo "[P28C-STALE count (content-diff invalidate+reread fired)]"; grep -ac "P28C-STALE" "$FR"
    echo "[P54-DOUBLEMAP count (dir-block double-alloc about to zero live data)]"; grep -ac "P54-DOUBLEMAP" "$FR"
    echo "[P54-NOTEX-MODIFY count (dirent placed while NOT holding dir EX = serialization hole)]"; grep -ac "P54-NOTEX-MODIFY" "$FR"
    echo "[P54-INAIL-DESTAGED count (in-AIL destaged-zombie now FUA-compared = residual clobber site)]"; grep -ac "P54-INAIL-DESTAGED" "$FR"
    echo "[P28C-STALE (coherent compare CAUGHT+refreshed a stale block) count]"; grep -ac "P28C-STALE" "$FR"
    echo "[P54-NOTEX-MODIFY samples]"; grep -a "P54-NOTEX-MODIFY" "$FR" | tail -5
    echo "[P54-DOUBLEMAP samples]"; grep -a "P54-DOUBLEMAP" "$FR" | tail -4
    echo "[P28E pcur=0 samples]"; grep -a "P28E ino=131 " "$FR" | grep "pcur=0" | tail -4
    echo "[P54-KEEPGUARD-STALE samples]"; grep -a "P54-KEEPGUARD-STALE" "$FR" | tail -4
    echo "[P54-MEPZERO samples]";         grep -a "P54-MEPZERO" "$FR" | tail -3
  ' 2>/dev/null | flt
done
echo "===== END PHANTOM DIAGNOSIS @ $(date -u +%T) ====="
