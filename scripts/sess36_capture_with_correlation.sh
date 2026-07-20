#!/bin/bash
# Sess36: capture + cross-node chronology correlation for the bug
#
# Wraps sess35_capture.sh and adds a post-processing step that:
# 1. Identifies the test's parent dir ino and concurrent_mkdir ino
# 2. Builds a chronology of events for those inos across both nodes
# 3. Categorizes the run as: clean, cache-divergence, or catastrophic
# 4. Highlights events that explain WHY the bug fired
#
# Per RULE 3.

set -u
SCRIPTS=/src/mxfs/scripts
OUT=/src/mxfs/notes/sess36_dmesg

mkdir -p "$OUT"
"$SCRIPTS/sess35_capture.sh" 2 2>&1 | tail -5

LATEST=$(ls -tr /home/steve/.mxfs/results | tail -1)
H17_LOG="/home/steve/.mxfs/results/$LATEST/test_concurrent_mkdir/node1.log"

echo
echo "==================================================="
echo "Run $LATEST classification"
echo "==================================================="
BEFORE=$(grep 'BEFORE drop_caches' "$H17_LOG" 2>/dev/null | grep -oE '=[0-9]+' | tr -d =)
AFTER=$(grep 'AFTER drop_caches' "$H17_LOG" 2>/dev/null | grep -oE '=[0-9]+' | tr -d =)
echo "BEFORE drop_caches: $BEFORE"
echo "AFTER  drop_caches: $AFTER"
if [ "$BEFORE" = "100" ] && [ "$AFTER" = "100" ]; then
  CAT="CLEAN (no bug this run)"
elif [ "$BEFORE" -lt "100" ] && [ "$AFTER" = "100" ]; then
  CAT="CACHE-DIVERGENCE (test1's cache stale, drop_caches recovers)"
elif [ "$AFTER" -lt "100" ]; then
  CAT="CATASTROPHIC ($((100-AFTER)) entries actually missing from disk)"
else
  CAT="UNKNOWN ($BEFORE/$AFTER)"
fi
echo "Classification: $CAT"

echo
echo "==================================================="
echo "Concurrent_mkdir ino on each node"
echo "==================================================="
for n in 1 2; do
  log="/src/mxfs/notes/sess35_dmesg/test${n}.log"
  [ -f "$log" ] || continue
  pick=$(grep -E 'dialloc PICK ino=[0-9]+ agno=[0-9]+ parent=131' "$log" | tail -1 | grep -oE 'ino=[0-9]+' | head -1)
  echo "test${n} dialloc PICK with parent=131: $pick"
done

echo
echo "==================================================="
echo "Parent dir (ino 131) chronology — WHO acquired when"
echo "==================================================="
{
  for n in 1 2; do
    log="/src/mxfs/notes/sess35_dmesg/test${n}.log"
    [ -f "$log" ] || continue
    grep -E 'ino=131[^0-9].*ACQ-FRESH|ino=131[^0-9].*FAST-PATH|ino=131[^0-9].*BAST_RELEASE|ino=131[^0-9].*GRANT-WAIT-OK' "$log" \
      | sed "s|^|test${n}: |"
  done
} | sort -t: -k2

echo
echo "==================================================="
echo "If catastrophic: did either node skip ino 131 lock?"
echo "==================================================="
for n in 1 2; do
  log="/src/mxfs/notes/sess35_dmesg/test${n}.log"
  [ -f "$log" ] || continue
  evt_count=$(grep -cE 'ino=131[^0-9]' "$log")
  echo "test${n}: $evt_count events for ino 131"
done

echo
echo "==================================================="
echo "Save dmesg snapshots for sess36 reference"
echo "==================================================="
cp /src/mxfs/notes/sess35_dmesg/test1.log "$OUT/${LATEST}_test1.log"
cp /src/mxfs/notes/sess35_dmesg/test2.log "$OUT/${LATEST}_test2.log"
echo "Saved to $OUT/${LATEST}_test{1,2}.log"
