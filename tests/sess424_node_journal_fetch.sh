#!/bin/bash
# sess424: read-only journal evidence fetch from MXFS test nodes.
# Usage: sess424_node_journal_fetch.sh <query: A|B|C|D> <host>...
# Writes raw output to tests/evidence/sess424_node_journal_0340/<host>_<query>.txt
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$REPO/tests/evidence/sess424_node_journal_0340"
mkdir -p "$OUT"
SINCE='2026-08-28 08:18'
UNTIL='2026-08-28 08:36'
PAT='P-TAUTH|superblock|can.t read|bad super|tauth|proto|PROTO|status=12|lock request failed|P-LKTIMEOUT|P34-ACQ-SLOW|hung task|blocked for more than|P-TCPDEATH|P-GOODBYE|P-DEPART|P-D512|release|RELEASE|unmount|Unmount|mount'
Q="$1"; shift
for h in "$@"; do
  case "$Q" in
    A) CMD="journalctl -k --no-pager --since '$SINCE' --until '$UNTIL' | grep -aE '$PAT'" ;;
    Abounds) CMD="echo '=== FIRST 5 ==='; journalctl -k --no-pager --since '$SINCE' --until '$UNTIL' | head -5; echo '=== LAST 5 ==='; journalctl -k --no-pager --since '$SINCE' --until '$UNTIL' | tail -5; echo '=== TOTAL LINES ==='; journalctl -k --no-pager --since '$SINCE' --until '$UNTIL' | wc -l" ;;
    B) CMD="journalctl -k --no-pager -b -1 --since '$SINCE' --until '$UNTIL' | grep -aE '$PAT'" ;;
    Bboots) CMD="journalctl --list-boots | tail -3" ;;
    C) CMD="journalctl -k --no-pager --since '$SINCE' --until '$UNTIL' | grep -aB5 -A5 'P-TAUTH-DOUBLE-GRANT'" ;;
    D) CMD="journalctl -k --no-pager --since '$SINCE' --until '$UNTIL' | grep -aoE 'P-TAUTH-[A-Z0-9-]+' | sort | uniq -c" ;;
    *) echo "unknown query $Q" >&2; exit 2 ;;
  esac
  (
    timeout 45 "$REPO/tools/mxfs_sshpass.sh" "$h" "$CMD" > "$OUT/${h}_${Q}.txt" 2>"$OUT/${h}_${Q}.err"
    echo "$?" > "$OUT/${h}_${Q}.rc"
  ) &
done
wait
for h in "$@"; do
  printf '%s rc=%s lines=%s err=%s\n' "$h" "$(cat "$OUT/${h}_${Q}.rc")" "$(wc -l < "$OUT/${h}_${Q}.txt")" "$(head -c 200 "$OUT/${h}_${Q}.err" | tr '\n' ' ')"
done
