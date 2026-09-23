#!/bin/bash
# fleet_probe_sweep.sh — read-only kernel-log probe census across the fleet.
# One ssh per node, ONE bounded journalctl read (--since), all patterns grepped
# from that one capture; per-node output + rc files (the unkillable-wedge rule), parallel, 25 s
# per node.  sess448 lesson: 9 x `journalctl -k` per node timed out 24/32 nodes
# under a running chain — read the journal once.
#
# Usage: tests/fleet_probe_sweep.sh <outdir> <since e.g. '-3h' or '2026-08-29 12:00'> [nodes=32] pattern...
# Output: $outdir/sweep.txt (table + fleet sums + first 3 verbatim hits per
# pattern), per-node raw in $outdir/nodeN.txt, exit 1 if fewer than all nodes
# answered (coverage is part of the evidence).
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd); cd "$REPO"
OUT=${1:?outdir}; SINCE=${2:?since}; N=${3:-32}; shift 3
PATS=("$@"); [ ${#PATS[@]} -gt 0 ] || { echo "no patterns" >&2; exit 2; }
mkdir -p "$OUT"; SSH=tools/mxfs_sshpass.sh
PL=""; for p in "${PATS[@]}"; do PL="$PL '$p'"; done
for i in $(seq 1 "$N"); do
  ( timeout 25 $SSH test$i "J=\$(journalctl -k --since '$SINCE' --no-pager 2>/dev/null); echo BOOT=\$(uptime -s); echo SV=\$(cat /sys/module/mxfs/srcversion 2>/dev/null); for p in $PL; do echo \"COUNT \$p=\$(printf '%s\n' \"\$J\" | grep -ac \"\$p\")\"; printf '%s\n' \"\$J\" | grep -a \"\$p\" | head -3 | cut -c1-260 | sed 's/^/HIT /'; done" > "$OUT/node$i.txt" 2>&1; echo $? > "$OUT/rc$i" ) &
done; wait
# sess451: `ans` must be computed OUTSIDE the `{ } | tee` group — a pipeline
# runs its left side in a subshell, so the count never reached the exit test
# below (chain 62: "line 29: ans: unbound variable", rc=1 on a good sweep).
ans=0
for i in $(seq 1 "$N"); do rc=$(cat "$OUT/rc$i"); [ "$rc" = 0 ] && ans=$((ans+1)); done
{
  echo "=== fleet_probe_sweep since='$SINCE' nodes=$N $(date -u +%FT%TZ) ==="
  for i in $(seq 1 "$N"); do rc=$(cat "$OUT/rc$i"); echo "test$i rc=$rc $(grep -a '^BOOT=\|^SV=' "$OUT/node$i.txt" | tr '\n' ' ') $(grep -a '^COUNT ' "$OUT/node$i.txt" | sed 's/^COUNT //' | tr '\n' ' ')"; done
  echo "answered=$ans/$N"
  for p in "${PATS[@]}"; do s=0; for i in $(seq 1 "$N"); do c=$(grep -a "^COUNT $p=" "$OUT/node$i.txt" | sed 's/.*=//' | tr -dc '0-9'); [ -n "$c" ] && s=$((s+c)); done; echo "SUM $p=$s"; done
  for p in "${PATS[@]}"; do grep -ah "^HIT .*$p" "$OUT"/node*.txt | head -3; done
} | tee "$OUT/sweep.txt"
[ "$ans" -eq "$N" ] || exit 1
