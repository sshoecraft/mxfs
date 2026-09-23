#!/bin/bash
# sess475 chain 118: D-0133 NON-COUNTER arm re-verification on the current
# freeze — tests/d0133_sb_mutation_gate.sh (0.29.2 mxfs_sb_mutation_refuse:
# every reachable runtime whole-SB producer refused / absent / pre-empted, the
# counter-only unmount sync allowed).  The sess420 rerun after the harness
# fixups (tests/evidence/20260828T073029Z_d0133gate) left an EMPTY evidence
# dir, so the fixed harness has never produced a verdict; this lap does, on the
# same build the counter arm (chain 116 v2) is verified on.
# budget: prep 300 (95-118 s measured); gate 100 (harness bound ~80 s).
set -u
cd /src/mxfs || exit 1
LABEL=${1:-s475a}
GATE=${GATE:-tests/evidence/sess475_chain117_d0532_s475a.log}
LOG=tests/evidence/sess475_chain118_d0133gate_$LABEL.log
PROD_KO=${PROD_KO:?PROD_KO required}
PROD_SV=${PROD_SV:?PROD_SV required}
NODE=${NODE:-test5}
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do sleep 30; done
lap() { local b="$1" l="$2"; shift 2; local T0=$(date +%s); timeout "$b" "$@"; echo "STAGE $l rc=$? wall=$(( $(date +%s) - T0 ))s"; }
install_ko() {
  [ -f "$1" ] || { echo "install_ko: missing $1"; return 1; }
  cp "$1" mxfs.ko || return 1
  for t in mkfs_mxfs chk_mxfs resize_mxfs fua_verify; do [ -f "$(dirname "$1")/tools/$t" ] && cp "$(dirname "$1")/tools/$t" tools/$t; done
  local sv; sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  echo "STAGE install_prod sv=$sv want=$2"; [ "$sv" = "$2" ]
}
{
  echo "=== sess475 chain118 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) NODE=$NODE ==="
  install_ko "$PROD_KO" "$PROD_SV" || { echo "ABORT: prod install"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  lap 300 "prep" ./run.sh 32 caw prep_cluster
  lap 100 "d0133_sb_mutation_gate $NODE" tests/d0133_sb_mutation_gate.sh "$LABEL" "$NODE"
  echo "RESULTS: $(grep -a '^  FAIL\|fails=' "$LOG" | tr '\n' ';')"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
