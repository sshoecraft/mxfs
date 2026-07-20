#!/bin/bash
# repro_pm_timed.sh — instrumented concurrent same-dir storm to localize WHERE
# the time goes (FS create loop vs sync vs cross-node readdir vs barrier).
# Runs the SAME shape as posix_multi but with phase wall-clock timing, writing
# a per-node phase report to /mnt/shared (NFS/mxfs-visible) and stdout.
#
# Launched by run via SSH with: MXFS_RANK, MXFS_NODES, broker env (reuses coord.sh)
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/suite/coord.sh"
R="${MXFS_RANK:?}"; T="${MXFS_NODES:?}"
MNT="${1:-/mnt/shared}"
D="$MNT/.pmtimed"
FPN="${FPN:-100}"
[ "$R" = 1 ] && { rm -rf "$D"; mkdir -p "$D"; sync; }
now() { date +%s.%N; }
el() { echo "$(echo "$(now)-$1"|bc)"; }

coord_barrier "ready" || { echo "R$R ABORT ready-barrier"; exit 1; }

a=$(now)
for i in $(seq 1 "$FPN"); do : > "$D/n${R}_f${i}"; done
t_create=$(el "$a")

a=$(now); sync; t_sync=$(el "$a")

a=$(now); coord_barrier "created"; t_bar1=$(el "$a")

# cross-node readdir: count all files (forces reading peer's dirents)
a=$(now); cnt=$(ls "$D" | grep -c '^n[0-9]'); t_count=$(el "$a")

a=$(now); coord_barrier "counted"; t_bar2=$(el "$a")

# cross-node content read: read one peer file
peer=$(( R==1 ? 2 : 1 ))
echo "content_$R" > "$D/c_$R"; sync
a=$(now); coord_barrier "wrote"; t_bar3=$(el "$a")
a=$(now); pc=$(cat "$D/c_$peer" 2>/dev/null); t_read=$(el "$a")

printf "R%d PHASE create=%ss sync=%ss bar_created=%ss count=%ss(saw=%d) bar_counted=%ss bar_wrote=%ss peerread=%ss(got=%s)\n" \
   "$R" "$t_create" "$t_sync" "$t_bar1" "$t_count" "$cnt" "$t_bar2" "$t_bar3" "$t_read" "$pc"
