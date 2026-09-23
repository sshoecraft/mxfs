#!/bin/bash
# sess448 chain 63: dirent_publish_integrity + dirent_type_integrity (P8) MUST
# run in the same run.sh invocation as dirent_durability (P6), which stamps
# MXFS_DIRENT_WINDOW on every node.  Chain 57 ran them alone two hours after
# chain 55's P6, with 8 nodes rebooted by NDR laps in between (volatile
# journald), so those 8 reported window=0 (unverifiable => FAIL, correctly)
# while the 24 with a window measured zero hits.  budget: 240 + 60 + 60 + 12x3
# + 15 => 420 s wrapper; prep 300.  Production defaults (no arming).  Gated on
# chain 62 DONE (rig idle, production build).
cd /src/mxfs || exit 1
while ! grep -q "^DONE" tests/evidence/sess448_chain62_probe_sweep_s448e.log 2>/dev/null; do sleep 30; done
LABEL=${1:-s448f}
LOG=tests/evidence/sess448_chain63_p6p8_rows_$LABEL.log
{
  echo "=== sess448 chain63 start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') modinfo_lab=$(modinfo mxfs.ko | grep -c mxfs_iclus_relmark_lab) ==="
  timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep rc=$prc"
  if [ "$prc" -ne 0 ]; then echo "ABORT: prep"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  T0=$(date +%s); timeout 420 ./run.sh 32 caw dirent_durability dirent_publish_integrity dirent_type_integrity; echo "STAGE rows rc=$? wall=$(( $(date +%s) - T0 ))s"
  ./showstat.sh 32 caw 2>/dev/null | grep -a 'dirent_\|Total' | cut -c1-160
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
