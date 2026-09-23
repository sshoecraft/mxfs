#!/bin/bash
# sess439 chain 22: build 0.45.0 (whole-cluster-restart build item 4:
# self-succession under the register-before-ledger ruling — REGISTER(rk=old,
# sark=new) on our own nexus, ledger entry with succeeds{}, prover consumes
# it as SELF_SUCCESSION_DONE when the old key is absent), deploy, verify:
#   prep             must mount 32/32 (regression gate for item 3 + 4)
#   remount_refused  lone_mount_create remount_refused: a SAME-BOOT dirty
#                    remount is still refused (swap(K,K) proves same boot ->
#                    reuse, then the dirty-slice rule applies) — must PASS
#   nosurv           no_survivor_crash_replay: all 32 destroyed with fsynced
#                    payload; test1 reboots (new boot_uuid), must self-succeed
#                    (P305-PR-PREDECESSOR-BOOT-REPLACED), mount unattended,
#                    and replay 31 foreign + its own predecessor slice under
#                    SELF_SUCCESSION_DONE / PREEMPT_ABORT_DONE certificates
# Gated on chain 21 DONE.  Budgets: build ~3 min (bound 500), tools 120, prep
# 66-95 s (bound 300), remount_refused (bound 100, sess433), nosurv ~800 s
# (bound 840, harness header), prep after nosurv (bound 300).
cd /src/mxfs || exit 1
LABEL=${1:-s439d}
LOG=tests/evidence/sess439_chain22_0450_self_succession_verify_$LABEL.log
EV=tests/evidence/sess439_chain22_0450_self_succession_verify_$LABEL
GATE=tests/evidence/sess439_chain21_fln_rerun_0440_s439c.log
SSH="tools/mxfs_sshpass.sh"
mkdir -p "$EV"
{
  echo "=== sess439 chain22 start $(date -u +%FT%TZ) ==="
  for t in $(seq 1 900); do grep -q '^DONE' "$GATE" 2>/dev/null && break; sleep 10; done
  grep -q '^DONE' "$GATE" || { echo "ABORT: chain21 not DONE"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  echo "gate passed at $(date -u +%FT%TZ) (iter $t)"
  OLD=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  timeout 500 make modules > "$EV/build.txt" 2>&1; brc=$?
  timeout 120 make tools >> "$EV/build.txt" 2>&1; trc=$?
  NEW=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  echo "BUILD_RC=$brc TOOLS_RC=$trc VERSION=$(cat VERSION) sv_old=$OLD sv_new=$NEW"
  grep -c 'error:' "$EV/build.txt" | sed 's/^/build errors=/'
  grep -a 'warning:' "$EV/build.txt" | grep -v 'compiler differs\|xfs_platform.h\|xfs_fs_report_error' | cut -c1-200 | head -20
  if [ "$brc" -ne 0 ] || [ "$trc" -ne 0 ] || [ "$NEW" = "$OLD" ]; then echo "ABORT: build failed or srcversion unchanged"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep rc=$prc"
  if [ "$prc" -ne 0 ]; then echo "ABORT: prep failed on 0.45.0"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 100 tests/lone_mount_create.sh ${LABEL}_refused test1 32 remount_refused; echo "STAGE remount_refused rc=$?"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  T0=$(date -u '+%Y-%m-%d %H:%M:%S')
  timeout 840 tests/no_survivor_crash_replay.sh $LABEL 32 test1; echo "STAGE nosurv rc=$?"
  timeout 40 $SSH test1 "journalctl -k -b --no-pager | grep -a 'P305\|P-PRKEY\|P236-FENCEKIND\|P238-FENCE-SELF\|P238-FENCE-ABSENT\|SELF_SUCCESSION\|P-BOOT-STATE' | cut -c1-230 | head -40" > "$EV/nosurv_test1.txt" 2>&1
  echo "--- test1 nosurv lines: $(grep -ac 'P305\|P-PRKEY\|P236\|P238\|P-BOOT' "$EV/nosurv_test1.txt")"; grep -a 'P305-PR-PREDECESSOR\|P305-PR-SELF\|P305-PR-HOST\|SELF_SUCCESSION\|P238-FENCE-ABSENT\|P-PRKEY-PUBLISHED' "$EV/nosurv_test1.txt" | head -12
  sleep 60
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep3 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
