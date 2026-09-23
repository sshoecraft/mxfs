#!/bin/bash
# sess442 chain 29 (0.48.1): K own-log replay ENFORCED via the escrowed certificate + manifest pointer (chain 28 s442a: enforcement-off ATOMIC-SKIPped every dirty K txn). Same legs as chain 28.
# Original chain-28 header: build 0.48.1 (item 5d fixes from the design-consult code review +
# chain 27: bootstrap-owner fence-time manifests collected from the on-disk
# CAW table (chain 27 s441d refused 7/31 tokened slices on NO_CAW manifests);
# typed K refusal only; norecovery refused on an adopted slice; own key
# required at reconcile; barrier stops at the first terminal slice under a
# bootstrap term; no clean slot release under an unfinished term; item 5e
# same-boot RESUME (peek/identity/dirty-scan/setup/run + adopt_resume) with
# the TEST-ONLY mxfs.bootstrap_inject fail points; chk_mxfs --clear-bootstrap),
# deploy, then:
#   prep                    32/32 regression gate
#   bootstrap_full_restart  the item-5 end-to-end (chain 27 shape, now with manifests)
#   prep
#   bootstrap_resume 3      K_CLAIMED resume (re-take K)
#   prep
#   bootstrap_resume 1      escrow NONE resume (adopt fresh)
#   prep
#   bootstrap_resume 2      PREPARED + guard resume (re-prepare + claim)
#   prep2
# Budgets: build ~3 min (bound 500), tools 120, prep 77-157 s (bound 300),
# full_restart ~1000 s (bound 1080), resume ~1100 s (bound 1260) x3.
cd /src/mxfs || exit 1
# sess442: queued behind chain 28 — wait for its DONE before touching mxfs.ko
while ! grep -q "^DONE" tests/evidence/sess442_chain28_0480_bootstrap_resume_s442a.log 2>/dev/null; do sleep 30; done
LABEL=${1:-s442b}
LOG=tests/evidence/sess442_chain29_0481_bootstrap_resume_$LABEL.log
EV=tests/evidence/sess442_chain29_0481_bootstrap_resume_$LABEL
mkdir -p "$EV"
{
  echo "=== sess442 chain29 start $(date -u +%FT%TZ) ==="
  OLD=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  timeout 500 make modules > "$EV/build.txt" 2>&1; brc=$?
  timeout 120 make tools >> "$EV/build.txt" 2>&1; trc=$?
  NEW=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  echo "BUILD_RC=$brc TOOLS_RC=$trc VERSION=$(cat VERSION) sv_old=$OLD sv_new=$NEW"
  echo "build errors=$(grep -c 'error:\|ERROR:' "$EV/build.txt")"
  grep -a 'error:\|ERROR:' "$EV/build.txt" | cut -c1-200 | head -10
  if [ "$brc" -ne 0 ] || [ "$trc" -ne 0 ] || [ "$NEW" = "$OLD" ]; then echo "ABORT: build failed or srcversion unchanged"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep rc=$prc"
  if [ "$prc" -ne 0 ]; then echo "ABORT: prep failed on $(cat VERSION)"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 1080 tests/bootstrap_full_restart.sh $LABEL 32 test1; echo "STAGE bootstrap_full_restart rc=$?"
  for pt in 3 1 2; do
    timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep_before_resume$pt rc=$prc"
    if [ "$prc" -ne 0 ]; then echo "ABORT: prep failed before resume $pt"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
    timeout 1260 tests/bootstrap_resume.sh ${LABEL}p$pt $pt 32 test1; echo "STAGE bootstrap_resume$pt rc=$?"
  done
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
