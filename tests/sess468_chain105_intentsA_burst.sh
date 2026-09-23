#!/bin/bash
# sess468 chain 105: frozen production 0.64.7 = 0.64.6 + fix shape A
# (D-FOREIGN-SLICE-INTENTS-ABANDONED, ruling Q1): xfs_inactive installs the
# replay certificate from its completed raw EX grant result before the first
# truncate/ifree dirty and revokes it by exact identity at INACT-EXREL
# (xfs/xfs_mxfs_dlm.c mxfs_dlm_inactive_authority_{install,revoke},
# xfs/xfs_inode.c P-INACT-CERT).
#
# Measurement: the intents verifier's burst arm (a node dies inside the EFD
# hold with fragmented-file rm transactions in its slice) twice, with a clean
# arm between them.  Fix shapes A+B together must turn the victim's rm
# transactions from POLICY-REFUSED (reason=1, classless=41 on 0.63.0) into
# tokened-and-admitted, so the census stands alone: the ruling's assertion
# set is policy_refused_txns==0, classless_images==0,
# authority_mismatch_images==0, atomic_skipped_txns==0, undischarged_EFD
# census>0, quarantine reason == 8 ONLY.  Producer-side proof on the victim:
# P-INACT-CERT installed=1 for the rm'd inos, P-IUNLINK-AGCLASS, and
# P239-OWNAUTH-NONDUR absent for blft 4 with comm kworker.
# budget: prep 300 (80-117 s measured); burst/clean 180 (chain 93 measured
# fails=0 laps inside 180).
set -u
cd /src/mxfs || exit 1
LABEL=${1:-s468d}
GATE=${GATE:-tests/evidence/sess468_chain104_joiner_s468c.log}
LOG=tests/evidence/sess468_chain105_intentsA_$LABEL.log
PROD_KO=${PROD_KO:-/src/mxfs/tests/evidence/sess468_frozen_0647/mxfs.ko}
PROD_SV=${PROD_SV:?PROD_SV required}
SSH=tools/mxfs_sshpass.sh
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do sleep 30; done
lap() { # <budget_s> <label> <cmd...>
  local b="$1" l="$2"; shift 2
  local T0=$(date +%s)
  timeout "$b" "$@"; echo "STAGE $l rc=$? wall=$(( $(date +%s) - T0 ))s"
}
# sess479: a failed prep invalidates every arm below it.  Chain 116 s479a ran
# all four of its arms after ./run.sh had refused to prep the fleet (host
# preflight rc=3) and scored the unprepped cluster as twelve FAILs — which
# reads exactly like a regression in the build under test.  Stop instead of
# scoring: an unprepped fleet measures nothing.
prep_arm() { # <label>
  local l="$1" T0=$(date +%s) rc
  timeout 300 ./run.sh 32 caw prep_cluster; rc=$?
  echo "STAGE $l rc=$rc wall=$(( $(date +%s) - T0 ))s"
  [ "$rc" = 0 ] && return 0
  echo "ABORT $l: prep_cluster rc=$rc — no arm can yield a verdict; scoring one would be fabricating evidence."
  echo "DONE $(date -u +%FT%TZ)"
  exit 2
}
install_ko() { # <ko> <sv> <label>
  local ko="$1" sv="$2" l="$3" t rc=1
  if [ -f "$ko" ] && [ "$(modinfo "$ko" | awk '/srcversion/{print $2}')" = "$sv" ]; then
    cp "$ko" mxfs.ko; rc=$?
    for t in "$(dirname "$ko")"/tools/*; do
      [ -f "$t" ] && [ -x "$t" ] && file "$t" | grep -q ELF && cp "$t" tools/
    done
  fi
  echo "STAGE install_$l rc=$rc sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') lab=$(modinfo mxfs.ko | grep -c mxfs_iclus_relmark_lab) from=$ko"
  return $rc
}
census() { # <tag>: victim/replayer evidence from the latest intents evidence dir
  local D=$(ls -dt tests/evidence/*_intents_$1 2>/dev/null | head -1)
  echo "census $1 dir=$D"
  [ -n "$D" ] || return 0
  echo "  P-INACT-CERT: $(grep -ah 'P-INACT-CERT ' "$D"/dmesg_*.txt 2>/dev/null | grep -ao 'installed=[01] try=[0-9]*' | sort | uniq -c | tr '\n' ';')"
  echo "  P-INACT-CERT-REVOKE-MISS: $(grep -ahc 'P-INACT-CERT-REVOKE-MISS' "$D"/dmesg_*.txt 2>/dev/null | paste -sd+ | bc 2>/dev/null)"
  echo "  P-IUNLINK-AGCLASS: $(grep -ahc 'P-IUNLINK-AGCLASS ' "$D"/dmesg_*.txt 2>/dev/null | paste -sd+ | bc 2>/dev/null)"
  echo "  NONDUR blft4 kworker: $(grep -ah 'P239-OWNAUTH-NONDUR' "$D"/dmesg_*.txt 2>/dev/null | grep -a 'blft=4' | grep -ac 'comm=kworker')"
  echo "  TOKENSUM: $(grep -ah 'P227-TOKENSUM' "$D"/dmesg_*.txt 2>/dev/null | grep -ao 'buf_items=[0-9]* tokened=[0-9]*\|ino=[0-9]* iclus=[0-9]* classless=[0-9]*\|classless=[0-9]*\|wapply=[0-9]* redundant=[0-9]* wskip=[0-9]*\|dino_none=[0-9]* dino_agsib=[0-9]*' | sort | uniq -c | tr '\n' ';')"
  echo "  refusal: $(grep -ah 'P227-FR-ATOMIC-SKIP\|POLICY-REFUSED\|reason=' "$D"/dmesg_*.txt 2>/dev/null | grep -ao 'sbreason=[0-9]*\|reason=[0-9]*\|domain=[0-9]*' | sort | uniq -c | tr '\n' ';')"
  # sess476 (0.64.34 CANCEL authority tokens): every CANCEL record now carries a
  # trailer — P227-TOKEN lines for cancelled blocks show blft=0 with a class;
  # P-FR-CANCEL-PASS1 is the end-of-pass-1 decision (txns parked / refused /
  # cancel entries kept vs suppressed / put_miss), P-FR-PASS-VERDICT-MISMATCH
  # and P-FR-CANCEL-PUT-MISS must be 0.
  echo "  CANCELTOK: $(grep -ah 'P227-TOKEN ' "$D"/dmesg_*.txt 2>/dev/null | grep -a 'blft=0 ' | grep -ao 'class=[0-9]* st=[0-9]*' | sort | uniq -c | tr '\n' ';')"
  echo "  CANCELP1: $(grep -ah 'P-FR-CANCEL-PASS1' "$D"/dmesg_*.txt 2>/dev/null | grep -ao 'txns=[0-9]* refused=[0-9]* cancel_kept=[0-9]* cancel_suppressed=[0-9]* put_miss=[0-9]*' | sort | uniq -c | tr '\n' ';') mismatch=$(grep -ahc 'P-FR-PASS-VERDICT-MISMATCH' "$D"/dmesg_*.txt 2>/dev/null | paste -sd+ | bc 2>/dev/null) putmiss_lines=$(grep -ahc 'P-FR-CANCEL-PUT-MISS' "$D"/dmesg_*.txt 2>/dev/null | paste -sd+ | bc 2>/dev/null) authcap_void=$(grep -ah 'P-AUTHCAP-VOID' "$D"/dmesg_*.txt 2>/dev/null | grep -ao 'why=[a-z_]*' | sort | uniq -c | tr '\n' ';')"
  # sess475: the untagged buffer items that taint the rm transactions (0.64.32 P227-UNTAGGED probe)
  echo "  UNTAGGED: $(grep -ah 'P227-UNTAGGED' "$D"/dmesg_*.txt 2>/dev/null | grep -ao 'blft=[0-9]* flags=0x[0-9a-f]* cancel=[01]' | sort | uniq -c | tr '\n' ';') untag_cancel=$(grep -ah 'P227-TOKENSUM' "$D"/dmesg_*.txt 2>/dev/null | grep -ao 'untag_cancel=[0-9]*' | sort | uniq -c | tr '\n' ';') nocap=$(grep -ah 'P240-AUTHCAP' "$D"/dmesg_*.txt 2>/dev/null | grep -ao 'nocap=[0-9]*' | tail -1)"
}
{
  echo "=== sess468 chain105 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) sv_before=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') ==="
  install_ko "$PROD_KO" "$PROD_SV" prod || { echo "ABORT: prod install"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  echo "STAGE markers $(for s in P-INACT-CERT P-IUNLINK-AGCLASS P-DIRSHARD-LOCATOR-FORK; do printf '%s=%s ' $s "$(strings -a mxfs.ko | grep -c "$s")"; done)"
  prep_arm prep
  lap 180 "intents burst lap1" tests/d_intents_undischarged_verify.sh ${LABEL}a burst
  census burst
  prep_arm prep_after_burst
  lap 180 "intents clean" tests/d_intents_undischarged_verify.sh ${LABEL}b clean
  census clean
  prep_arm prep_after_clean
  lap 180 "intents burst lap2" tests/d_intents_undischarged_verify.sh ${LABEL}c burst
  census burst
  prep_arm prep_final
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
