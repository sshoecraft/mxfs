#!/bin/bash
# sess395: preserve evidence of slot-10 TERMINAL REFUSAL VERDICT / quarantine
# One ssh per node, all 32 in parallel, per-node out/rc files.
cd /src/mxfs || exit 1
FILT='dmesg -T | grep -E "Aug 22 1(4:5[0-9]|5:[0-3][0-9])" | grep -iE "slot 10|slot=10|4222738768|victim|refus|verdict|quarantin|TERMINAL|foreign|replay|recovery_(begin|complete)|P3[0-9][0-9]-|P24[0-9]-|recover" | grep -vE "P82-|P150|P145|P144|P165|P12-|P244-REL|P245|P86-|P87-|P84-|P83-" | cut -c1-400'
REMOTE="C=\$($FILT | wc -l); echo \"MXFSCOUNT=\$C\"; $FILT | head -60"
D=$(mktemp -d)
for i in $(seq 1 32); do
  (
    timeout 60 tools/mxfs_sshpass.sh test$i "$REMOTE" 2>"$D/test$i.err" \
      | grep -vE 'authorized|Permanently added' > "$D/test$i.out"
    echo "${PIPESTATUS[0]}" > "$D/test$i.rc"
  ) &
done
wait
OUT=/src/mxfs/tests/logs/sess395_slot10_refusal_evidence.txt
{
  echo "# sess395 slot-10 TERMINAL REFUSAL VERDICT evidence sweep"
  echo "# collected: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
  echo "# nodes: test1..test32, one ssh each, in parallel"
  echo "# exact remote command run on each node:"
  echo "#   $REMOTE"
  echo "# local ssh wrapper: timeout 60 tools/mxfs_sshpass.sh testN \"<remote cmd>\""
  echo "# local post-filter: grep -vE 'authorized|Permanently added'"
  echo
  for i in $(seq 1 32); do
    rc=$(cat "$D/test$i.rc" 2>/dev/null)
    cnt=$(grep -m1 '^MXFSCOUNT=' "$D/test$i.out" 2>/dev/null | cut -d= -f2)
    [ -z "$cnt" ] && cnt="NA"
    echo "=== test$i (count=$cnt) [ssh_rc=$rc]"
    if [ -s "$D/test$i.err" ]; then
      grep -vE 'authorized|Permanently added' "$D/test$i.err" | sed 's/^/STDERR: /'
    fi
    grep -v '^MXFSCOUNT=' "$D/test$i.out" 2>/dev/null
    echo
  done
} > "$OUT"
echo "WROTE $OUT"
echo "--- per-node counts / rc ---"
for i in $(seq 1 32); do
  rc=$(cat "$D/test$i.rc" 2>/dev/null); cnt=$(grep -m1 '^MXFSCOUNT=' "$D/test$i.out" 2>/dev/null | cut -d= -f2)
  lines=$(grep -cv '^MXFSCOUNT=' "$D/test$i.out" 2>/dev/null)
  echo "test$i count=${cnt:-NA} rc=${rc:-NA} returned_lines=$lines"
done
echo "--- keyword-hit lines fleet-wide (refus|verdict|quarantin|TERMINAL|recovery_complete) ---"
for i in $(seq 1 32); do
  grep -v '^MXFSCOUNT=' "$D/test$i.out" 2>/dev/null | grep -iE 'refus|verdict|quarantin|TERMINAL|recovery_complete' | sed "s/^/test$i| /"
done > "$D/keyhits.txt"
echo "KEYHIT_TOTAL=$(wc -l < "$D/keyhits.txt")"
cat "$D/keyhits.txt"
echo "SCRATCH=$D"
