#!/bin/bash
# d513_write_eio_containment.sh — D-FOREIGN-SHADOW-UNWIND-HOST-SHUTDOWN-513B
# closure arm (sess449; ledger item 4 "injected replay-write IO error"):
# a FAILED foreign-replay buffer WRITE must fail the replay, never the
# elected replayer's live mount; a failed LIVE-mount write must still shut
# that mount down (upstream policy retained).
#
# Arm 1 (foreign): arm the one-shot freplay_inject_write_eio knob on every
# survivor (only the elected replayer's first foreign-provenance write
# consumes it), run an inode-mode dirty load on the victim (touch+sync on
# preexisting files — XFS_LI_INODE items that genuinely APPLY at foreign
# replay, so the replay WRITES; proven sess341), kill the victim, and assert:
#   P227-FR-INJECT-WRITE-EIO foreign=1 on exactly one survivor (the replayer)
#   P227-FR-BUFFAIL on that survivor (provenance routing took the failure)
#   P227-FR-UNWIND on that survivor (batch failed without I/O)
#   exactly one refusing replayer, >=1 terminal publish, quarantine imported
#   by the other survivors, the victim slot NOT published as recovered,
#   ZERO survivors shut down / withdrawn, every survivor still mounted.
# Arm 2 (live control): on CONTROL (a survivor that is not the replayer),
# arm buf_inject_write_eio_live=1, do a metadata write + sync, and assert
# that node — and only that node — logs a forced shutdown.  CONTROL's mount
# is dead afterwards: re-prep the cluster.
#
# Usage: tests/d513_write_eio_containment.sh <N> <victim> [control]
#   N        fleet size (test1..testN), freshly prepped and mounted
#   victim   node to virsh destroy (not test1)
#   control  node for the live-write control (default test3; must differ from
#            the victim and from the elected replayer — checked after arm 1)
# Env: VICTIM_LOAD (s, default 20), RECOVERY_WAIT (s, default 150).
#      D513_ARM=eio (default) | verify — 0.74.2 (D-FOREIGN-REPLAY-WRITE-
#        VERIFIER-FAILURE-SHUTS-DOWN-SURVIVOR-0904): `verify` arms
#        freplay_inject_verify_fail instead, which corrupts the next outgoing
#        foreign-replay image so its WRITE VERIFIER refuses it; asserts
#        P227-FR-INJECT-VERIFY-FAIL + P227-FR-VERIFY-FAIL + P227-FR-BUFFAIL on
#        the replayer and the same containment set (refused, published,
#        imported, zero survivor shutdowns).  No P227-FR-UNWIND is expected:
#        the refusal happens at the end-of-pass submit, after the queue is
#        already drained.
#      D513_SKIP_CONTROL=1 — skip arm 2 (a 2-node fleet has no control node).
#
# budget: load 20 + kill + HB confirm ~62 s + fence + replay + publish +
# import + harvest ≈ 150 s wait + 30 s control + ssh ≈ 230 s → bound 300 s.
# Leaves a durable quarantine on the victim's slice domain AND a shut-down
# control mount — re-prep before any other board test.  Exit 0 = PASS,
# 1 = FAIL, 2 = INFRA-FAIL (knob not armed / load never landed).
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"

N="${1:?usage: d513_write_eio_containment.sh <N> <victim> [control]}"
VICTIM="${2:?usage: d513_write_eio_containment.sh <N> <victim> [control]}"
CONTROL="${3:-test3}"
MNT=/mnt/shared
VICTIM_LOAD="${VICTIM_LOAD:-20}"
RECOVERY_WAIT="${RECOVERY_WAIT:-150}"
ARM="${D513_ARM:-eio}"
case "$ARM" in
  eio)    KNOB_F=/sys/module/mxfs/parameters/freplay_inject_write_eio
          INJ_RE='P227-FR-INJECT-WRITE-EIO.*foreign=1' ;;
  verify) KNOB_F=/sys/module/mxfs/parameters/freplay_inject_verify_fail
          INJ_RE='P227-FR-INJECT-VERIFY-FAIL' ;;
  *) echo "FAIL: D513_ARM must be eio or verify"; exit 1 ;;
esac
KNOB_L=/sys/module/mxfs/parameters/buf_inject_write_eio_live
SKIP_CONTROL="${D513_SKIP_CONTROL:-0}"

[ "$VICTIM" = "test1" ] && { echo "FAIL: test1 is the probe node, pick another victim"; exit 1; }
[ "$VICTIM" = "$CONTROL" ] && { echo "FAIL: victim == control"; exit 1; }

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT="$REPO/tests/evidence/${STAMP}_d513_write_eio"
mkdir -p "$OUT"
echo "=== d513_write_eio_containment: N=$N victim=$VICTIM control=$CONTROL arm=$ARM skip_control=$SKIP_CONTROL @ $STAMP ==="

survivors=()
for i in $(seq 1 "$N"); do
    h="test$i"
    [ "$h" = "$VICTIM" ] || survivors+=("$h")
done

# 1. Arm the foreign one-shot on every survivor; live knob confirmed 0.
echo "--- arming $(basename "$KNOB_F")=1 on ${#survivors[@]} survivors"
for h in "${survivors[@]}"; do
    "$SSH" "$h" "echo 1 > $KNOB_F; echo 0 > $KNOB_L; dmesg --clear" >/dev/null 2>&1 &
done
wait
armed=0
for h in "${survivors[@]}"; do
    v=$("$SSH" "$h" "cat $KNOB_F" 2>/dev/null | tail -1 | tr -d '[:space:]')
    [ "$v" = 1 ] && armed=$((armed+1))
done
if [ "$armed" -ne "${#survivors[@]}" ]; then
    echo "INFRA-FAIL: knob armed on $armed/${#survivors[@]} survivors (module lacks the sess449 knob?) — no kill issued"
    exit 2
fi
echo "knob CONFIRMED armed on all $armed survivors"

# 2. Inode-mode dirty load on the victim (the only txn shape that APPLIES at
#    foreign replay and therefore writes buffers — sess341).
echo "--- ${VICTIM_LOAD}s inode-mode load on $VICTIM"
"$SSH" "$VICTIM" "D=$MNT/.d513load; mkdir -p \$D;
    for i in \$(seq 1 64); do echo seed > \$D/t\$i; done; sync" >/dev/null 2>&1
"$SSH" "$VICTIM" "nohup bash -c '
    D=$MNT/.d513load
    end=\$((SECONDS + ${VICTIM_LOAD} + 30))
    while [ \$SECONDS -lt \$end ]; do
        touch \$D/t{1..64}
        sync
    done
' >/tmp/d513load.log 2>&1 &" >/dev/null 2>&1
sleep "$VICTIM_LOAD"
lcnt=$("$SSH" test1 "ls $MNT/.d513load 2>/dev/null | wc -l" 2>/dev/null | tail -1 | tr -d '[:space:]')
echo "victim load confirmed: ${lcnt:-0} files visible from test1"
[ "${lcnt:-0}" -gt 0 ] || { echo "INFRA-FAIL: victim load never landed"; exit 2; }

# 3. Kill the victim.
date -u "+KILL $VICTIM @ %FT%TZ"
sudo virsh -c qemu:///system destroy "$VICTIM" || { echo "FAIL: virsh destroy $VICTIM"; exit 1; }

echo "waiting ${RECOVERY_WAIT}s for fence + replay (injected write failure) + publish + import..."
sleep "$RECOVERY_WAIT"

# 4. Harvest survivor dmesg (cleared at arm time).
for h in "${survivors[@]}"; do
    "$SSH" "$h" "dmesg" > "$OUT/$h.dmesg" 2>/dev/null &
done
wait

pass=1
inj=$(grep -l "$INJ_RE" "$OUT"/*.dmesg 2>/dev/null | wc -l)
inj_node=$(grep -l "$INJ_RE" "$OUT"/*.dmesg 2>/dev/null | head -1 | xargs -r basename | sed 's/\.dmesg//')
buffail=$(grep -h "P227-FR-BUFFAIL" "$OUT"/*.dmesg 2>/dev/null | wc -l)
verifail=$(grep -h "P227-FR-VERIFY-FAIL" "$OUT"/*.dmesg 2>/dev/null | wc -l)
corrupt_shut=$(grep -h "Corruption of in-memory data" "$OUT"/*.dmesg 2>/dev/null | wc -l)
unwind=$(grep -h "P227-FR-UNWIND" "$OUT"/*.dmesg 2>/dev/null | wc -l)
refusers=$(grep -l "slice replay refused" "$OUT"/*.dmesg 2>/dev/null | wc -l)
publishes=$(grep -h "terminal outcome PUBLISHED" "$OUT"/*.dmesg 2>/dev/null | wc -l)
importers=$(grep -l "P240-QUAR-IMPORT" "$OUT"/*.dmesg 2>/dev/null | wc -l)
recovered_pub=$(grep -h "published as recovered\|slice recovery complete" "$OUT"/*.dmesg 2>/dev/null | wc -l)
shutdowns=$(grep -l "Filesystem has been shut down\|forced shutdown\|MXFS.*withdraw" "$OUT"/*.dmesg 2>/dev/null | wc -l)
faults=$(grep -ciE 'kernel BUG|BUG:|Oops|general protection|Call Trace' "$OUT"/*.dmesg | awk -F: '{s+=$2} END{print s+0}')

echo "--- arm 1 assertions (foreign write failure)"
echo "injection consumed on survivors (want 1): $inj  node=${inj_node:-none}"
[ "$inj" -eq 1 ] || { echo "FAIL: foreign injection fired on $inj survivors (vacuous if 0: the replay never wrote)"; pass=0; }
echo "P227-FR-BUFFAIL lines (want >=1): $buffail"
[ "$buffail" -ge 1 ] || { echo "FAIL: provenance routing did not take the failure"; pass=0; }
if [ "$ARM" = verify ]; then
    echo "P227-FR-VERIFY-FAIL lines (want >=1): $verifail   'Corruption of in-memory data' shutdowns (want 0): $corrupt_shut"
    [ "$verifail" -ge 1 ] || { echo "FAIL: the verifier arm did not route by provenance"; pass=0; }
    [ "$corrupt_shut" -eq 0 ] || { echo "FAIL: the verifier refusal shut a survivor down (SHUTDOWN_CORRUPT_INCORE)"; pass=0; }
else
    echo "P227-FR-UNWIND lines (want >=1): $unwind"
    [ "$unwind" -ge 1 ] || { echo "FAIL: pass-2 error did not unwind via delwri_fail"; pass=0; }
fi
echo "refusing replayers (want 1): $refusers"
[ "$refusers" -eq 1 ] || { echo "FAIL: expected exactly 1 refusing replayer"; pass=0; }
echo "terminal publishes (want >=1): $publishes"
[ "$publishes" -ge 1 ] || { echo "FAIL: refusal was never published"; pass=0; }
echo "importing survivors (want >=$(( ${#survivors[@]} - 1 ))): $importers"
[ "$importers" -ge $(( ${#survivors[@]} - 1 )) ] || { echo "FAIL: quarantine import did not propagate"; pass=0; }
echo "slot published-as-recovered lines (want 0): $recovered_pub"
[ "$recovered_pub" -eq 0 ] || { echo "FAIL: refused slice was published as recovered"; pass=0; }
echo "survivors with shutdown/withdraw (want 0): $shutdowns"
if [ "$shutdowns" -ne 0 ]; then
    echo "FAIL: survivor shutdown — the 513B suicide"; grep -l "Filesystem has been shut down\|forced shutdown\|MXFS.*withdraw" "$OUT"/*.dmesg; pass=0
fi
echo "kernel fault lines (want 0): $faults"
[ "$faults" -eq 0 ] || { echo "FAIL: kernel faults"; pass=0; }
mounted=0
for h in "${survivors[@]}"; do
    m=$("$SSH" "$h" "mount | grep -c 'on $MNT type mxfs'" 2>/dev/null | tail -1 | tr -d '[:space:]')
    [ "${m:-0}" -ge 1 ] && mounted=$((mounted+1))
done
echo "survivors still mounted (want ${#survivors[@]}): $mounted"
[ "$mounted" -eq "${#survivors[@]}" ] || { echo "FAIL: survivor lost its mount"; pass=0; }

# 5. Disarm the foreign knob everywhere (consumed only on the replayer).
for h in "${survivors[@]}"; do
    "$SSH" "$h" "echo 0 > $KNOB_F" >/dev/null 2>&1 &
done
wait

# 6. Arm 2 — live-write control on CONTROL (must not be the replayer).
if [ "$SKIP_CONTROL" = 1 ]; then
    echo "--- arm 2 skipped (D513_SKIP_CONTROL=1)"
    echo "--- detail"
    grep -h "$INJ_RE\|P227-FR-VERIFY-FAIL\|P227-FR-BUFFAIL\|P227-FR-UNWIND\|slice replay refused\|terminal outcome PUBLISHED" "$OUT"/*.dmesg | head -8
    echo "evidence: $OUT   (victim slice domain is quarantined — re-prep before any other test)"
    if [ "$pass" -eq 1 ]; then echo "=== d513_write_eio_containment PASS arm=$ARM @ $(date -u +%FT%TZ) ==="; exit 0; fi
    echo "=== d513_write_eio_containment FAIL arm=$ARM @ $(date -u +%FT%TZ) ==="; exit 1
fi
if [ "${inj_node:-}" = "$CONTROL" ]; then
    for h in "${survivors[@]}"; do
        [ "$h" = "$inj_node" ] || [ "$h" = "test1" ] || { CONTROL="$h"; break; }
    done
    echo "control retargeted to $CONTROL (the replayer was the default)"
fi
echo "--- arm 2: live write failure on $CONTROL"
"$SSH" "$CONTROL" "dmesg --clear; echo 1 > $KNOB_L; cat $KNOB_L" > "$OUT/control_arm.txt" 2>&1
"$SSH" "$CONTROL" "D=$MNT/.d513ctl; mkdir -p \$D; for i in \$(seq 1 32); do echo x > \$D/c\$i; done; sync; sleep 5; dmesg; echo KNOB_AFTER=\$(cat $KNOB_L)" > "$OUT/control.dmesg" 2>&1
ctl_inj=$(grep -c "P227-FR-INJECT-WRITE-EIO.*foreign=0" "$OUT/control.dmesg")
ctl_shut=$(grep -c "Filesystem has been shut down\|forced shutdown" "$OUT/control.dmesg")
ctl_knob=$(sed -n 's/^KNOB_AFTER=//p' "$OUT/control.dmesg" | tail -1)
echo "control injection fired (want 1): $ctl_inj   control shutdown lines (want >=1): $ctl_shut   knob after (want 0): $ctl_knob"
[ "$ctl_inj" -eq 1 ] || { echo "FAIL: live injection never fired on $CONTROL"; pass=0; }
[ "$ctl_shut" -ge 1 ] || { echo "FAIL: live write failure did NOT shut down $CONTROL (upstream policy lost)"; pass=0; }
others_shut=0
for h in "${survivors[@]}"; do
    [ "$h" = "$CONTROL" ] && continue
    s=$("$SSH" "$h" "dmesg | grep -c 'Filesystem has been shut down\|forced shutdown'" 2>/dev/null | tail -1 | tr -d '[:space:]')
    [ "${s:-0}" -gt 0 ] && others_shut=$((others_shut+1))
done
echo "other survivors shut down by the control (want 0): $others_shut"
[ "$others_shut" -eq 0 ] || { echo "FAIL: the live control leaked beyond $CONTROL"; pass=0; }

echo "--- detail"
grep -h "P227-FR-INJECT-WRITE-EIO\|P227-FR-BUFFAIL\|P227-FR-UNWIND\|slice replay refused\|terminal outcome PUBLISHED" "$OUT"/*.dmesg | head -8
echo "evidence: $OUT   (control mount $CONTROL is shut down — re-prep before any other test)"
if [ "$pass" -eq 1 ]; then
    echo "=== d513_write_eio_containment PASS @ $(date -u +%FT%TZ) ==="
    exit 0
fi
echo "=== d513_write_eio_containment FAIL @ $(date -u +%FT%TZ) ==="
exit 1
