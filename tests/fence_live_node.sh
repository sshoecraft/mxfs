#!/bin/bash
# fence_live_node.sh — D-FENCED-VICTIM-NONCONTAINMENT-498 verification: PR-preempt
# a LIVE, MOUNTED node's key from a peer (plain PREEMPT, no abort, exactly what
# a false-death fence does to it) and measure how fast the victim notices and
# withdraws, and how much conflicting I/O it leaks onto the target meanwhile.
#
# The sess406 natural occurrence (test9, 0.26.0): fenced at 08:27:21Z, SELF_GONE
# audited at 08:27:22Z, NO withdrawal for 6 min, 4494 reservation-conflict
# commands at the target, log-flood halt of the rig.  The 0.26.2 fixes: (a) the
# reservation-health tick's SELF_GONE launches the P277 inspection, (b) XFS
# buffer / log / data write completions with -EBADE count as data-path
# conflicts, (c) the inspection is launched from the PR worker tick.
#
# Modes:
#   idle   the victim does nothing; detection comes from its own HB CAS bouncing
#          (P277-RESV-CONFLICT x3 -> inspection) and/or the P305 SELF_GONE audit
#          (maintainer: ~5 s lead; auditor: 45-60 s), whichever is first.
#   churn  the victim creates files in its own dir while preempted: metadata
#          writeback (xfsaild) bounces -> buffer-path conflicts (the test9 shape).
#
# Asserts (victim side, from the MARK onward):
#   1. PR IN on the peer shows the victim key PRESENT before and ABSENT after the
#      preempt (evidence the injection did what it claims).
#   2. P277-FENCED-SELF-WITHDRAW appears within WITHDRAW_S of the preempt
#      (idle: 75 s covers an auditor's audit interval + inspection; churn: 75 s
#      too — the measured latency is printed and is the real result).
#   3. Exactly one withdrawal verdict; the mount is gone afterwards; no 'BUG:',
#      no 'Oops', no P277-RESV-ANOMALY-driven ambiguity-cap withdrawal when PR IN
#      could answer (reason text 'PR IN confirmed' expected).
#   4. The target saw a BOUNDED number of reservation-conflict commands from the
#      victim between the preempt and the withdrawal: <= CONFLICT_MAX (default
#      200; the unfixed shape was thousands).  Counted on clyde's kernel log
#      (SCST logs one line per conflicting command).
#   5. Survivors recover the victim's slot afterwards (terminal replay line or a
#      clean release) within 95 s of the withdrawal — reported; FAIL if absent.
#
# budget: ssh bounded (20 s); preempt + observation bounded (WITHDRAW_S);
# per-node rc files.  the unkillable-wedge rule: no pgrep/ps.  the source-tree rule: lives in tests/.
# After the run the rig is left MOUNTED on the survivors; the victim is shut
# down/unmounted by its own withdrawal (unmount it; the next prep re-forms).
#
# Usage: tests/fence_live_node.sh <label> <idle|churn> [victim=test20] [peer=test1] [nodes=32] [--no-prep]
# Env:   FLN_OUT (evidence dir, under tests/evidence/), FLN_WITHDRAW_S (75 preempt / 90 hbpause),
#        FLN_CONFLICT_MAX (200), MXFS_DEV (/dev/mapper/mpatha)
#        FLN_PARAMS (default "target_cache_protected=1 foreign_replay_token_enforce=1"):
#          module params set fleet-wide after prep (tests/fleet_set_params.sh).
#          sess410: at the knob default foreign_replay_token_enforce=0 EVERY
#          foreign transaction carrying buffer images is ATOMIC-SKIPped (the
#          designed fail-closed blanket of ledger #1 D-FOREIGN-REPLAY-UNGATED-
#          IMAGES; rman_matrix.sh carries the same ENF for the same reason), so a
#          victim with a dirty slice is refused (-117, P241-RECOV-TERMINAL,
#          AG-domain quarantine) and the recovery assertion below can never pass
#          — fln3_log_idle / fln3_hb_churn on 0.26.12 failed exactly so.  Set
#          FLN_PARAMS="" to measure the default-knob behaviour deliberately.
#        FLN_INJECT=hbpause|preempt|logioerr (default hbpause):
#          hbpause — sess409: pause the VICTIM's disklock heartbeat thread once
#            for FLN_HB_PAUSE_MS (75000) via mxfs.dl_inject_hb_pause_ms while its
#            data path keeps running: the peers expire it (~62 s), fence it with
#            a real PREEMPT AND ABORT + certificate and replay its slice — the
#            sess276 false-death shape D-498 is about.  The victim must then
#            self-withdraw on its bounced writes/HB CAS and stop; the cluster
#            must recover its slot.
#          preempt — the peer removes the victim's PR key out of band (sg_persist
#            preempt).  Exercises the victim side only: with no published fence
#            evidence the peers' own fence attempt finds KEY_ABSENT_UNPROVEN and
#            the slice is designed-unreplayable (sess381 ruling; the prover
#            retries with backoff, the replayer refuses every 30 s) — so the
#            recovery assertion is REPORTED, not counted, in this mode.
#          logioerr — sess410 (D-LOG-ERROR-SHUTDOWN-SKIPS-DLM-WITHDRAW-409): fail
#            the VICTIM's next iclog write completion via mxfs.log_inject_ioerr
#            (0.26.12+) and force the log with a write+sync, so the FIRST shutdown
#            originates in xlog_force_shutdown ('shut down due to log error').
#            The withdraw marker here is P-WITHDRAW-QUEUE (the node is not fenced;
#            it declares voluntary death itself); it must appear within
#            FLN_WITHDRAW_S (10) of the injection, the heartbeat must stop (the
#            peers then fence it: its PR key must be gone at the end) and the
#            cluster must replay/release its slot.
set -u
LABEL=${1:?label}; MODE=${2:?idle|churn}; VICTIM=${3:-test20}; PEER=${4:-test1}; NODES=${5:-32}
PREP=1; [ "${6:-}" = --no-prep ] && PREP=0
case $MODE in idle|churn) ;; *) echo "mode must be idle or churn"; exit 2;; esac
[ "$VICTIM" = "$PEER" ] && { echo "victim and peer must differ"; exit 2; }
cd "$(dirname "$0")/.." || exit 2
OUT=${FLN_OUT:-$(mktemp -d)}; mkdir -p "$OUT"
SSH=tools/mxfs_sshpass.sh
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "$VICTIM"; DEV=$MXFS_DEV_RESOLVED
MNT=${MXFS_MNT:-/mnt/shared}
INJECT=${FLN_INJECT:-hbpause}
HB_PAUSE_MS=${FLN_HB_PAUSE_MS:-75000}
case $INJECT in hbpause) WITHDRAW_S=${FLN_WITHDRAW_S:-$(( HB_PAUSE_MS / 1000 + 15 ))} ;; preempt) WITHDRAW_S=${FLN_WITHDRAW_S:-75} ;; logioerr) WITHDRAW_S=${FLN_WITHDRAW_S:-10} ;; *) echo "FLN_INJECT must be hbpause, preempt or logioerr"; exit 2;; esac
# the victim-side line that marks the withdrawal in this mode
# sess412: an IDLE hbpause victim has almost no I/O to bounce, so its
# containment consistently lands through the fence-notify metadata-error
# path (P-WITHDRAW-QUEUE + shutdown, measured ~+79s) without ever
# accumulating the 3 conflicts that fire P277-FENCED-SELF-WITHDRAW
# (fln6/fln10, both otherwise fully contained: bounded conflicts, cluster
# recovery, replay complete).  Accept EITHER voluntary-death marker; the
# 90s bound and every other assertion are unchanged — the defect (D-498)
# is about bounded containment, not which probe line announces it.
case $INJECT in logioerr) WD_RE='P-WITHDRAW-QUEUE' ;; *) WD_RE='P277-FENCED-SELF-WITHDRAW\|P-WITHDRAW-QUEUE' ;; esac
CONFLICT_MAX=${FLN_CONFLICT_MAX:-200}
PARAMS=${FLN_PARAMS-target_cache_protected=1 foreign_replay_token_enforce=1}
export MXFS_MKFS_OPTS=${MXFS_MKFS_OPTS:--d 50G}
t0=$(date +%s)
echo "=== fence_live_node label=$LABEL mode=$MODE inject=$INJECT victim=$VICTIM peer=$PEER nodes=$NODES withdraw_s=$WITHDRAW_S out=$OUT $(date -u +%FT%TZ) ==="

if [ $PREP = 1 ]; then
    export D385_OUT=$OUT MXFS_KEEP_ARTIFACTS=1
    # sess409: outer bound must exceed d385's PREP_TIMEOUT (320 s) — see tmpfile_churn_kill.sh
    D385_STEP="arm_prep TREATMENT" timeout 335 tests/d385_publication_verify.sh 3 $NODES > "$OUT/prep.log" 2>&1
    rc=$?; echo "prep rc=$rc wall=$(( $(date +%s) - t0 ))s  $(grep -m1 'prep_cluster OK\|FAIL' "$OUT/prep.log" | cut -c1-120)"
    [ $rc = 0 ] || { echo "PREP FAILED — see $OUT/prep.log"; exit 3; }
fi
if [ -n "$PARAMS" ]; then
    tests/fleet_set_params.sh "$PARAMS" "$NODES" "$OUT/knobs.txt" > /dev/null 2>&1; prc=$?
    echo "params: '$PARAMS' on $NODES nodes rc=$prc ($(grep -c 'rc=0' "$OUT/knobs.txt" 2>/dev/null) rc=0 lines; SETFAIL=$(grep -c SETFAIL "$OUT/knobs.txt" 2>/dev/null))"
    [ $prc = 0 ] && ! grep -q SETFAIL "$OUT/knobs.txt" || { echo "FAIL: fleet_set_params refused on some node(s) — see $OUT/knobs.txt"; exit 2; }
fi

# identities: slot + node id from the claim line (key == node id, hex for sg_persist)
learn() { timeout 20 $SSH "$1" "(journalctl -k -o cat --since -30min 2>/dev/null; dmesg) | grep -a 'claimed heartbeat slot' | tail -1" 2>/dev/null | grep -av '^Unauthorized\|^Warning:\|^If you' | tail -1; }
vc=$(learn "$VICTIM"); pc=$(learn "$PEER")
VSLOT=$(printf '%s\n' "$vc" | sed -n 's/.*claimed heartbeat slot \([0-9]*\) .*/\1/p')
VID=$(printf '%s\n' "$vc" | sed -n 's/.*for node \([0-9]*\).*/\1/p')
PID_=$(printf '%s\n' "$pc" | sed -n 's/.*for node \([0-9]*\).*/\1/p')
[ -n "${VSLOT:-}" ] && [ -n "${VID:-}" ] && [ -n "${PID_:-}" ] || { echo "FAIL: could not learn identities (victim='$vc' peer='$pc')"; exit 2; }
# sess439: since 0.43.0 the PR key is a 64-bit per-boot key (P-PRKEY-PUBLISHED
# key=0x...), no longer the node_id.  Learn it from the node's own log; fall
# back to node_id only for a pre-0.43.0 module (no P-PRKEY line at all).
learnkey() { timeout 20 $SSH "$1" "(journalctl -k -o cat --since -30min 2>/dev/null; dmesg) | grep -a 'P-PRKEY-PUBLISHED\|P-PRKEY-REGISTERED' | tail -1 | sed -n 's/.*key=\(0x[0-9a-f]*\).*/\1/p'" 2>/dev/null | grep -av '^Unauthorized\|^Warning:\|^If you' | tail -1; }
VKEY=$(learnkey "$VICTIM"); PKEY=$(learnkey "$PEER")
[ -n "${VKEY:-}" ] || VKEY=$(printf '0x%x' "$VID")
[ -n "${PKEY:-}" ] || PKEY=$(printf '0x%x' "$PID_")
ver=$(timeout 20 $SSH "$VICTIM" "cat /sys/module/mxfs/srcversion; grep -c ' mxfs ' /proc/mounts" 2>/dev/null | grep -av '^Unauthorized\|^Warning:\|^If you' | tr '\n' ' ')
echo "identities: victim=$VICTIM slot=$VSLOT node=$VID key=$VKEY  peer=$PEER node=$PID_ key=$PKEY  victim ver/mounted: $ver"

# MARK every node's kmsg; baseline
MARK="FLN-$LABEL-$$-$(date -u +%s)"
for i in $(seq 1 $NODES); do ( timeout 20 $SSH test$i "echo '$MARK' > /dev/kmsg" >/dev/null 2>&1 ) & done; wait
keys_before=$(timeout 30 $SSH "$PEER" "sg_persist --in --read-keys $DEV 2>&1 | grep -ci '$VKEY\$\|${VKEY#0x}\$'" 2>/dev/null | grep -av '^Unauthorized\|^Warning:\|^If you' | tail -1 | tr -dc 0-9)
timeout 30 $SSH "$PEER" "sg_persist --in --read-keys $DEV 2>&1 | head -40" > "$OUT/keys_before.txt" 2>/dev/null
echo "pr-in before: victim key lines=$keys_before (keys_before.txt: $(grep -ci 'keys follow\|0x' "$OUT/keys_before.txt") lines)"

# optional churn on the victim only (its own dir), detached, bounded 120 s
if [ "$MODE" = churn ]; then
    # sess467: no file-count cap.  Chain 11 (0.41.10) measured 685 files in the
    # first 3 s and churn_done=4000 at ~18 s, so the loop was long finished when
    # the victim withdrew at +67 s and no syscall could fail: the EBADE/EIO
    # assertion below was vacuous.  Run until the first failure or the 120 s
    # bound (the churn must be alive at the withdrawal for item 2 to be tested).
    timeout 20 $SSH "$VICTIM" "nohup sh -c 'mkdir -p $MNT/fln_$VICTIM; timeout 120 sh -c \"i=0; while :; do echo x > $MNT/fln_$VICTIM/f\\\$i && sync $MNT/fln_$VICTIM/f\\\$i || break; i=\\\$((i+1)); done; echo churn_done=\\\$i\" > /root/fln_churn.out 2>&1 &' >/dev/null 2>&1" >/dev/null 2>&1
    sleep 3
    echo "churn started on $VICTIM at +$(( $(date +%s) - t0 ))s: $(timeout 10 $SSH "$VICTIM" "cat /root/fln_churn.out 2>/dev/null | tail -1; ls $MNT/fln_$VICTIM 2>/dev/null | wc -l" 2>/dev/null | grep -av '^Unauthorized\|^Warning:\|^If you' | tr '\n' ' ')"
fi

# THE INJECTION.
TP=$(date -u +%FT%T.%3NZ); tp=$(date +%s)
if [ "$INJECT" = preempt ]; then
    # plain PREEMPT of the victim's key by the peer's registered key.
    # --prout-type is mandatory (sess408: without it SCST answers ILLEGAL REQUEST and
    # the injection silently does not take); 7 = WE-AR, the type MXFS reserves with.
    pre=$(timeout 30 $SSH "$PEER" "sg_persist --out --preempt --prout-type=7 --param-rk=$PKEY --param-sark=$VKEY $DEV 2>&1; echo rc=\$?" 2>/dev/null | grep -av '^Unauthorized\|^Warning:\|^If you' | tr '\n' ' ')
    echo "PREEMPT at $TP: $pre"
elif [ "$INJECT" = logioerr ]; then
    # fail the next iclog completion (one-shot knob, 0.26.12+) and force a log
    # write: create+sync in the victim's own dir.  Poll up to 12 s for the ack.
    pre=$(timeout 30 $SSH "$VICTIM" "mkdir -p $MNT/fln_$VICTIM; echo 1 > /sys/module/mxfs/parameters/log_inject_ioerr 2>&1 && echo set_rc=0 || echo set_rc=\$?; echo x > $MNT/fln_$VICTIM/logioerr_\$\$; sync -f $MNT 2>/dev/null; for i in 1 2 3 4 5 6; do dmesg | grep -aq 'P-LOG-INJECT-IOERR' && break; sleep 2; done; dmesg | grep -a 'P-LOG-INJECT-IOERR\|log I/O error\|shut down due to log error' | head -3 | cut -c1-160" 2>/dev/null | grep -av '^Unauthorized\|^Warning:\|^If you' | tr '\n' ' ')
    echo "LOG-IOERR at $TP: $pre"
    case "$pre" in *P-LOG-INJECT-IOERR*) ;; *) echo "FAIL: the log I/O error injection did not fire on $VICTIM within 12 s (knob missing? module < 0.26.12? no log write?)"; exit 2;; esac
else
    # pause the victim's heartbeat thread once (one-shot knob, 0.26.11+)
    # the knob is consumed at the top of the heartbeat loop (2 s cadence, but a
    # monitor pass at 32 nodes can hold the thread for seconds): poll up to 12 s
    pre=$(timeout 30 $SSH "$VICTIM" "echo $HB_PAUSE_MS > /sys/module/mxfs/parameters/dl_inject_hb_pause_ms 2>&1 && echo set_rc=0 || echo set_rc=\$?; for i in 1 2 3 4 5 6; do sleep 2; dmesg | grep -aq 'P-HB-INJECT-PAUSE' && break; done; dmesg | grep -a 'P-HB-INJECT-PAUSE' | tail -1 | cut -c1-160" 2>/dev/null | grep -av '^Unauthorized\|^Warning:\|^If you' | tr '\n' ' ')
    echo "HB-PAUSE ${HB_PAUSE_MS}ms at $TP: $pre"
    case "$pre" in *P-HB-INJECT-PAUSE*) ;; *) echo "FAIL: the heartbeat pause did not arm on $VICTIM within 12 s (knob missing? module < 0.26.11? HB thread stuck?)"; exit 2;; esac
fi
sleep 1
keys_after=$(timeout 30 $SSH "$PEER" "sg_persist --in --read-keys $DEV 2>&1 | grep -ci '$VKEY\$\|${VKEY#0x}\$'" 2>/dev/null | grep -av '^Unauthorized\|^Warning:\|^If you' | tail -1 | tr -dc 0-9)
timeout 30 $SSH "$PEER" "sg_persist --in --read-keys $DEV 2>&1 | head -40" > "$OUT/keys_after.txt" 2>/dev/null
resv=$(timeout 30 $SSH "$PEER" "sg_persist --in --read-reservation $DEV 2>&1 | grep -E 'Key=|type:' | tr '\n' ' '" 2>/dev/null | grep -av '^Unauthorized\|^Warning:\|^If you' | tail -1)
echo "pr-in after: victim key lines=$keys_after  reservation: $resv"

# observe the victim until it withdraws (or the bound)
wd=""; lat=""
while :; do
    now=$(date +%s)
    wd=$(timeout 15 $SSH "$VICTIM" "dmesg | sed -n '/$MARK/,\$p' | grep -a -m1 '$WD_RE' | cut -c1-300" 2>/dev/null | grep -av '^Unauthorized\|^Warning:\|^If you' | tail -1)
    if [ -n "$wd" ]; then lat=$(( now - tp )); echo "WITHDRAW seen at +${lat}s after the injection: $wd"; break; fi
    if [ $(( now - tp )) -ge "$WITHDRAW_S" ]; then echo "WAIT EXPIRED: no $WD_RE on $VICTIM within ${WITHDRAW_S}s of the injection"; break; fi
    sleep 2
done
sleep 6      # let the withdrawal/shutdown lines land

# victim-side evidence (from the MARK)
timeout 30 $SSH "$VICTIM" "dmesg | sed -n '/$MARK/,\$p'" > "$OUT/victim_dmesg.txt" 2>/dev/null
vs() { grep -ac -- "$1" "$OUT/victim_dmesg.txt"; }
first() { grep -a -m1 -- "$1" "$OUT/victim_dmesg.txt" | cut -c1-260; }
echo "victim: logerr=$(vs 'shut down due to log error') inject=$(vs 'P-LOG-INJECT-IOERR') wdq=$(vs 'P-WITHDRAW-QUEUE') wdone=$(vs 'P-WITHDRAW —') conflict=$(vs 'P277-RESV-CONFLICT') selfgone=$(vs 'P305-RESV-HEALTH state=SELF_GONE') selfgone_inspect=$(vs 'P305-RESV-SELF-GONE-INSPECT') withdraw=$(vs 'P277-FENCED-SELF-WITHDRAW') anomaly=$(vs 'P277-RESV-ANOMALY') shutdown=$(vs 'Shutting down') blk_conflict=$(vs 'reservation conflict error') bug=$(vs 'BUG:\|Oops') fence_intent_after=$(vs 'P236-FENCE-INTENT') hb_conflict=$(vs 'conflict_cb\|HB.*RESERVATION') "
echo "  first conflict : $(first 'P277-RESV-CONFLICT\|reservation conflict error')"
echo "  first selfgone : $(first 'P305-RESV-HEALTH state=SELF_GONE\|P305-RESV-SELF-GONE-INSPECT')"
echo "  withdraw       : $(first "$WD_RE")"
vm=$(timeout 20 $SSH "$VICTIM" "grep -c ' mxfs ' /proc/mounts; cat /root/fln_churn.out 2>/dev/null | tail -1" 2>/dev/null | grep -av '^Unauthorized\|^Warning:\|^If you' | tr '\n' ' ')
echo "  victim mounted/churn: $vm"
echo "  victim dmesg tail: $(grep -a 'mxfs\|XFS' "$OUT/victim_dmesg.txt" | tail -4 | cut -c1-160 | tr '\n' ';')"

# target-side: conflicting commands from the victim between preempt and now
TN=$(date -u +%FT%T.%3NZ)
conf=$(journalctl -k --since "$TP" --until "$TN" 2>/dev/null | grep -c "Reservation conflict.*${VICTIM}-mxfs-node")
conf_all=$(journalctl -k --since "$TP" --until "$TN" 2>/dev/null | grep -c "Reservation conflict")
echo "target: reservation-conflict commands from $VICTIM=$conf (all initiators=$conf_all) between $TP and $TN"

# survivors: did the cluster recover the victim's slot?
# sess409: "withdraw" = v5_resv_conflict_withdraw -> fence_notify_fn -> forced
# filesystem SHUTDOWN (dlm/v5_mount.c).  The victim's heartbeat stops, so the
# peers see its death only after HB expiry (~62 s) and then fence + replay /
# release the slot.  A 4 s look found nothing in sess408 (D-498 evidence);
# the cluster-side containment check has to wait the recovery window:
# 62 s expiry + fence + replay (<=30 s measured) = 95 s after the withdraw.
RECOV_BOUND=${FLN_RECOV_BOUND:-95}
D=$(mktemp -d)
sweep_survivors() {
    for i in $(seq 1 $NODES); do [ "test$i" = "$VICTIM" ] && continue; ( timeout 20 $SSH test$i "dmesg | sed -n '/$MARK/,\$p' | grep -a 'slot $VSLOT\b\|slot=$VSLOT\b' | grep -a 'foreign replay of .* complete\|foreign replay of .* failed\|P163-RECOVERY-COMPLETE\|released heartbeat slot\|clean release\|P238-FENCE-DONE\|P236-FENCE-CERTIFIED' | head -4 | cut -c1-200" > $D/s$i 2>/dev/null ) & done; wait
    for i in $(seq 1 $NODES); do [ "test$i" = "$VICTIM" ] && continue; echo "test$i $(grep -av '^Unauthorized\|^Warning:\|^If you' $D/s$i | tr '\n' ' | ')"; done > "$OUT/survivors.txt"
    recov=$(grep -ac 'complete\|P163-RECOVERY-COMPLETE\|clean release\|released heartbeat' "$OUT/survivors.txt")
    fenced_again=$(grep -ac 'P236-FENCE-CERTIFIED' "$OUT/survivors.txt")
}
twd=$(date +%s)
while :; do
    sweep_survivors
    [ "$recov" -ge 1 ] && { echo "survivors: recovery/release line for slot $VSLOT seen +$(( $(date +%s) - twd ))s after the withdraw check"; break; }
    [ -z "$wd" ] && break       # no withdrawal: no point waiting for its recovery
    [ $(( $(date +%s) - twd )) -ge "$RECOV_BOUND" ] && { echo "WAIT EXPIRED: no recovery/release line for slot $VSLOT on any survivor within ${RECOV_BOUND}s of the withdraw"; break; }
    sleep 5
done
echo "survivors: nodes with a recovery/release line for slot $VSLOT=$recov fence_certified_lines=$fenced_again"
# sess409: keep the REPLAYER's context — a later prep power-cycles nodes and the
# VM journals do not persist, so 'foreign replay of slot 12 failed: error -117'
# (fln2_hb_churn) was left with no surrounding evidence.  For every survivor that
# logged a foreign-replay line for this slot, dump 80 lines before / 240 after
# (a churn slice logs ~100 lines before its verdict: fln3_hb_churn cut off at +40).
for i in $(seq 1 $NODES); do [ "test$i" = "$VICTIM" ] && continue
    grep -aq 'foreign replay of' $D/s$i 2>/dev/null || continue
    timeout 40 $SSH test$i "dmesg | grep -an 'foreign replay of .*slot $VSLOT\b\|foreign replay slot=$VSLOT\b' | head -1 | cut -d: -f1 | { read -r n; [ -n \"\$n\" ] && dmesg | sed -n \"\$(( n>80 ? n-80 : 1 )),\$(( n+240 ))p\"; }" 2>/dev/null | grep -av '^Unauthorized\|^Warning:\|^If you' | cut -c1-400 > "$OUT/replay_test$i.txt"
    echo "  replayer context: test$i -> $OUT/replay_test$i.txt ($(wc -l < "$OUT/replay_test$i.txt") lines; $(grep -a 'foreign replay of' "$OUT/replay_test$i.txt" | head -2 | cut -c1-140 | tr '\n' '|'))"
done
# sess412: a failed replay's victim slice is destroyed by the NEXT arm's prep
# (fln6_hb_churn's slot-27 type-0 evidence was lost exactly so).  Archive the
# slice from the SCST backing image, envelope-correct, the moment a failure is
# seen.  FLN_BACKING must be the fileio backing file on clyde.
# the host-side image only when the rig declares one and it is this LUN
# (the qnap declares none: the slice dump below is then skipped)
FLN_BACKING=$(tools/mxfs_host_image.sh 2>/dev/null) || FLN_BACKING=
if grep -aq 'foreign replay of .* failed: error' "$OUT"/replay_test*.txt 2>/dev/null && [ -r "$FLN_BACKING" ]; then
    timeout 60 python3 tools/mxfs_logslice.py "$FLN_BACKING" --slice "$VSLOT" \
        --raw-out "$OUT/slice${VSLOT}_platter_after.bin" > "$OUT/slice${VSLOT}_decode.txt" 2>&1
    gzip -f "$OUT/slice${VSLOT}_platter_after.bin" 2>/dev/null
    echo "  slice archived: $OUT/slice${VSLOT}_platter_after.bin.gz + decode summary ($(tail -4 "$OUT/slice${VSLOT}_decode.txt" | head -1))"
fi
# target-side, post-withdraw: a withdrawn (shut-down) node must stop WRITING.
# Count reservation-conflict commands from the victim from (withdraw + 10 s
# grace for in-flight bios) to now.
conf_post=0
if [ -n "$wd" ]; then
    TW=$(date -u -d "@$(( tp + lat + 10 ))" +%FT%T.%3NZ)
    conf_post=$(journalctl -k --since "$TW" 2>/dev/null | grep -c "Reservation conflict.*${VICTIM}-mxfs-node")
    echo "target: reservation-conflict commands from $VICTIM AFTER withdraw+10s ($TW ->)=$conf_post"
fi

# verdict
fail=0
[ "${keys_before:-0}" -ge 1 ] || { echo "FAIL: victim key $VKEY not present in PR IN BEFORE the preempt (injection evidence missing)"; fail=1; }
if [ "$INJECT" = preempt ]; then
    [ "${keys_after:-1}" = 0 ] || { echo "FAIL: victim key $VKEY STILL present after the preempt (keys_after=$keys_after) — injection did not take"; fail=1; }
else
    keys_final=$(timeout 30 $SSH "$PEER" "sg_persist --in --read-keys $DEV 2>&1 | grep -ci '$VKEY\$\|${VKEY#0x}\$'" 2>/dev/null | grep -av '^Unauthorized\|^Warning:\|^If you' | tail -1 | tr -dc 0-9)
    echo "pr-in at the end: victim key lines=$keys_final ($INJECT: the PEERS must have fenced it)"
    [ "${keys_final:-1}" = 0 ] || { echo "FAIL: victim key $VKEY still registered at the end — the peers never fenced the $INJECT victim (keys_final=$keys_final)"; fail=1; }
fi
if [ "$INJECT" = logioerr ]; then
    [ "$(vs 'shut down due to log error')" -ge 1 ] || { echo "FAIL: no 'shut down due to log error' on the victim — the first shutdown did not come from xlog_force_shutdown (injection missed the log path)"; fail=1; }
    [ "$(vs 'P-WITHDRAW —')" -ge 1 ] || { echo "FAIL: P-WITHDRAW (the queued withdrawal) never ran on the victim"; fail=1; }
fi
[ -n "$wd" ] || { echo "FAIL: no withdrawal ($WD_RE) within ${WITHDRAW_S}s (D-498 shape: fenced-but-alive node stays a member / D-409 shape: log-error shutdown never withdraws)"; fail=1; }
[ "$(vs 'P277-FENCED-SELF-WITHDRAW')" -le 1 ] || { echo "FAIL: more than one withdrawal verdict ($(vs 'P277-FENCED-SELF-WITHDRAW'))"; fail=1; }
# sess436 (D-RSYNC-OVERWRITE-LAP-USERSPACE-FAIL-ERRNO-UNKNOWN item 2): a fenced
# node's syscalls must fail EIO, never with the raw SCSI RESERVATION CONFLICT
# (EBADE, strerror "Invalid exchange").  The churn loop now fsyncs each file
# (`sync FILE`) so both the create (metadata) and the data-writeback paths
# report through it; dash/coreutils print the strerror into fln_churn.out.
if [ "$MODE" = churn ]; then
    ebade=$(timeout 15 $SSH "$VICTIM" "grep -ac 'Invalid exchange' /root/fln_churn.out 2>/dev/null; echo" 2>/dev/null | grep -av '^Unauthorized\|^Warning:\|^If you' | tr -dc '0-9' | head -c 6)
    eio=$(timeout 15 $SSH "$VICTIM" "grep -ac 'Input/output error' /root/fln_churn.out 2>/dev/null; echo" 2>/dev/null | grep -av '^Unauthorized\|^Warning:\|^If you' | tr -dc '0-9' | head -c 6)
    echo "  victim churn errno: EBADE(Invalid exchange)=${ebade:-?} EIO(Input/output error)=${eio:-?}"
    [ "${ebade:-1}" = 0 ] || { echo "FAIL: the victim's syscalls returned EBADE ${ebade:-?} time(s) (P-EBADE-BOUNDARY must convert it to EIO)"; fail=1; }
    # sess467: the boundary claim needs a FAILING syscall inside the fenced
    # window — zero failures of either kind means the churn was not alive at
    # the withdrawal (or the shutdown did not reach userspace), and the arm is
    # INCONCLUSIVE for item 2, not a PASS.
    [ "${eio:-0}" -ge 1 ] || { echo "FAIL: INCONCLUSIVE for the EIO boundary — the victim's churn recorded no failing syscall (EIO=${eio:-?} EBADE=${ebade:-?}); churn must be alive at the withdrawal"; fail=1; }
fi
[ "$(vs 'BUG:\|Oops')" = 0 ] || { echo "FAIL: BUG/Oops on the victim"; fail=1; }
[ "$conf" -le "$CONFLICT_MAX" ] || { echo "FAIL: $conf reservation-conflict commands from $VICTIM at the target (> $CONFLICT_MAX) — the fenced node kept writing"; fail=1; }
# sess409: withdraw does NOT unmount — it force-shuts the filesystem down
# (dlm/v5_mount.c v5_resv_conflict_withdraw -> fence_notify_fn); the mount
# persists like any XFS shutdown until umount.  The assertions that follow
# from the semantics: the shutdown landed, the node stopped writing, and
# the peers recovered its slot.
# (the log-error path says "Filesystem has been shut down due to log error" instead of "Shutting down filesystem")
[ -z "$wd" ] || [ "$(vs 'Shutting down\|shut down due to log error')" -ge 1 ] || { echo "FAIL: withdraw logged but no 'Shutting down' / 'shut down due to log error' on the victim (withdraw must force-shutdown the filesystem)"; fail=1; }
[ -z "$wd" ] || [ "$conf_post" = 0 ] || { echo "FAIL: $conf_post reservation-conflict commands from $VICTIM reached the target AFTER withdraw+10s — the withdrawn node kept writing"; fail=1; }
if [ "$INJECT" = preempt ]; then
    # out-of-band key removal: no published fence evidence exists, so the peers'
    # own attempt finds KEY_ABSENT_UNPROVEN and the slice is designed-unreplayable
    # (sess381 ruling; sess409 evidence tests/evidence/sess409_fln_churn/survivors_sweep:
    # prover P304-FENCE-RETRY x41 with backoff, replayer 'NOT replayed — no proven
    # exclusion' every 30 s).  Reported, not counted.
    echo "preempt mode: survivor recovery=$recov (designed refusal without fence evidence — reported, not counted)"
else
    [ -z "$wd" ] || [ "$recov" -ge 1 ] || { echo "FAIL: no survivor recovered/released slot $VSLOT within ${RECOV_BOUND}s of the withdraw — the peers never reclaimed the $INJECT victim's slot"; fail=1; }
fi
if [ $fail = 0 ]; then echo "VERDICT PASS: $MODE/$INJECT victim withdrew ${lat}s after the injection ($(vs 'P277-RESV-CONFLICT') counted conflicts, selfgone_inspect=$(vs 'P305-RESV-SELF-GONE-INSPECT')), $conf conflicting commands reached the target"; else echo "VERDICT FAIL"; fi
echo "=== done label=$LABEL total=$(( $(date +%s) - t0 ))s out=$OUT ==="
exit $fail
