#!/bin/bash
# d_intents_2tcp_open_efi.sh — D-FOREIGN-SLICE-INTENTS-ABANDONED on the
# 2-node TCP rig: a victim that dies with an open EFI in its journal slice,
# and what the survivor and the returning victim then experience.
#
# The 32-node CAW arm of this shape lives in tests/d_intents_undischarged_verify.sh
# (sess421-479).  This is the same producer on two nodes and the TCP transport,
# with the CONSEQUENCE measured rather than only the refusal:
#   1. V (the victim) builds 8 fragmented files (4096 single-block extents each,
#      fsync'd) in its own directory; W (the survivor) lists the directory and
#      reads the head of every file so the inodes are PUBLISHED (an unpublished
#      create+remove installs no replay certificate and the rm transactions are
#      refused as unauthorized before the census can decide).
#   2. V arms mxfs.dbg_efd_hold_ms=60000 and removes the files in parallel: the
#      first extent free forces the log (its EFI durable) and holds the EFD
#      transaction; V is virsh-destroyed inside the hold, so its last durable
#      checkpoint carries an EFI whose EFD never landed.
#   3. W: heartbeat expiry -> fence -> replay of V's slice.  The census names the
#      open intent (P226-ICENSUS open>=1, P226-ICENSUS-SPLIT recover/quarantine).
#      CONTROL build (no mxfs.obl_complete_enable knob): nothing can complete a
#      dead peer's EFI, so the slice is refused before any purge
#      (P226-FR-INTENTS-UNDISCHARGED, P241-RECOV-TERMINAL reason=8) and V's
#      domain is quarantined cluster-wide; P163-RECOVERY-COMPLETE for V's slot
#      must be ZERO.
#      FIX build (0.85.0, the obligation custody model): the replay SUCCEEDS with
#      an OPEN obligation case (P226-FR-INTENTS-RECOVERABLE), the list is
#      published in the IMAGES_REPLAYED milestone (P-OBL-PARK, P226-OBL-WRITE),
#      the dead node's grants are retired and its AGs frozen (P-OBL-OPEN,
#      P-OBLF-OPEN), the engine frees every extent in live transactions
#      (P-OBL-ENGINE-EXTENT ... EMPTY->freed), the proof is committed
#      (P-OBL-DONE-WRITE), OBLIGATIONS_DONE lands (P234-RECOV-OBLIGATIONS-DONE,
#      P-OBL-COMPLETE) and only then is the slot published
#      (P163-RECOVERY-COMPLETE >= 1, ZERO P241-RECOV-TERMINAL).
#   4. The consequence on W, measured: W stays mounted with no shutdown; a create
#      in V's directory (V's allocation group, inside the mask) and a create at
#      the root (outside it) are each timed under a 20 s alarm and their rc
#      recorded.  FIX build: both must succeed.  The extents the open EFI named
#      are queried on the platter (chk_mxfs --free-query, read-only, on the
#      LUN's backing image on clyde): FIX build with CHURN=0 asserts FREE.
#   5. V is virsh-started and mounts again; the mount's outcome and its kernel
#      lines are recorded.  FIX build: the mount must succeed (prep_rc=0,
#      mounted=1) and V must create in its former directory.  CONTROL: the LUN
#      is left quarantined — re-prep (MXFS_FORCE_PREP=1) before any other test.
#
# Arms (env):
#   CHURN=1     after W's election a loop on W creates/removes small dirs+files
#               inside V's directory (the frozen AG) until the case completes:
#               the freeze must park blocking acquirers and let them proceed
#               (P-OBLF-AG-WAIT/EAGAIN reported), with ZERO churn errors, ZERO
#               P-OBLF-AG-TIMEOUT, no shutdown.  Default 0 (the platter
#               free-query is then a strict assertion; with churn the freed
#               blocks may be legitimately re-allocated before the query).
#   MODE=custodian_kill (FIX build only): W arms mxfs.dbg_obl_engine_hold_ms so
#               the engine holds after its FIRST extent commits; W is
#               virsh-destroyed inside the hold.  Both nodes are then started
#               and re-prepared (V first); the case is taken over by whoever
#               mounts first and must complete from the same durable list with
#               entry 0 reading FULL->already-free and the rest EMPTY->freed;
#               both nodes end mounted, V's slot published, nothing terminal.
#               W's death is a total outage: the first node back meets the
#               dead custodian's single-holder Write Exclusive gate on the LUN
#               and must prove the holder dead over one full dead window
#               before it can preempt it (P-PR-DEADGATE-*, 0.85.1), then fence
#               and replay W's slot under a gate of its own and take V's case
#               over (P239-GATE-REPROVE-* when the first node back is W's own
#               successor).  The second node back joins a live member that may
#               still hold the gate until the case publishes: a refusal at its
#               PR-ledger publish with P-PR-DEADGATE-LIVE on its log is the
#               designed admission refusal, so rejoin() retries the prep once
#               after a bounded wait and reports the retry as MEASURED.
#   MODE=terminal_rejoin (FIX build; D-SOLE-SURVIVOR-GATE-NEVER-RESTORED-
#               AFTER-A-TERMINAL-REFUSAL): W's completion is switched off
#               (mxfs.obl_complete_enable=0, restored at exit) so the replay
#               is terminally REFUSED as on the control build, and the lap
#               measures what happens to the sole-survivor gate afterwards.
#               W installs the gate for V (V's key already purged by the
#               target: P-PR-GATE-ISSUE), publishes the terminal verdict and
#               clears its dependant (P-PR-GATE-DEP-CLEAR why=refused-
#               terminal).  Before 0.87.12 nothing then drove the restore:
#               WE(1) stayed on the LUN, and the returned V (a new
#               incarnation) was refused at its PR-ledger publish
#               (P-PRKEY-PUBLISHED rc=-52, mount aborted) for the survivor's
#               lifetime (s610h).  Since 0.87.12 the terminal publication
#               drives the restore (P-PR-GATE-RESTORE site=refused-terminal)
#               and V rejoins: prep_rc=0, mounted=1, it imports the verdict
#               (P241-RECOV-TERMINAL-IMPORT) and its create in its former
#               directory is refused by the quarantine (P240-QUAR-NSOP-
#               REFUSE, rc!=0) while a create at the root succeeds; W stays
#               mounted.  EXPECT=refuse is the control on a build without the
#               restore: V's remount refused with rc=-52 and no restore line.
#               The arm is REACHED only if the gate was installed (the
#               target must have purged V's key before W fenced it — the
#               QNAP does in ~30-40 s, inside the 62 s heartbeat expiry);
#               otherwise the lap is INCONCLUSIVE.  The LUN carries a
#               quarantined slice afterwards: re-prep before any other test.
#
# derived time budget (MODE=complete): file build ~3 s + publish ~3 s + hold
# wait <=30 s (typically <5 s) + destroy + heartbeat expiry ~62 s + fence/replay
# ~15-25 s + engine <=5 s + chk_mxfs free-query (measured on the 128 GB image)
# + probes <=40 s + V restart ~60 s + V mount <=60 s + captures ~10 s
# => ~300 s; caller bound 420 s.  custodian_kill: ~102 s to the custodian's
# death + V restart ~15 s + V mount (dead-gate window ~65 s + fence, replay
# and takeover ~40 s; measured 67 s to the preempt on s614b) + W restart ~15 s
# + W mount ~90 s (measured s614b) + one admission retry <=60 s + engine
# <=5 s + free-query + probes ~40 s + captures ~10 s => ~440 s; caller bound
# 600 s.  A timeout IS a failure.
#
# Usage: [CHURN=0|1] [MODE=complete|custodian_kill] tests/d_intents_2tcp_open_efi.sh <label> [W=test1] [V=test2]
# Exit 0 = every assertion met, 1 = an assertion failed, 2 = ABORT (precondition).
set -u
LABEL=${1:?label}; W=${2:-test1}; V=${3:-test2}
CHURN=${CHURN:-0}; MODE=${MODE:-complete}
cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
VIRSH="sudo virsh -c qemu:///system"
MNT=${MXFS_MNT:-/mnt/shared}
P=/sys/module/mxfs/parameters
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "$W"; MXFS_DEV=$MXFS_DEV_RESOLVED
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_intents2tcp_$LABEL
mkdir -p "$OUT"
fails=0
# rs/rsx/measure/capture_require (tests/lib/rig.sh; rs and rsx both close
# stdin): every capture a verdict is counted from crosses the boundary in
# the parent shell first; a failed acquisition is an ABORT, never a count of
# zero.
. "$(dirname "$0")/lib/rig.sh"
# ck: tests/lib/rig.sh (sourced above) provides it, and its version ABORTs on an EMPTY value instead of printing a FAIL about MXFS
ge1() { [ "${1:-0}" -ge 1 ] 2>/dev/null && echo yes || echo no; }
cnt() { rs 20 "$1" "dmesg | sed -n \"/$MARK/,\\\$p\" | grep -ac '$2'" | tr -dc '0-9'; }
waitfor() { local i=0; while [ $i -lt "$3" ]; do [ "$(cnt "$1" "$2")" -ge 1 ] 2>/dev/null && { echo $i; return 0; }; sleep 3; i=$((i+3)); done; echo timeout; return 1; }
t0=$(date +%s); el() { echo $(( $(date +%s) - t0 )); }
SV=$(modinfo mxfs.ko 2>/dev/null | sed -n 's/^srcversion: *//p')
MARK="I2T-$LABEL-$$"
echo "=== d_intents_2tcp_open_efi label=$LABEL W=$W V=$V mode=$MODE churn=$CHURN sv=$SV out=$OUT $(date -u +%FT%TZ) ==="

FIX=0
for n in $W $V; do
    info=$(rs 20 "$n" "echo sv=\$(cat /sys/module/mxfs/srcversion) ft=\$(cat $P/force_transport) m=\$(grep -c ' $MNT mxfs ' /proc/mounts) hold=\$(test -w $P/dbg_efd_hold_ms && echo 1 || echo 0) fix=\$(test -w $P/obl_complete_enable && echo \$(cat $P/obl_complete_enable) || echo 0) ehold=\$(test -w $P/dbg_obl_engine_hold_ms && echo 1 || echo 0) tok=\$(cat $P/foreign_replay_token_enforce)" | tr -d '\n')
    echo "  INFO $n $info"
    [[ "$info" == *"sv=$SV"* ]] || { echo "ABORT: $n srcversion != tree $SV"; exit 2; }
    [[ "$info" == *"ft=1"* ]]  || { echo "ABORT: $n not on TCP"; exit 2; }
    [[ "$info" == *"m=1"* ]]   || { echo "ABORT: $n not mounted"; exit 2; }
    [[ "$info" == *"hold=1"* ]] || { echo "ABORT: $n lacks dbg_efd_hold_ms"; exit 2; }
    [[ "$info" == *"fix=1"* ]] && FIX=1
done
echo "  INFO build class: $([ $FIX = 1 ] && echo 'FIX (obl_complete_enable=1)' || echo 'CONTROL (no completion)')"
[ "$MODE" = custodian_kill ] && [ $FIX != 1 ] && { echo "ABORT: MODE=custodian_kill needs the fix build"; exit 2; }
EXPECT=${EXPECT:-fix}
if [ "$MODE" = terminal_rejoin ]; then
    [ $FIX = 1 ] || { echo "ABORT: MODE=terminal_rejoin needs the obl_complete_enable knob (fix build)"; exit 2; }
    rs 15 "$W" "echo 0 > $P/obl_complete_enable && cat $P/obl_complete_enable" | grep -qx 0 || { echo "ABORT: could not switch completion off on $W"; exit 2; }
    trap 'rs 15 "$W" "echo 1 > $P/obl_complete_enable" >/dev/null; capture' EXIT
    FIX=0
    echo "  INFO $W completion switched OFF for this lap (obl_complete_enable=0): the replay will be terminally refused; expect=$EXPECT"
fi
[ -r "$IMG" ] || { echo "ABORT: LUN backing image $IMG not readable on this host"; exit 2; }
for n in $W $V; do rs 12 "$n" "echo '$MARK' > /dev/kmsg" >/dev/null; done
capture() {
    rs 40 "$W" "dmesg | sed -n \"/$MARK/,\\\$p\"" > "$OUT/dmesg_${W}.txt" 2>/dev/null
    echo "  INFO capture: $W=$(wc -l < "$OUT/dmesg_${W}.txt") lines (+$(el)s)"
}
trap capture EXIT
trap 'capture; exit 124' TERM

# ── 1. the victim's fragmented files, published to the survivor ──
DIR=$MNT/.icensus_$LABEL
rs 90 "$V" "mkdir -p $DIR && python3 - <<'EOF'
import os
d='$DIR'
for f in range(8):
    fd=os.open(os.path.join(d,'frag%d'%f), os.O_CREAT|os.O_WRONLY|os.O_TRUNC, 0o644)
    for i in range(4096):
        os.pwrite(fd, b'\\xa5'*4096, i*8192)
    os.fsync(fd); os.close(fd)
dfd=os.open(d, os.O_RDONLY); os.fsync(dfd)
print('ok ino=%d'%os.stat(d).st_ino)
EOF" > "$OUT/build.txt"
grep -q '^ok' "$OUT/build.txt" || { echo "ABORT: V fragmented-file build failed: $(cat "$OUT/build.txt")"; exit 2; }
DINO=$(grep -ao 'ino=[0-9]*' "$OUT/build.txt" | cut -d= -f2)
value_now_into ext "$V" 20 "$OUT/rv_ext_1.txt" '^[0-9]+$' "ext on $V" "filefrag -v $DIR/frag0 2>/dev/null | grep -ac '^ *[0-9][0-9]*:' || [ \$? = 1 ]"
echo "  INFO V built 8 files in $DIR (ino $DINO), frag0 extents=$ext (+$(el)s)"
ck "V's files are fragmented (>=2000 extents)" "$([ "${ext:-0}" -ge 2000 ] && echo yes || echo no)" "yes"
measure "$W" 60 "$OUT/rv_pub_2.txt" '^[0-9]+$' "the listing and read of the 8 frag files on $W" "ls -l $DIR | grep -c frag; for f in $DIR/frag*; do head -c 4096 \$f | wc -c; done | grep -c 4096 || [ \$? = 1 ]"; pub=$(cat "$OUT/rv_pub_2.txt")
echo "  INFO published via $W: listed=$(echo "$pub" | sed -n 1p | tr -dc '0-9') read=$(echo "$pub" | sed -n 2p | tr -dc '0-9') (+$(el)s)"
ck "W listed and read all 8 files (published before the rm)" "$(echo "$pub" | sed -n 2p | tr -dc '0-9')" "8"

# ── 2. the open EFI: arm the hold, start the removal, kill inside the hold ──
if [ "$MODE" = custodian_kill ]; then
    rs 15 "$W" "echo 90000 > $P/dbg_obl_engine_hold_ms && cat $P/dbg_obl_engine_hold_ms" | grep -qx 90000 || { echo "ABORT: could not arm dbg_obl_engine_hold_ms on $W"; exit 2; }
    echo "  INFO $W armed dbg_obl_engine_hold_ms=90000 (the custodian will be destroyed inside the hold)"
fi
rs 15 "$V" "echo 60000 > $P/dbg_efd_hold_ms && cat $P/dbg_efd_hold_ms" | grep -qx 60000 || { echo "ABORT: could not arm dbg_efd_hold_ms on $V"; exit 2; }
rs 15 "$V" "setsid nohup sh -c 'for f in $DIR/frag*; do rm -f \$f & done; wait' >/dev/null 2>&1 & echo started" | grep -q started || { echo "ABORT: could not start the unlink burst on $V"; exit 2; }
wait_for_into t "$V" 30 "$MARK" "P-EFD-HOLD start"; ck "V entered the EFD hold with a durable EFI (${t}s)" "$([ "$t" != timeout ] && echo yes || echo no)" "yes"
[ "$t" != timeout ] || { echo "ABORT: no P-EFD-HOLD on $V — nothing to destroy into"; rs 10 "$V" "echo 0 > $P/dbg_efd_hold_ms"; exit 2; }
measure "$V" 15 "$OUT/dmesg_${V}_prekill.txt" '^DMESG_END$' "the victim's pre-kill kernel log on $V" "dmesg | sed -n \"/$MARK/,\\\$p\" | grep -a 'P-EFD-HOLD\|P-INACT-CERT\|P-IUNLINK-AGCLASS\|P228-TOKCLASS\|P-INACT-EX \|P-UNLPRE\|P82-'; echo DMESG_END"
echo "  INFO victim pre-kill capture: $(wc -l < "$OUT/dmesg_${V}_prekill.txt") lines; $(grep -a 'P-EFD-HOLD start' "$OUT/dmesg_${V}_prekill.txt" | head -1 | cut -c1-160)"
$VIRSH destroy "$V" >/dev/null 2>&1; KILL_T=$(date +%s); echo "  INFO virsh destroy $V rc=$? at $(date -u +%T) (+$(el)s)"

# ── 3. the survivor's replay: census, then refusal (control) or completion (fix) ──
wait_for_into t "$W" 110 "$MARK" "elected (slot"; ck "W elected to replay V's slice (${t}s after the kill)" "$([ "$t" != timeout ] && echo yes || echo no)" "yes"
vline=$(rs 20 "$W" "dmesg | sed -n \"/$MARK/,\\\$p\" | grep -a 'lease expired/died' | head -1")
vslot=$(echo "$vline" | grep -ao '(slot [0-9]*' | tr -dc '0-9'); vid=$(echo "$vline" | grep -ao 'node [0-9]* (slot' | tr -dc '0-9')
echo "  INFO victim node=$vid slot=$vslot"
[ -n "$vslot" ] || { echo "ABORT: could not parse the victim's slot"; exit 2; }
CHURN_PID=""
if [ "$CHURN" = 1 ]; then
    # the survivor's ordinary work inside the frozen AG, from the election to
    # the completion: every op must either proceed or park on the freeze and
    # then proceed — never fail, never time out
    rs 15 "$W" "mkdir -p $DIR/churn 2>/dev/null; rm -f /tmp/churn_$LABEL.log; touch /tmp/churn_go_$LABEL; setsid nohup sh -c 'i=0; n=0; e=0; while [ -f /tmp/churn_go_$LABEL ]; do d=$DIR/churn/c\$i; if mkdir \$d 2>>/tmp/churn_$LABEL.err && echo x > \$d/f 2>>/tmp/churn_$LABEL.err && rm -rf \$d 2>>/tmp/churn_$LABEL.err; then n=\$((n+1)); else e=\$((e+1)); fi; i=\$((i+1)); echo \"ops=\$n errs=\$e\" > /tmp/churn_$LABEL.log; done' >/dev/null 2>&1 & echo started" | grep -q started && CHURN_PID=1
    echo "  INFO churn arm on $W in $DIR/churn: $([ -n "$CHURN_PID" ] && echo started || echo NOT started) (+$(el)s)"
fi
wait_for_into t "$W" 90 "$MARK" "P226-ICENSUS victim_slot=$vslot "; ck "census summary printed for slot $vslot (${t}s)" "$([ "$t" != timeout ] && echo yes || echo no)" "yes"
cl=$(rs 20 "$W" "dmesg | sed -n \"/$MARK/,\\\$p\" | grep -a 'P226-ICENSUS victim_slot=$vslot ' | tail -1")
echo "  INFO $(echo "$cl" | cut -c1-230)"
open=$(echo "$cl" | grep -ao ' open=[0-9]*' | tr -dc '0-9'); intents=$(echo "$cl" | grep -ao ' intents=[0-9]*' | tr -dc '0-9')
nextents=$(echo "$cl" | grep -ao ' extents=[0-9]*' | tr -dc '0-9')
ck "census saw intents in the slice (intents>=1)" "$(ge1 "$intents")" "yes"
ck "census left >=1 intent undischarged" "$(ge1 "$open")" "yes"
split=$(rs 20 "$W" "dmesg | sed -n \"/$MARK/,\\\$p\" | grep -a 'P226-ICENSUS-SPLIT victim_slot=$vslot ' | tail -1")
echo "  INFO $(echo "$split" | cut -c1-230)"
rs 20 "$W" "dmesg | sed -n \"/$MARK/,\\\$p\" | grep -a 'P226-ICENSUS-CLASS' | head -8 | cut -c1-230" | sed 's/^/  INFO /'
agmask=""
if [ $FIX = 1 ]; then
    wait_for_into t "$W" 60 "$MARK" "P226-FR-INTENTS-RECOVERABLE slot $vslot"; ck "replay SUCCEEDED with an OPEN obligation case (P226-FR-INTENTS-RECOVERABLE, ${t}s)" "$([ "$t" != timeout ] && echo yes || echo no)" "yes"
    if [ "$t" = timeout ]; then
        rs 20 "$W" "dmesg | sed -n \"/$MARK/,\\\$p\" | grep -a 'P226-FR-INTENTS\|P241-RECOV-TERMINAL\|P226-OBL' | head -4 | cut -c1-260" | sed 's/^/  INFO /'
        echo "=== d_intents_2tcp_open_efi $LABEL: fails=$fails wall=$(el)s out=$OUT — the verdict did not flip; nothing else can be measured (the LUN carries a quarantined slice: re-prep) ==="
        exit 1
    fi
    rs 20 "$W" "dmesg | sed -n \"/$MARK/,\\\$p\" | grep -a 'P226-FR-INTENTS-RECOVERABLE\|P-OBL-PARK\|P226-OBL-WRITE\|P234-RECOV-IMAGES-REPLAYED\|P-OBL-OPEN \|P-OBLF-\|P-COMPLETE-RETIRE-TIMING' | head -12 | cut -c1-230" | sed 's/^/  INFO /'
    window_count_into wc1 "$W" 20 "$MARK" "P-OBL-PARK count=" "OPEN obligation list parked for the ladder (P-OBL-PARK)"
    ck "OPEN obligation list parked for the ladder (P-OBL-PARK)" "$(ge1 "$wc1")" "yes"
    window_count_into wc2 "$W" 20 "$MARK" "P-OBL-OPEN slot=$vslot" "ladder took the OPEN branch (P-OBL-OPEN: grants retired, AGs frozen)"
    ck "ladder took the OPEN branch (P-OBL-OPEN: grants retired, AGs frozen)" "$(ge1 "$wc2")" "yes"
    window_count_into wc3 "$W" 20 "$MARK" "P-OBLF-INSTALL slot=$vslot" "freeze installed on the survivor (P-OBLF-INSTALL)"
    ck "freeze installed on the survivor (P-OBLF-INSTALL)" "$(ge1 "$wc3")" "yes"
    agmask=$(rs 20 "$W" "dmesg | sed -n \"/$MARK/,\\\$p\" | grep -a 'P-OBL-OPEN slot=$vslot' | tail -1" | grep -ao 'ag_mask=0x[0-9a-f]*' | head -1 | cut -d= -f2)
    if [ "$MODE" = custodian_kill ]; then
        wait_for_into t "$W" 60 "$MARK" "P-OBL-ENGINE-HOLD slot=$vslot"; ck "engine committed entry 0 and entered the hold (${t}s)" "$([ "$t" != timeout ] && echo yes || echo no)" "yes"
        [ "$t" != timeout ] || { echo "ABORT: no engine hold on $W — cannot kill the custodian inside it"; exit 2; }
        rs 20 "$W" "dmesg | sed -n \"/$MARK/,\\\$p\" | grep -a 'P-OBL-ENGINE-' | cut -c1-230" > "$OUT/dmesg_${W}_engine_prekill.txt" 2>/dev/null
        sed 's/^/  INFO W(pre-kill): /' "$OUT/dmesg_${W}_engine_prekill.txt" | head -6
        capture
        $VIRSH destroy "$W" >/dev/null 2>&1; echo "  INFO virsh destroy $W (the custodian, inside the hold) rc=$? at $(date -u +%T) (+$(el)s)"
    else
        wait_for_into t "$W" 120 "$MARK" "P-OBL-COMPLETE slot=$vslot"; ck "engine completed the case (P-OBL-COMPLETE, ${t}s)" "$([ "$t" != timeout ] && echo yes || echo no)" "yes"
    fi
else
    wait_for_into t "$W" 60 "$MARK" "P241-RECOV-TERMINAL slot=$vslot .*REFUSED"; ck "terminal verdict REFUSED durable on slot $vslot (${t}s)" "$([ "$t" != timeout ] && echo yes || echo no)" "yes"
    tl=$(rs 20 "$W" "dmesg | sed -n \"/$MARK/,\\\$p\" | grep -a 'P241-RECOV-TERMINAL slot=$vslot ' | tail -1")
    reason=$(echo "$tl" | grep -ao 'reason=[0-9]*' | head -1 | tr -dc '0-9')
    echo "  INFO terminal: $(echo "$tl" | cut -c1-230)"
    ck "refusal reason is INTENTS-UNDISCHARGED(8) or POLICY-REFUSED(1)" "$([ "${reason:-0}" = 8 ] || [ "${reason:-0}" = 1 ] && echo yes || echo no)" "yes"
    und=$(rs 20 "$W" "dmesg | sed -n \"/$MARK/,\\\$p\" | grep -a 'P226-FR-INTENTS-UNDISCHARGED slot $vslot' | tail -1")
    echo "  INFO $(echo "$und" | cut -c1-300)"
    window_count_into wc4 "$W" 20 "$MARK" "P226-FR-INTENTS-UNDISCHARGED slot $vslot" "P226-FR-INTENTS-UNDISCHARGED printed for slot  vslot"
    ck "P226-FR-INTENTS-UNDISCHARGED printed for slot $vslot" "$(ge1 "$wc4")" "yes"
    refl=$(rs 20 "$W" "dmesg | sed -n \"/$MARK/,\\\$p\" | grep -a 'slice replay refused' | tail -1")
    echo "  INFO $(echo "$refl" | cut -c1-260)"
    agmask=$(echo "$refl" | grep -ao 'ag_mask=0x[0-9a-f]*' | head -1 | cut -d= -f2)
    window_count_into wc5 "$W" 20 "$MARK" "P163-RECOVERY-COMPLETE slot=$vslot" "ZERO P163-RECOVERY-COMPLETE for slot  vslot (never published as recove"
    ck "ZERO P163-RECOVERY-COMPLETE for slot $vslot (never published as recovered)" "$wc5" "0"
fi

# the completion's evidence, on the node that completed it (W, or after a
# custodian kill, whichever node took the case over)
CNODE=$W
completion_asserts() {
    local n=$1
    measure "$n" 20 "$OUT/dmesg_${n}_completion.txt" '^DMESG_END$' "the completion kernel log on $n" "dmesg | sed -n \"/$MARK/,\\\$p\" | grep -a 'P-OBL-ENGINE-\|P-OBL-DONE-WRITE\|P234-RECOV-OBLIGATIONS-DONE\|P-OBL-COMPLETE\|P-OBLF-\|P163-RECOVERY-COMPLETE slot=$vslot\|P-COMPLETE-RETIRE-TIMING' | cut -c1-230; echo DMESG_END"
    sed 's/^/  INFO /' "$OUT/dmesg_${n}_completion.txt" | head -24
    local freed full
    freed=$(grep -ac 'P-OBL-ENGINE-EXTENT slot='"$vslot"' .*EMPTY->freed' "$OUT/dmesg_${n}_completion.txt")
    full=$(grep -ac 'P-OBL-ENGINE-EXTENT slot='"$vslot"' .*FULL->already-free' "$OUT/dmesg_${n}_completion.txt")
    echo "  MEASURED engine on $n: freed=$freed already_free=$full census_extents=${nextents:-?}"
    if [ "$MODE" = custodian_kill ]; then
        ck "successor found entry 0 FULL (the dead custodian's committed free replayed home)" "$(ge1 "$full")" "yes"
        ck "successor freed the remaining extents (freed + already_free == census extents)" "$(( freed + full ))" "${nextents:-0}"
    else
        ck "engine freed every census extent (EMPTY->freed == extents)" "$freed" "${nextents:-0}"
        ck "no extent read FULL on a first completion" "$full" "0"
    fi
    ck "no SPARSE extent" "$(grep -ac 'P-OBL-ENGINE-SPARSE' "$OUT/dmesg_${n}_completion.txt")" "0"
    ck "completion proof COMMITTED and read back (P-OBL-DONE-WRITE)" "$(ge1 "$(grep -ac 'P-OBL-DONE-WRITE slot='"$vslot" "$OUT/dmesg_${n}_completion.txt")")" "yes"
    ck "OBLIGATIONS_DONE durable (P234-RECOV-OBLIGATIONS-DONE)" "$(ge1 "$(grep -ac 'P234-RECOV-OBLIGATIONS-DONE slot='"$vslot" "$OUT/dmesg_${n}_completion.txt")")" "yes"
    ck "P-OBL-COMPLETE on $n" "$(ge1 "$(grep -ac 'P-OBL-COMPLETE slot='"$vslot" "$OUT/dmesg_${n}_completion.txt")")" "yes"
    wait_for_into t "$n" 90 "$MARK" "P163-RECOVERY-COMPLETE slot=$vslot"; ck "slot $vslot PUBLISHED as recovered only after DONE (P163-RECOVERY-COMPLETE, ${t}s)" "$([ "$t" != timeout ] && echo yes || echo no)" "yes"
    window_count_into wc6 "$n" 20 "$MARK" 'P241-RECOV-TERMINAL' "ZERO P241-RECOV-TERMINAL on  n (nothing quarantined)"
    ck "ZERO P241-RECOV-TERMINAL on $n (nothing quarantined)" "$wc6" "0"
    window_count_into wc7 "$n" 20 "$MARK" 'P-OBLF-AG-TIMEOUT' "ZERO P-OBLF-AG-TIMEOUT on  n (no acquirer outlived the freeze budget)"
    ck "ZERO P-OBLF-AG-TIMEOUT on $n (no acquirer outlived the freeze budget)" "$wc7" "0"
    window_count_into wc8 "$n" 20 "$MARK" "P-OBLF-LIFT slot=$vslot" "freeze lifted on  n (P-OBLF-LIFT after DONE)"
    ck "freeze lifted on $n (P-OBLF-LIFT after DONE)" "$(ge1 "$wc8")" "yes"
    echo "  MEASURED freeze traffic on $n: window_count_into wait "$n" 20 "$MARK" 'P-OBLF-AG-WAIT' "wait" window_count_into eagain "$n" 20 "$MARK" 'P-OBLF-AG-EAGAIN' "eagain""
    window_count_into wc11 "$n" 20 "$MARK" 'Shutting down filesystem' "n not shut down"
    ck "$n not shut down" "$wc11" "0"
    window_count_into wc12 "$n" 20 "$MARK" 'Corruption of in-memory' "n no in-memory corruption line"
    ck "$n no in-memory corruption line" "$wc12" "0"
    window_into "$OUT/rv_rv3_3.txt" "$n" 20 "$MARK"; rv3=$(cat "$OUT/rv_rv3_3.txt" | grep -ac '\bBUG: \|Oops\|WARNING: ' | tr -dc '0-9')
    ck "$n no kernel BUG/Oops/WARNING" "$rv3" "0"
}
free_query() {
    # the platter answer for every extent the engine touched: FREE afterwards
    local n=$1 q="" line
    while read -r line; do
        q="$q --free-query $(echo "$line" | grep -ao 'agno=[0-9]*' | cut -d= -f2):$(echo "$line" | grep -ao 'agbno=[0-9]*' | cut -d= -f2):$(echo "$line" | grep -ao 'len=[0-9]*' | cut -d= -f2)"
    done < <(grep -a 'P-OBL-ENGINE-EXTENT slot='"$vslot" "$OUT/dmesg_${n}_completion.txt" | head -16)
    [ -n "$q" ] || { echo "  MEASURED free-query: no engine extent lines to query"; return; }
    local tq=$(date +%s)
    # s70: the query used to be asked of the host image (MXFS_SCST_IMG), which
    # on the qnap rig is the OTHER rig's filesystem — a well-formed FREE from
    # the wrong device.  It is asked of the resolved LUN on the node that
    # completed the case, through the checker's query-only mode (no exclusion,
    # so a mounted node may answer; the cached pages are dropped first).
    measure "$n" 300 "$OUT/chk_free_query.txt" '^  FREE-QUERY ' "the free query on $n" "/src/mxfs/tools/chk_mxfs --query-only $q $MXFS_DEV 2>&1"
    echo "  INFO chk_mxfs free-query on $n wall=$(( $(date +%s) - tq ))s: $(grep -a 'FREE-QUERY' "$OUT/chk_free_query.txt" | tr '\n' ';' | cut -c1-300)"
    local nq nf
    nq=$(grep -ac 'FREE-QUERY' "$OUT/chk_free_query.txt"); nf=$(grep -ac 'FREE-QUERY.*: FREE ' "$OUT/chk_free_query.txt")
    if [ "$CHURN" = 1 ]; then
        echo "  MEASURED platter: $nf of $nq obligation extents FREE (churn may have re-allocated them legitimately; reported, not asserted)"
    else
        ck "every obligation extent reads FREE on the platter (chk_mxfs --free-query)" "$nf/$nq" "$nq/$nq"
        ck "free-query answered every extent" "$(ge1 "$nq")" "yes"
    fi
}
if [ $FIX = 1 ] && [ "$MODE" != custodian_kill ]; then
    if [ -n "$CHURN_PID" ]; then
        rs 15 "$W" "rm -f /tmp/churn_go_$LABEL; sleep 2; cat /tmp/churn_$LABEL.log; echo errlines=\$(wc -l < /tmp/churn_$LABEL.err 2>/dev/null || echo 0); head -3 /tmp/churn_$LABEL.err 2>/dev/null" > "$OUT/churn.txt" 2>/dev/null
        echo "  MEASURED churn on $W: $(tr '\n' ' ' < "$OUT/churn.txt")"
        ck "churn ran (ops>=1)" "$(ge1 "$(grep -ao 'ops=[0-9]*' "$OUT/churn.txt" | cut -d= -f2)")" "yes"
        ck "churn saw ZERO errors through the freeze" "$(grep -ao 'errs=[0-9]*' "$OUT/churn.txt" | cut -d= -f2)" "0"
    fi
    completion_asserts "$W"
    free_query "$W"
elif [ $FIX = 0 ]; then
    window_count_into wc13 "$W" 20 "$MARK" 'Shutting down filesystem' "W not shut down"
    ck "W not shut down" "$wc13" "0"
    window_count_into wc14 "$W" 20 "$MARK" 'Corruption of in-memory' "W no in-memory corruption line"
    ck "W no in-memory corruption line" "$wc14" "0"
fi

# ── 4. the consequence on the survivor: creates inside and outside the mask ──
if [ "$MODE" != custodian_kill ]; then
    measure "$W" 60 "$OUT/rv_probe_4.txt" '^listed_dir=' "probe on $W" "t=\$(date +%s%N); e=\$(timeout 20 mkdir $DIR/w_in_mask_$LABEL 2>&1); echo in_rc=\$? in_ms=\$(( (\$(date +%s%N)-t)/1000000 )) in_err=[\$e]; t=\$(date +%s%N); e=\$(timeout 20 mkdir $MNT/w_out_mask_$LABEL 2>&1); echo out_rc=\$? out_ms=\$(( (\$(date +%s%N)-t)/1000000 )) out_err=[\$e]; echo listed_dir=\$(ls $DIR 2>&1 | head -3 | tr '\n' ' ')"; probe=$(cat "$OUT/rv_probe_4.txt" | tr '\n' ' ')
    echo "  MEASURED survivor after the verdict (ag_mask=${agmask:-?}, V's dir ino $DINO): $probe"
    rs 20 "$W" "dmesg | sed -n \"/$MARK/,\\\$p\" | grep -a 'P240-QUAR' | tail -4 | cut -c1-230" | sed 's/^/  INFO /'
    if [ $FIX = 1 ]; then
        ck "survivor's create INSIDE the former mask succeeds" "$(echo "$probe" | grep -ao 'in_rc=[0-9]*' | cut -d= -f2)" "0"
        ck "survivor's create outside the mask succeeds" "$(echo "$probe" | grep -ao 'out_rc=[0-9]*' | cut -d= -f2)" "0"
        window_count_into wc15 "$W" 20 "$MARK" 'P240-QUAR' "ZERO P240-QUAR lines on W"
        ck "ZERO P240-QUAR lines on W" "$wc15" "0"
    else
        echo "  MEASURED open obligations: $(echo "$und" | grep -ao '[0-9]* intent obligation(s)' | head -1); $(echo "$split" | grep -ao 'recover=[0-9]* recover_mask=0x[0-9a-f]* quarantine=[0-9]*')"
    fi
fi

# ── 5. the victim returns (and, after a custodian kill, the custodian too) ──
KO_MD5=$(md5sum mxfs.ko | cut -c1-32)
rejoin() {
    local n=$1 i=0 vm
    $VIRSH start "$n" >/dev/null 2>&1; echo "  INFO virsh start $n rc=$? (+$(el)s)"
    while [ $i -lt 120 ]; do rs 8 "$n" "echo up" 2>/dev/null | grep -q up && break; sleep 5; i=$((i+5)); done
    echo "  INFO $n ssh back after ${i}s"
    [ $i -lt 120 ] || { echo "  MEASURED $n remount: did not come back within 120 s"; return 1; }
    # A freshly booted node has no module: the join is exactly what the fleet
    # prep does per node (NFS-mount the tree, copy and insmod its mxfs.ko
    # with force_transport=1, mount).  prep_node.sh does not format.
    measure "$n" 200 "$OUT/rv_vm_$n.txt" '^prep_rc=' "the remount of $n" "mountpoint -q /src || { mkdir -p /src; mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp; }; echo '$MARK' > /dev/kmsg 2>/dev/null; t=\$(date +%s%N); MXFS_DEV='$MXFS_DEV' MXFS_KO_MD5='$KO_MD5' timeout 180 bash /src/mxfs/tests/setup/prep_node.sh tcp > /tmp/prep_node_$LABEL.log 2>&1; rc=\$?; echo prep_rc=\$rc prep_ms=\$(( (\$(date +%s%N)-t)/1000000 )) mounted=\$(grep -c ' $MNT mxfs ' /proc/mounts); tail -3 /tmp/prep_node_$LABEL.log | tr '\n' ' '"; vm=$(tr '\n' ' ' < "$OUT/rv_vm_$n.txt")
    echo "  MEASURED $n remount (prep_node.sh tcp): $vm"
    if [ "$MODE" = custodian_kill ] && [[ "$vm" != *"mounted=1"* ]] &&
       [ "$(rs 20 "$n" "dmesg | sed -n \"/$MARK/,\\\$p\" | grep -ac 'P-PR-DEADGATE-LIVE'")" -ge 1 ] 2>/dev/null; then
        # the live member still holds the sole-survivor gate (the case has
        # not published yet): the designed refusal at admission.  One
        # bounded retry; the refusal itself stays on the record above.
        echo "  MEASURED $n was refused under a LIVE gate holder (P-PR-DEADGATE-LIVE); retrying the prep once after 20 s (+$(el)s)"
        sleep 20
        measure "$n" 200 "$OUT/rv_vm_5.txt" '^prep_rc=' "vm on $n" "echo '$MARK' > /dev/kmsg 2>/dev/null; t=\$(date +%s%N); MXFS_DEV='$MXFS_DEV' MXFS_KO_MD5='$KO_MD5' timeout 180 bash /src/mxfs/tests/setup/prep_node.sh tcp > /tmp/prep_node_${LABEL}_retry.log 2>&1; rc=\$?; echo prep_rc=\$rc prep_ms=\$(( (\$(date +%s%N)-t)/1000000 )) mounted=\$(grep -c ' $MNT mxfs ' /proc/mounts); tail -3 /tmp/prep_node_${LABEL}_retry.log | tr '\n' ' '"; vm=$(cat "$OUT/rv_vm_5.txt" | tr '\n' ' ')
        echo "  MEASURED $n remount retry (prep_node.sh tcp): $vm"
    fi
    rs 30 "$n" "dmesg | sed -n \"/$MARK/,\\\$p\"" > "$OUT/dmesg_${n}_remount.txt" 2>/dev/null
    grep -a 'REFUSED\|QUARANT\|P234\|P238\|P241\|P163\|refus\|Ending clean mount\|barrier\|P-OBL\|P-OBLF' "$OUT/dmesg_${n}_remount.txt" | tail -10 | cut -c1-230 | sed "s/^/  INFO $n: /"
    LAST_VM=$vm
    if [ $FIX = 1 ]; then
        ck "$n remounted (prep_rc=0)" "$(echo "$vm" | grep -ao 'prep_rc=[0-9]*' | cut -d= -f2)" "0"
        ck "$n mounted" "$(echo "$vm" | grep -ao 'mounted=[0-9]*' | cut -d= -f2)" "1"
    fi
    return 0
}
rejoin "$V"
if [ "$MODE" = terminal_rejoin ]; then
    window_count_into gate "$W" 20 "$MARK" 'P-PR-GATE-ISSUE\|P-PR-GATE-ALREADY' "gate"; window_count_into depc "$W" 20 "$MARK" "P-PR-GATE-DEP-CLEAR slot=$vslot why=refused-terminal" "depc"
    window_count_into rest "$W" 20 "$MARK" 'P-PR-GATE-RESTORE site=refused-terminal' "rest"; window_count_into restany "$W" 20 "$MARK" 'P-PR-GATE-RESTORE site=' "restany"
    window_count_into owed "$W" 20 "$MARK" 'P-PR-GATE-RESTORE-OWED' "owed"; window_count_into heldl "$W" 20 "$MARK" 'P-PR-GATE-RESTORE-HELD' "heldl"; window_count_into pend "$W" 20 "$MARK" 'P-PR-GATE-RESTORE-PENDING' "pend"
    rs 20 "$W" "dmesg | sed -n \"/$MARK/,\\\$p\" | grep -a 'P-PR-GATE\|P241-RECOV-TERMINAL slot=$vslot\|P303-FENCECAP-WRONGTYPE' | cut -c1-230" | sed "s/^/  INFO $W: /"
    vrc=$(echo "$LAST_VM" | grep -ao 'prep_rc=[0-9]*' | cut -d= -f2); vmnt=$(echo "$LAST_VM" | grep -ao 'mounted=[0-9]*' | cut -d= -f2)
    vref=$(grep -ac 'P-PRKEY-PUBLISHED.*rc=-52' "$OUT/dmesg_${V}_remount.txt"); vimp=$(grep -ac 'P241-RECOV-TERMINAL-IMPORT\|P241-RECOV-TERMINAL-SCAN' "$OUT/dmesg_${V}_remount.txt")
    echo "  RESULT terminal_rejoin GATE_INSTALLED=$gate DEP_CLEAR_TERMINAL=$depc RESTORE_TERMINAL=$rest RESTORE_ANY=$restany OWED=$owed HELD=$heldl PENDING=$pend V_prep_rc=${vrc:-none} V_mounted=${vmnt:-none} V_PUBLISH_REFUSED=$vref V_IMPORTED_VERDICT=$vimp"
    if [ "${gate:-0}" -ge 1 ]; then
        reached=1
        ck "W published the terminal verdict and released its gate dependant (DEP-CLEAR why=refused-terminal)" "$(ge1 "$depc")" "yes"
        if [ "$EXPECT" = refuse ]; then
            ck "(control) nothing drove the restore after the verdict (RESTORE=0)" "${restany:-na}" "0"
            ck "(control) the returned victim was refused at its PR-ledger publish (rc=-52)" "$(ge1 "$vref")" "yes"
            ck "(control) the returned victim did not mount" "${vmnt:-none}" "0"
        else
            ck "the terminal publication drove the restore (P-PR-GATE-RESTORE site=refused-terminal)" "$(ge1 "$rest")" "yes"
            ck "the returned victim was not refused at its PR-ledger publish" "${vref:-na}" "0"
            ck "the returned victim remounted (prep_rc=0)" "${vrc:-none}" "0"
            ck "the returned victim is mounted" "${vmnt:-none}" "1"
            ck "the returned victim imported the terminal verdict (P241-RECOV-TERMINAL-IMPORT)" "$(ge1 "$vimp")" "yes"
            measure "$V" 60 "$OUT/rv_vc_6.txt" '^[0-9]+$' "vc on $V" "t=\$(date +%s%N); e=\$(timeout 20 mkdir $DIR/v_back_$LABEL 2>&1); echo in_rc=\$? in_ms=\$(( (\$(date +%s%N)-t)/1000000 )) in_err=[\$e]; t=\$(date +%s%N); e=\$(timeout 20 mkdir $MNT/v_out_$LABEL 2>&1); echo out_rc=\$? out_ms=\$(( (\$(date +%s%N)-t)/1000000 )) out_err=[\$e]; dmesg | sed -n \"/$MARK/,\\\$p\" | grep -ac 'P240-QUAR-NSOP-REFUSE\|P240-QUAR-REFUSE' || [ \$? = 1 ]"; vc=$(cat "$OUT/rv_vc_6.txt" | tr '\n' ' ')
            echo "  MEASURED returned victim: $vc"
            ck "the quarantine is still in force on the returned victim (create in its former directory refused, rc!=0)" "$([ "$(echo "$vc" | grep -ao 'in_rc=[0-9]*' | cut -d= -f2)" != 0 ] && echo yes || echo no)" "yes"
            ck "the returned victim logged the quarantine refusal (P240-QUAR-*-REFUSE >= 1)" "$(ge1 "$(echo "$vc" | awk '{print $NF}')")" "yes"
            ck "the returned victim creates outside the quarantined domain" "$(echo "$vc" | grep -ao 'out_rc=[0-9]*' | cut -d= -f2)" "0"
            window_into "$OUT/rv_rv7_7.txt" "$V" 20 "$MARK"; rv7=$(cat "$OUT/rv_rv7_7.txt" | grep -ac '\bBUG: \|Oops\|WARNING: ' | tr -dc '0-9')
            ck "V no kernel BUG/Oops/WARNING" "$rv7" "0"
        fi
        value_now_into rv8 "$W" 15 "$OUT/rv_rv8_8.txt" '^[0-9]+$' "rv8 on $W" "grep -c ' $MNT mxfs ' /proc/mounts || [ \$? = 1 ]"
        ck "W still mounted" "$rv8" "1"
        window_count_into wc23 "$W" 20 "$MARK" 'Shutting down filesystem' "W not shut down after the victim s return"
        ck "W not shut down after the victim's return" "$wc23" "0"
    else
        reached=0
        echo "  NOTE the gate was never installed on $W (V's key was still registered when W fenced it, or W was not the sole survivor): this lap says nothing about the gate restore"
    fi
fi
if [ "$MODE" = custodian_kill ]; then
    rejoin "$W"
    # whichever node took the case over completes it; both are up now
    for n in $V $W; do
        if [ "$(waitfor "$n" "P-OBL-COMPLETE slot=$vslot" 6)" != timeout ]; then CNODE=$n; break; fi
    done
    if [ "$CNODE" = "$W" ] && [ "$(cnt "$W" "P-OBL-COMPLETE slot=$vslot")" = 0 ]; then
        wait_for_into t "$V" 180 "$MARK" "P-OBL-COMPLETE slot=$vslot"; [ "$t" != timeout ] && CNODE=$V
        [ "$t" = timeout ] && { wait_for_into t "$W" 60 "$MARK" "P-OBL-COMPLETE slot=$vslot"; [ "$t" != timeout ] && CNODE=$W; }
    fi
    echo "  INFO the takeover completion ran on $CNODE (+$(el)s)"
    window_count_into wc24 "$CNODE" 20 "$MARK" "P-OBL-COMPLETE slot=$vslot" "the case was completed after the custodian s death (P-OBL-COMPLETE on"
    ck "the case was completed after the custodian's death (P-OBL-COMPLETE on a successor)" "$(ge1 "$wc24")" "yes"
    completion_asserts "$CNODE"
    free_query "$CNODE"
    for n in $V $W; do
        value_now_into rv9 "$n" 15 "$OUT/rv_rv9_9.txt" '^[0-9]+$' "rv9 on $n" "grep -c ' $MNT mxfs ' /proc/mounts || [ \$? = 1 ]"
        ck "$n mounted at the end" "$rv9" "1"
    done
fi
if [ $FIX = 1 ]; then
    measure "$V" 40 "$OUT/rv_vc_10.txt" '^listed=' "vc on $V" "t=\$(date +%s%N); e=\$(timeout 20 mkdir $DIR/v_back_$LABEL 2>&1); echo v_rc=\$? v_ms=\$(( (\$(date +%s%N)-t)/1000000 )) v_err=[\$e]; echo listed=\$(ls $DIR 2>&1 | wc -l)"; vc=$(cat "$OUT/rv_vc_10.txt" | tr '\n' ' ')
    echo "  MEASURED returned victim creates in its former directory: $vc"
    ck "returned victim creates in its former directory" "$(echo "$vc" | grep -ao 'v_rc=[0-9]*' | cut -d= -f2)" "0"
    window_into "$OUT/rv_rv11_11.txt" "$V" 20 "$MARK"; rv11=$(cat "$OUT/rv_rv11_11.txt" | grep -ac '\bBUG: \|Oops\|WARNING: ' | tr -dc '0-9')
    ck "V no kernel BUG/Oops/WARNING" "$rv11" "0"
fi

echo "=== d_intents_2tcp_open_efi $LABEL: fails=$fails wall=$(el)s out=$OUT$([ $FIX = 0 ] && echo ' — the LUN carries a quarantined slice: re-prep before any other test') ==="
[ "$fails" -eq 0 ]
