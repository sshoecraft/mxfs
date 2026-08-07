#!/bin/bash
# tests/guard_race_arms.sh — race arms for the recovery GUARD (0.11.355/356,
# D-DESTAGE-TEAR closure evidence).  Uses the mxfs.ubsweep_hold_ms debug knob
# (0.11.356) to stretch the guarded unclaimed-bucket sweep window from ~100ms
# to minutes so the two races become directly testable:
#
#   joiner    — while a survivor HOLDS the guard on dead B's slot S, boot and
#               mount B again.  The joiner's claim path must SKIP the guarded
#               slot (never judge, never steal) and claim a DIFFERENT slot;
#               the holder's sweep must complete rc=0 (guard never lost).
#   abandoned — while a survivor HOLDS the guard on S, virsh-destroy the
#               holder.  A peer's next unclaimed-bucket pass must detect the
#               corpse guard by CHANGE-DETECTION (timestamp unmoved across
#               ~3 refresh intervals — no cross-node clock math), reclaim it,
#               and complete the sweep rc=0.
#
# Setup recipe per arm (the real producer, from openunlink_deaths):
#   fd-holder node keeps the victim file open; B unlinks it and is destroyed.
#   The zombie parks on B's AGI bucket and DEFERS (fd held) — so B's slot goes
#   unclaimed with a provably NONEMPTY bucket, and every unclaimed-bucket pass
#   guards S until the fd closes.  Closing the fd ends the arm (reap frees).
#
# dmesg persists across invocations, so every detection below is a per-node
# COUNT-GROWTH test against a snapshot, never "line exists".
#
# Budget (RULE 0):
#   joiner:    death detect->hold <=150s + boot+rejoin ~120s (inside 180s
#              hold) + sweep-done <=200s + reap <=90s + knob reset  => cap 560s
#   abandoned: detect ~50s + destroy holder + peer takeover <=330s (62s lease
#              + batch + 3s abandon probe + guard) + takeover hold 45s +
#              sweep-done <=120s + reap <=90s + parallel restore ~150s
#                                                                   => cap 590s
#
#   stale_resume — holder takes the guard, holds ~15s, then STALLS (no
#               refresh, via mxfs.ubsweep_stall_ms) for 150s and RESUMES.
#               NB rejoins during the stall; its mount-settle scan probes the
#               frozen guard, judges it abandoned, reclaims, sweeps rc=0.
#               The resumed holder must CAS-fail its next refresh
#               (P99-GUARD-LOST), abort with rc=-116, and sweep NOTHING.
#   inherit   — bucketed shape with NO holds: after B dies and the deferred
#               zombie parks on B's bucket S, B rejoins, must re-claim the
#               SAME slot S (only vacancy in a dense rig) and thereby inherit
#               the nonempty bucket.  Closing the fd must then free the
#               zombie with ZERO further recovery events (P163 counters
#               frozen) — the ordinary last-close liveness path.
#
# usage: guard_race_arms.sh joiner|abandoned|stale_resume|inherit [B=test2] [FDH=test1]
set -u
ARM="${1:?usage: guard_race_arms.sh joiner|abandoned|stale_resume|inherit [B] [FDH]}"
case "$ARM" in joiner|abandoned|stale_resume|inherit) ;; *) echo "unknown arm '$ARM'"; exit 2 ;; esac
NB="${2:-test2}"          # the node that unlinks and dies (its slot gets guarded)
FDH="${3:-test1}"         # the fd holder (stays alive; keeps the bucket nonempty)
SSH=tools/mxfs_sshpass.sh
VIRSH="virsh -c qemu:///system"
N="${MXFS_NODES:-32}"
RUNID="gra_$(date +%s)_$$"
D="/mnt/shared/.${RUNID}"
T=$(mktemp -d)
KOMD5=$(md5sum mxfs.ko 2>/dev/null | awk '{print $1}')

ALL=(); for i in $(seq 1 "$N"); do ALL+=("test$i"); done
SURV=(); for n in "${ALL[@]}"; do [ "$n" != "$NB" ] && SURV+=("$n"); done

say() { echo "[$(date +%H:%M:%S)] $*"; }

DEV=$($SSH "$FDH" "mount -t mxfs | awk '{print \$1; exit}'" 2>/dev/null | tr -d ' \r\n')
[ -z "$DEV" ] && DEV=/dev/mapper/mpatha

set_knob() { # set_knob <hold_ms> [stall_ms] — on every live survivor, parallel
  local hold="$1" stall="${2:-0}" n
  for n in "${SURV[@]}"; do
    ( $SSH "$n" "echo $hold > /sys/module/mxfs/parameters/ubsweep_hold_ms; echo $stall > /sys/module/mxfs/parameters/ubsweep_stall_ms" \
        >/dev/null 2>&1 ) &
  done
  wait
}

cnt() { # cnt <node> <pattern> — dmesg count of pattern on node
  local c
  c=$($SSH "$1" "dmesg | grep -c '$2'" 2>/dev/null | tr -d ' \r\n')
  echo "${c:-0}"
}

snap_counts() { # snap_counts <tag> <pattern> — per-survivor counts to $T/cnt.<tag>.<node>
  local tag="$1" pat="$2" n
  for n in "${SURV[@]}"; do
    ( cnt "$n" "$pat" > "$T/cnt.$tag.$n" ) &
  done
  wait
}

scan_new() { # scan_new <tag> <pattern> — "node|last-line" for survivors whose count grew
  local tag="$1" pat="$2" n sd
  sd=$(mktemp -d -p "$T")
  for n in "${SURV[@]}"; do
    ( local c b
      c=$(cnt "$n" "$pat")
      b=$(cat "$T/cnt.$tag.$n" 2>/dev/null || echo 0)
      if [ "${c:-0}" -gt "${b:-0}" ]; then
        L=$($SSH "$n" "dmesg | grep '$pat' | tail -1" 2>/dev/null | tr -d '\r')
        echo "$n|$L" > "$sd/$n"
      fi ) &
  done
  wait
  cat "$sd"/* 2>/dev/null
}

boot_rejoin() { # boot_rejoin <node> — start VM if down, restore, prep+mount
  local node="$1" t=0
  $VIRSH start "$node" >/dev/null 2>&1
  while [ $t -lt 180 ]; do
    $SSH "$node" "echo up" >/dev/null 2>&1 && break
    sleep 5; t=$((t+5))
  done
  $SSH "$node" "
    mountpoint -q /src || { mkdir -p /src; mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; }
    iscsiadm -m discovery -t st -p 192.168.120.1:3260 >/dev/null 2>&1
    iscsiadm -m discovery -t st -p 192.168.120.2:3260 >/dev/null 2>&1
    iscsiadm -m node --login >/dev/null 2>&1
    iscsiadm -m session --rescan >/dev/null 2>&1
    multipath >/dev/null 2>&1" >/dev/null 2>&1
  local t2=0
  while [ $t2 -lt 90 ]; do
    $SSH "$node" "[ -e '$DEV' ] && mountpoint -q /src && echo DEV_UP" 2>/dev/null | grep -q DEV_UP && break
    $SSH "$node" "multipath >/dev/null 2>&1" >/dev/null 2>&1
    sleep 5; t2=$((t2+5))
  done
  $SSH "$node" "MXFS_DEV='$DEV' MXFS_KO_MD5='$KOMD5' bash /src/mxfs/tests/setup/prep_node.sh caw" >/dev/null 2>&1
  $SSH "$node" "mount -t mxfs | grep -q mxfs"
}

CLEANED=0
RESTORE=("$NB")
cleanup() {
  [ "$CLEANED" = 1 ] && return
  CLEANED=1
  say "cleanup: fd released, knob=0 everywhere, victims restored"
  $SSH "$FDH" "pkill -f $RUNID" >/dev/null 2>&1
  set_knob 0
  local v pids=()
  for v in "${RESTORE[@]:-}"; do
    [ -n "$v" ] || continue
    boot_rejoin "$v" >/dev/null 2>&1 &
    pids+=($!)
  done
  [ "${#pids[@]}" -gt 0 ] && wait "${pids[@]}"
  set_knob 0
}
trap cleanup EXIT

fail() { echo "RESULT: FAIL | case=guard_race_$ARM | $*"; exit 1; }

# ── produce the guarded state: fd on FDH, unlink+death on NB ──────────────
say "arm=$ARM  B=$NB (dies)  fd-holder=$FDH  survivors=${#SURV[@]}"
for n in "$FDH" "$NB"; do
  $SSH "$n" "mount -t mxfs | grep -q mxfs" || fail "$n not mounted (prep the rig first)"
done

HOLD_MS=180000; STALL_MS=0
case "$ARM" in
  abandoned)    HOLD_MS=45000 ;;
  stale_resume) HOLD_MS=15000; STALL_MS=240000 ;;
  inherit)      HOLD_MS=0 ;;
esac
say "setting ubsweep_hold_ms=$HOLD_MS ubsweep_stall_ms=$STALL_MS on all survivors + snapshotting counters"
set_knob "$HOLD_MS" "$STALL_MS"
snap_counts hold "P99-UBSWEEP-HOLD"
if [ "$ARM" = inherit ]; then
  NBSLOT=$($SSH "$NB" "dmesg | grep -E 'claimed heartbeat slot' | tail -1" 2>/dev/null | sed -n 's/.*claimed heartbeat slot \([0-9]*\).*/\1/p')
  [ -n "$NBSLOT" ] || fail "cannot determine $NB's current slot"
  say "$NB currently on slot $NBSLOT"
  snap_counts p97 "P97-SWEEP-AG.*bucket=$NBSLOT "
fi

$SSH "$FDH" "mkdir -p $D && echo GRA-$RUNID > $D/f" >/dev/null 2>&1
INO=$($SSH "$FDH" "stat -c '%i' $D/f" 2>/dev/null | tr -d ' \r\n')
[ -z "$INO" ] && fail "victim create failed"
# inode numbers are reused across tests, so convergence is count-growth too
PAT_REAP="P89-REAP-DONE ino=${INO}\b|P98-ORPHAN-ADOPT ino=${INO}\b"
C0=$($SSH "$FDH" "dmesg | grep -cE '$PAT_REAP'" 2>/dev/null | tr -d ' \r\n')
A0=$(cnt "$FDH" "P98-ORPHAN-ADOPT ino=${INO} ")
# holder bash stays RESIDENT (trailing ':' defeats the tail-exec optimization
# that would erase $RUNID from the cmdline) and the sleep child gets fd9
# CLOSED (9<&-) — so pkill -f $RUNID kills the one and only fd holder.
$SSH "$FDH" "nohup bash -c 'exec 9<$D/f; sleep 900 9<&-; :' </dev/null >/dev/null 2>&1 &" >/dev/null 2>&1
sleep 1
$SSH "$NB" "rm $D/f" >/dev/null 2>&1
sleep 3
say "destroying $NB (victim ino=$INO)"
$VIRSH destroy "$NB" >/dev/null 2>&1

if [ "$ARM" = inherit ]; then
  # ── inherit arm: bucketed shape, no holds; joiner re-claims its old slot
  #    and inherits the deferred zombie; ordinary last close must free it
  #    with zero further recovery events. ─────────────────────────────────
  BK=""; TW=0
  while [ $TW -lt 150 ]; do
    R=$(scan_new p97 "P97-SWEEP-AG.*bucket=$NBSLOT " | head -1)
    if [ -n "$R" ]; then BK="$R"; break; fi
    A1=$(cnt "$FDH" "P98-ORPHAN-ADOPT ino=${INO} ")
    if [ "${A1:-0}" -gt "${A0:-0}" ]; then
      echo "RESULT: RETRY | case=guard_race_inherit | shape=torn ino=$INO (bucketless adopt — bucket insert did not land this death)"
      exit 2
    fi
    sleep 10; TW=$((TW+10))
  done
  [ -n "$BK" ] || fail "no bucket-$NBSLOT sweep observed in 150s (ino=$INO)"
  say "bucketed shape confirmed on ${BK%%|*}: '${BK#*|}'"
  boot_rejoin "$NB" || fail "$NB failed to rejoin"
  RESTORE=()
  CL=$($SSH "$NB" "dmesg | grep -E 'claimed heartbeat slot' | tail -1" 2>/dev/null | tr -d '\r')
  NEWSLOT=$(sed -n 's/.*claimed heartbeat slot \([0-9]*\).*/\1/p' <<<"$CL")
  say "joiner claim: '$CL'"
  [ "$NEWSLOT" = "$NBSLOT" ] || fail "joiner claimed slot ${NEWSLOT:-none}, expected its old slot $NBSLOT (rig not dense — full prep first)"
  # From here on, NO recovery event may fire; the free must come from the
  # ordinary last-close path (inline inactivation or the 30s reap retry).
  snap_counts p163 "P163-RECOVERY-COMPLETE"
  N163=$(cnt "$NB" "P163-RECOVERY-COMPLETE")
  snap_counts rem "P82-REM ino=${INO} "
  snap_counts reap "P89-REAP-DONE ino=${INO}"
  NREM=$(cnt "$NB" "P82-REM ino=${INO} "); NREAP=$(cnt "$NB" "P89-REAP-DONE ino=${INO}")
  say "closing fd on $FDH; ordinary last close must free ino=$INO"
  $SSH "$FDH" "pkill -f $RUNID" >/dev/null 2>&1
  FREED=""; TW2=0
  while [ $TW2 -lt 120 ]; do
    R=$(scan_new rem "P82-REM ino=${INO} " | head -1)
    [ -z "$R" ] && R=$(scan_new reap "P89-REAP-DONE ino=${INO}" | head -1)
    if [ -z "$R" ]; then
      R1=$(cnt "$NB" "P82-REM ino=${INO} "); R2=$(cnt "$NB" "P89-REAP-DONE ino=${INO}")
      [ "${R1:-0}" -gt "${NREM:-0}" ] || [ "${R2:-0}" -gt "${NREAP:-0}" ] && R="$NB|(fresh-boot count growth rem=$R1 reap=$R2)"
    fi
    if [ -n "$R" ]; then FREED="$R"; break; fi
    sleep 10; TW2=$((TW2+10))
  done
  [ -n "$FREED" ] || fail "zombie ino=$INO not freed within 120s of ordinary last close"
  NR=$(scan_new p163 "P163-RECOVERY-COMPLETE" | head -1)
  N163b=$(cnt "$NB" "P163-RECOVERY-COMPLETE")
  [ -z "$NR" ] && [ "${N163b:-0}" = "${N163:-0}" ] || fail "a recovery event fired during the last-close window: ${NR:-$NB p163 $N163->$N163b}"
  cleanup
  echo "RESULT: PASS | case=guard_race_inherit | slot=$NBSLOT joiner_reclaimed=1 freed_by='${FREED%%|*}' after=${TW2}s recovery_events=0 ino=$INO"
  exit 0
fi

# ── wait for a survivor to take the guard and enter the HOLD ──────────────
HOLDER=""; HSLOT=""
TW=0
while [ $TW -lt 150 ]; do
  R=$(scan_new hold "P99-UBSWEEP-HOLD" | head -1)
  if [ -n "$R" ]; then
    HOLDER="${R%%|*}"
    HSLOT=$(sed -n 's/.*P99-UBSWEEP-HOLD slot=\([0-9]*\).*/\1/p' <<<"$R")
    break
  fi
  sleep 10; TW=$((TW+10))
done
if [ -z "$HOLDER" ]; then
  # No guarded sweep can also mean the death produced the TORN shape: the
  # bucket insert was lost, the zombie went BUCKETLESS, and the orphan scan
  # adopted it (P98-ORPHAN-ADOPT) — nothing on the dead slot's bucket, so
  # there is nothing to guard.  That is correct kernel behavior but the
  # wrong shape for this arm; signal the driver to retry with a new victim.
  A1=$(cnt "$FDH" "P98-ORPHAN-ADOPT ino=${INO} ")
  if [ "${A1:-0}" -gt "${A0:-0}" ]; then
    echo "RESULT: RETRY | case=guard_race_$ARM | shape=torn ino=$INO (bucketless adopt path took it — guard precondition absent this death)"
    exit 2
  fi
  fail "no survivor entered P99-UBSWEEP-HOLD within 150s and no adopt either (ino=$INO)"
fi
say "guard holder=$HOLDER slot=$HSLOT (after ${TW}s)"
PAT_HOLD="P99-UBSWEEP-HOLD slot=$HSLOT "
PAT_DONE="P99-UBSWEEP-DONE slot=$HSLOT rc="
PAT_GUARD="P99-GUARD slot=$HSLOT "
# Baselines at detection: the detected hold has logged HOLD but (with 45s+
# holds and ~10s detection lag) not yet DONE.  Old DONE lines from earlier
# boots/tests are frozen into these baselines and cancel out in the deltas.
H0=$(cnt "$HOLDER" "$PAT_HOLD"); D0=$(cnt "$HOLDER" "$PAT_DONE")

if [ "$ARM" = joiner ]; then
  # ── joiner arm: boot+mount NB while the guard is HELD ───────────────────
  say "booting $NB back INTO the hold window"
  boot_rejoin "$NB" || fail "joiner $NB failed to boot+mount during hold"
  # In-hold certificate, sampled within ~2s of the mount.  Holds are serial
  # per node; each completed hold adds 1 to both counts, so unfinished-now =
  # (dH - dD) + 1 (the detected hold was unfinished at baseline time).
  NH=$(cnt "$HOLDER" "$PAT_HOLD"); ND=$(cnt "$HOLDER" "$PAT_DONE")
  INHOLD=$(( (NH - H0) - (ND - D0) + 1 ))
  CL=$($SSH "$NB" "dmesg | grep -E 'claimed heartbeat slot' | tail -1" 2>/dev/null | tr -d '\r')
  NEWSLOT=$(sed -n 's/.*claimed heartbeat slot \([0-9]*\).*/\1/p' <<<"$CL")
  RACES=$($SSH "$NB" "dmesg | grep -c 'P130-CLAIM-RACE'" 2>/dev/null | tr -d ' \r\n')
  say "joiner claim: '$CL' races=$RACES holder dH=$((NH-H0)) dD=$((ND-D0)) inhold=$INHOLD"
  [ -n "$NEWSLOT" ] || fail "joiner has no claim line"
  [ "$INHOLD" -gt 0 ] || fail "inconclusive: no hold in progress when joiner claimed (dH=$((NH-H0)) dD=$((ND-D0))) — raise HOLD_MS"
  [ "$NEWSLOT" != "$HSLOT" ] || fail "joiner claimed the GUARDED slot $HSLOT"
  # holder must finish this hold's sweep with the guard intact
  TW2=0; NDF="$ND"
  while [ $TW2 -lt 200 ]; do
    NDF=$(cnt "$HOLDER" "$PAT_DONE")
    [ "${NDF:-0}" -gt "${ND:-0}" ] && break
    sleep 10; TW2=$((TW2+10))
  done
  [ "${NDF:-0}" -gt "${ND:-0}" ] || fail "holder $HOLDER never finished UBSWEEP on slot $HSLOT"
  DONE=$($SSH "$HOLDER" "dmesg | grep '$PAT_DONE' | tail -1" 2>/dev/null | tr -d '\r')
  RC=$(sed -n 's/.*rc=\(-\?[0-9]*\).*/\1/p' <<<"$DONE")
  say "holder sweep done: '$DONE'"
  [ "$RC" = "0" ] || fail "holder sweep rc=$RC (guard lost or sweep error) — '$DONE'"
  RESTORE=()   # NB is already back
elif [ "$ARM" = stale_resume ]; then
  # ── stale_resume arm: holder stalls (no refresh); NB rejoins and its
  #    settle scan reclaims the frozen guard; the resumed holder must lose
  #    its refresh CAS and abort having swept NOTHING. ────────────────────
  PAT_AG="P97-SWEEP-AG.*bucket=$HSLOT "
  PAT_LOST="P99-GUARD-LOST slot=$HSLOT "
  PAT_DONEB="P99-UBSWEEP-DONE slot=$HSLOT rc=-116"
  G0=$(cnt "$HOLDER" "$PAT_AG"); L0=$(cnt "$HOLDER" "$PAT_LOST")
  DB0=$(cnt "$HOLDER" "$PAT_DONEB")
  DOK0=$(cnt "$HOLDER" "P99-UBSWEEP-DONE slot=$HSLOT rc=0")
  snap_counts guard "$PAT_GUARD"
  snap_counts done "$PAT_DONE"
  say "booting $NB into the STALL window (stall=${STALL_MS}ms)"
  boot_rejoin "$NB" || fail "$NB failed to boot+mount during stall"
  RESTORE=()
  SL=$(cnt "$HOLDER" "P99-UBSWEEP-STALL slot=$HSLOT ")
  [ "${SL:-0}" -gt 0 ] || fail "holder never logged P99-UBSWEEP-STALL (knob ineffective?)"
  TK=""; TW2=0
  while [ $TW2 -lt 200 ]; do
    R=$(scan_new guard "$PAT_GUARD" | grep -v "^$HOLDER|" | head -1)
    if [ -z "$R" ]; then
      NG=$(cnt "$NB" "$PAT_GUARD")
      if [ "${NG:-0}" -gt 0 ]; then
        R="$NB|$($SSH "$NB" "dmesg | grep '$PAT_GUARD' | tail -1" 2>/dev/null | tr -d '\r')"
      fi
    fi
    if [ -n "$R" ]; then TK="$R"; break; fi
    DOK1=$(cnt "$HOLDER" "P99-UBSWEEP-DONE slot=$HSLOT rc=0")
    if [ "${DOK1:-0}" -gt "${DOK0:-0}" ]; then
      echo "RESULT: RETRY | case=guard_race_stale_resume | holder resumed rc=0 before any peer probed the frozen guard (timing missed)"
      exit 2
    fi
    sleep 10; TW2=$((TW2+10))
  done
  [ -n "$TK" ] || fail "no peer reclaimed the frozen guard on slot $HSLOT within 200s"
  H2="${TK%%|*}"
  say "takeover by $H2 during stall: '${TK#*|}'"
  # resumed holder must observe the loss and abort without a single sweep
  TW3=0; L1="$L0"
  while [ $TW3 -lt 300 ]; do
    L1=$(cnt "$HOLDER" "$PAT_LOST")
    [ "${L1:-0}" -gt "${L0:-0}" ] && break
    sleep 15; TW3=$((TW3+15))
  done
  [ "${L1:-0}" -gt "${L0:-0}" ] || fail "resumed holder never logged P99-GUARD-LOST"
  DB1=$(cnt "$HOLDER" "$PAT_DONEB")
  G1=$(cnt "$HOLDER" "$PAT_AG")
  [ "${DB1:-0}" -gt "${DB0:-0}" ] || fail "resumed holder did not abort with rc=-116 (DONE-b $DB0->$DB1)"
  [ "${G1:-0}" = "${G0:-0}" ] || fail "STALE HOLDER SWEPT AFTER TAKEOVER (P97-SWEEP-AG $G0->$G1) — fencing broken"
  say "stale holder fenced: GUARD-LOST, rc=-116, sweeps $G0->$G1 (unchanged)"
  # the takeover's own sweep must complete rc=0
  BD2=$(cat "$T/cnt.done.$H2" 2>/dev/null || echo 0)
  [ "$H2" = "$NB" ] && BD2=0
  TW4a=0; ND2="$BD2"
  while [ $TW4a -lt 120 ]; do
    ND2=$(cnt "$H2" "$PAT_DONE")
    [ "${ND2:-0}" -gt "${BD2:-0}" ] && break
    sleep 10; TW4a=$((TW4a+10))
  done
  [ "${ND2:-0}" -gt "${BD2:-0}" ] || fail "takeover node $H2 never finished its sweep"
  DONE=$($SSH "$H2" "dmesg | grep '$PAT_DONE' | tail -1" 2>/dev/null | tr -d '\r')
  RC=$(sed -n 's/.*rc=\(-\?[0-9]*\).*/\1/p' <<<"$DONE")
  say "takeover sweep done: '$DONE'"
  [ "$RC" = "0" ] || fail "takeover sweep rc=$RC — '$DONE'"
else
  # ── abandoned arm: kill the holder mid-hold; a peer must take over ──────
  snap_counts guard "$PAT_GUARD"
  snap_counts done "$PAT_DONE"
  say "destroying guard holder $HOLDER mid-hold"
  $VIRSH destroy "$HOLDER" >/dev/null 2>&1
  RESTORE=("$NB" "$HOLDER")
  SURV2=(); for n in "${SURV[@]}"; do [ "$n" != "$HOLDER" ] && SURV2+=("$n"); done
  SURV=("${SURV2[@]}")
  # a peer must reclaim the corpse guard (change-detection) and finish
  TW2=0; TK=""
  while [ $TW2 -lt 330 ]; do
    R=$(scan_new guard "$PAT_GUARD" | head -1)
    if [ -n "$R" ]; then TK="$R"; break; fi
    sleep 15; TW2=$((TW2+15))
  done
  [ -n "$TK" ] || fail "no peer took over the abandoned guard on slot $HSLOT within 330s"
  H2="${TK%%|*}"
  say "takeover by $H2 after ${TW2}s: '${TK#*|}'"
  BD2=$(cat "$T/cnt.done.$H2" 2>/dev/null || echo 0)
  TW3=0; ND2="$BD2"
  while [ $TW3 -lt 120 ]; do
    ND2=$(cnt "$H2" "$PAT_DONE")
    [ "${ND2:-0}" -gt "${BD2:-0}" ] && break
    sleep 10; TW3=$((TW3+10))
  done
  [ "${ND2:-0}" -gt "${BD2:-0}" ] || fail "takeover node $H2 never finished UBSWEEP on slot $HSLOT"
  DONE=$($SSH "$H2" "dmesg | grep '$PAT_DONE' | tail -1" 2>/dev/null | tr -d '\r')
  RC=$(sed -n 's/.*rc=\(-\?[0-9]*\).*/\1/p' <<<"$DONE")
  say "takeover sweep done: '$DONE'"
  [ "$RC" = "0" ] || fail "takeover sweep rc=$RC — '$DONE'"
fi

# ── converge: release the fd, zombie must reap ────────────────────────────
say "releasing fd on $FDH; waiting for reap of ino=$INO"
$SSH "$FDH" "pkill -f $RUNID" >/dev/null 2>&1
set_knob 0
CONV=0; TW4=0
while [ $TW4 -lt 90 ]; do
  C1=$($SSH "$FDH" "dmesg | grep -cE '$PAT_REAP'" 2>/dev/null | tr -d ' \r\n')
  CONV=$(( ${C1:-0} - ${C0:-0} ))
  [ "$CONV" -gt 0 ] && break
  sleep 10; TW4=$((TW4+10))
done

cleanup
case "$ARM" in
  joiner)
    echo "RESULT: PASS | case=guard_race_joiner | holder=$HOLDER slot=$HSLOT joiner=$NB new_slot=$NEWSLOT races=$RACES sweep_rc=0 reap_evidence=$CONV ino=$INO" ;;
  stale_resume)
    echo "RESULT: PASS | case=guard_race_stale_resume | holder=$HOLDER slot=$HSLOT takeover=$H2 holder_fenced=1 holder_sweeps_after=0 takeover_rc=0 reap_evidence=$CONV ino=$INO" ;;
  *)
    echo "RESULT: PASS | case=guard_race_abandoned | holder=$HOLDER slot=$HSLOT takeover=$H2 takeover_after=${TW2}s sweep_rc=0 reap_evidence=$CONV ino=$INO" ;;
esac
exit 0
