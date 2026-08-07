#!/bin/bash
# inflight_ab.sh — the D-PR-FENCE-PREEMPT-WITHOUT-ABORT step-4 A/B discriminator.
#
# Runs ONE arm: a victim write is held in the target's task set by dm-delay, the
# survivor issues PERSISTENT RESERVE OUT with the requested service action
# (0x04 PREEMPT or 0x05 PREEMPT AND ABORT), and every event is placed on ONE
# host monotonic timeline so the two properties can be scored separately:
#
#   (A) CANCELLATION  — the victim's bytes never become observable at all.
#   (B) LINEARIZATION — no victim modification becomes observable at or after
#                       the instant the PR command completed.
#   (C) CONTINUED EXCLUSION — a NEW victim write after the fence is rejected
#                       with RESERVATION CONFLICT and does not modify the store.
#
# Per the sess133 RULE-5 ruling the completion boundary is chosen PER ARM so
# each direction is conservative:
#   0x05 (safety arm)    boundary = ftrace entry of scst_cmd_done_pr_preempt,
#                        which is STRICTLY EARLIER than the wire GOOD, so
#                        "landed before boundary" is a STRICTER test than real.
#   0x04 (violation arm) boundary = userspace PROUT return, which is STRICTLY
#                        LATER than the wire GOOD, so "landed after boundary"
#                        is a STRICTER demonstration of the violation.
# ftrace runs with trace_clock=mono, so its timestamps ARE CLOCK_MONOTONIC and
# compare directly with the timestamps prprobe emits from clock_gettime().
#
# Usage:  inflight_ab.sh <0x04|0x05> [outdir]
# Env:    W_MS (dm-delay write delay, default 12000)

set -u

HERE=$(cd "$(dirname "$0")" && pwd)
P="$HERE/prprobe"
STACK="$HERE/stack.sh"
T=/sys/kernel/tracing

SA="${1:?usage: inflight_ab.sh <0x04|0x05> [outdir]}"
OUT="${2:-}"
[ -n "$OUT" ] || OUT=$(mktemp -d /var/tmp/fence_ab.XXXXXX)
mkdir -p "$OUT"

W_MS=${W_MS:-12000}
VK=0xfeed0001            # victim reservation key
SK=0xfeed0002            # survivor reservation key
TYPE=5                   # WE-RO — what MXFS's fence asks for
SGIO_TMO=120000          # SG_IO timeout, well clear of W (ruling: >= 60s)

# Fresh LBA + unique pattern per arm (ruling: no A/B state contamination).
# ARM_SEQ additionally shifts every offset by position in the run sequence, so a
# repeated service action (the ruled order is 0x04 -> 0x05 -> 0x04) still lands
# on blocks NO earlier arm has ever written.  The per-arm baseline write already
# resets the observation block, but a never-before-touched LBA removes the
# question entirely rather than answering it.
ARM_SEQ=${ARM_SEQ:-1}
case "$SA" in
  0x04) LBA=131072; LBA_C=133120; PAT=0xa4; PAT_C=0xc4; CLEAN=0x11 ;;
  0x05) LBA=135168; LBA_C=137216; PAT=0xa5; PAT_C=0xc5; CLEAN=0x22 ;;
  *) echo "service action must be 0x04 or 0x05" >&2; exit 2 ;;
esac
LBA=$((LBA + (ARM_SEQ - 1) * 16384))
LBA_C=$((LBA_C + (ARM_SEQ - 1) * 16384))
OFF=$((LBA * 512))
OFF_C=$((LBA_C * 512))

say() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$OUT/run.log"; }

eval "$(sudo bash "$STACK" devmap)"
[ -n "${LOOP:-}" ] && [ -n "${VICTIM:-}" ] && [ -n "${SURVIVOR:-}" ] \
  || { echo "stack not up — run: sudo bash $STACK up" >&2; exit 2; }

say "arm SA=$SA W_MS=$W_MS out=$OUT mode=$MODE gen=${GEN:-n/a}"
say "loop=$LOOP dm=$DM victim=$VICTIM($VICTIM_IQN) survivor=$SURVIVOR($SURVIVOR_IQN)"

# ---------------------------------------------- LUN offset -> below-delay offset
#
# The observation point is the device immediately BELOW dm-delay, and in fileio
# mode the LUN is a FILE on a filesystem that sits on that device: LUN byte X is
# NOT byte X of the loop device.  stack.sh fiemap resolves it programmatically
# (prprobe's FS_IOC_FIEMAP, which refuses anything that is not a single
# initialized, unshared, directly-mapped extent).  In blockio mode the same call
# reports the identity mapping, so this code path is uniform across both stages.
#
# dm-delay maps the loop device from sector 0 with no offset, so a physical byte
# offset on the dm device IS the same byte offset on the loop device.
lun2phys() {   # <lun byte offset> [len] -> physical byte offset below dm-delay
  local line
  line=$(sudo bash "$STACK" fiemap "$1" "${2:-4096}" 2>&1)
  case "$line" in
    fiemap\ *) ;;
    *) echo "FIEMAP REFUSED for LUN offset $1: $line" >&2; return 1 ;;
  esac
  echo "$line" | sed -n 's/.*[[:space:]]phys=\([0-9]*\).*/\1/p'
}

{ echo "### fiemap BEFORE (primary $OFF, property-C $OFF_C)"
  sudo bash "$STACK" fiemap "$OFF"   4096 2>&1
  sudo bash "$STACK" fiemap "$OFF_C" 4096 2>&1
} > "$OUT/fiemap_before.txt" 2>&1
PHYS=$(lun2phys "$OFF"   4096)  || { say "INVALID: cannot map primary LUN offset"; exit 3; }
PHYS_C=$(lun2phys "$OFF_C" 4096) || { say "INVALID: cannot map property-C LUN offset"; exit 3; }
[ -n "$PHYS" ] && [ -n "$PHYS_C" ] || { say "INVALID: empty physical offset"; exit 3; }
# Every layer must agree on 4 KiB alignment or the O_DIRECT observation is not
# reading the same bytes the target wrote.
if [ $((PHYS % 4096)) != 0 ] || [ $((PHYS_C % 4096)) != 0 ]; then
  say "INVALID: physical offset not 4 KiB aligned (phys=$PHYS phys_c=$PHYS_C)"; exit 3
fi
PHYS_LBA512=$((PHYS / 512))
PHYS_C_LBA512=$((PHYS_C / 512))

say "observation LUN offset=$OFF (lba $LBA) -> below-delay phys=$PHYS (sector $PHYS_LBA512) pattern=$PAT"
say "property-C  LUN offset=$OFF_C (lba $LBA_C) -> below-delay phys=$PHYS_C (sector $PHYS_C_LBA512) pattern=$PAT_C"

# ---------------------------------------------------------------- preconditions
{
  echo "### iscsiadm -m session -P 3"; sudo iscsiadm -m session -P 3 2>&1
  echo "### SCST sessions on the test target ($TARGET, mode=$MODE)"
  sudo ls "/sys/kernel/scst_tgt/targets/iscsi/$TARGET/sessions/" 2>&1
  echo "### dm table"; sudo dmsetup table "$(basename "$DM")" 2>&1
  echo "### loop"; losetup -l -O NAME,DIO,BACK-FILE 2>&1 | grep -E "NAME|$LOOP"
  echo "### multipath"; sudo multipath -ll 2>&1 | head -20
} > "$OUT/precond.txt" 2>&1

if [ "$VICTIM" = "$SURVIVOR" ]; then say "INVALID: victim and survivor are the same device"; exit 3; fi
if [ "$VICTIM_IQN" = "$SURVIVOR_IQN" ]; then say "INVALID: one initiator identity for both nexuses"; exit 3; fi

# Mark the kernel log with a SELF-IDENTIFYING token, not a line count.
#
# `dmesg | wc -l` + `tail -n +N` is UNSOUND: the printk ring buffer is bounded in
# BYTES, not lines, so a burst of long lines (SCST's PR tracing runs ~200 chars)
# evicts a GREATER NUMBER of shorter old lines than it adds.  The total line
# count then falls below the mark and `tail -n +N` yields NOTHING.  That is not
# hypothetical -- it produced a 0-line dmesg.txt for the sess135 arm-3 run while
# the conflict line it was supposed to contain was still sitting in the buffer.
#
# An empty capture is the worst possible failure here because it makes the
# "no EH / no reset / no timeout" validity item pass VACUOUSLY.  A token is exact,
# survives eviction accounting, needs no clock, and -- if the token itself has
# been evicted -- proves the evidence was LOST rather than absent.
DMESG_TOKEN="MXFS-FENCE-ARM-MARK-$$-$SA-$(date -u +%s%N)"
echo "$DMESG_TOKEN" | sudo tee /dev/kmsg >/dev/null
echo "$DMESG_TOKEN" > "$OUT/dmesg_token.txt"

# ------------------------------------------------------------- rebuild PR state
say "rebuilding PR state (CLEAR, then register victim+survivor, survivor reserves WE-RO)"
# A setup step that silently failed is how the first attempt produced an
# unregistered victim whose write was rejected before execution — exactly the
# wrong-answer risk the ruling told us to rule out.  So: drain the Unit
# Attention that CLEAR/PREEMPT posts to every other nexus, and ASSERT each step.
setup_step() {   # <dev> <sa> <rk> <sark> <what>
  local dev="$1" sa="$2" rk="$3" sark="$4" what="$5" line
  line=$(sudo "$P" prout "$dev" "$sa" "$rk" "$sark" $TYPE $SGIO_TMO | tee -a "$OUT/pr_setup.txt" | grep prout_done)
  case "$line" in
    *good=1*) return 0 ;;
    *) say "SETUP FAILED ($what on $dev): $line"; return 1 ;;
  esac
}
sudo "$P" clearua "$SURVIVOR" >> "$OUT/pr_setup.txt" 2>&1
sudo "$P" clearua "$VICTIM"   >> "$OUT/pr_setup.txt" 2>&1
setup_step "$SURVIVOR" 0x06 0x0  "$SK" "register survivor"  || exit 3
setup_step "$SURVIVOR" 0x03 "$SK" 0x0  "CLEAR"              || exit 3
# CLEAR posts REGISTRATIONS PREEMPTED to the other nexus; drain it before use.
sudo "$P" clearua "$VICTIM"   >> "$OUT/pr_setup.txt" 2>&1
sudo "$P" clearua "$SURVIVOR" >> "$OUT/pr_setup.txt" 2>&1
setup_step "$VICTIM"   0x06 0x0  "$VK" "register victim"    || exit 3
setup_step "$SURVIVOR" 0x06 0x0  "$SK" "register survivor"  || exit 3
setup_step "$SURVIVOR" 0x01 "$SK" 0x0  "RESERVE WE-RO"      || exit 3
# Both registrations MUST be present before the trial can mean anything.
sudo "$P" prin "$SURVIVOR" 0x00 > "$OUT/pr_keys_setup.txt" 2>&1
grep -q "feed0001" "$OUT/pr_keys_setup.txt" || { say "SETUP FAILED: victim key absent after setup"; exit 3; }
grep -q "feed0002" "$OUT/pr_keys_setup.txt" || { say "SETUP FAILED: survivor key absent after setup"; exit 3; }
sudo "$P" prin  "$SURVIVOR" 0x03 > "$OUT/pr_before.txt" 2>&1
sudo "$P" prin  "$SURVIVOR" 0x01 >> "$OUT/pr_before.txt" 2>&1
grep -E "prin_full |prin_rsv" "$OUT/pr_before.txt" | tee -a "$OUT/run.log"

# ------------------------------------------------------------------- baseline
say "baseline: writing CLEAN=$CLEAN below dm-delay at phys $PHYS and $PHYS_C"
sudo bash "$STACK" delay 0 >> "$OUT/run.log" 2>&1
sudo "$P" dwrite "$LOOP" "$PHYS"   4096 "$CLEAN" >> "$OUT/baseline.txt" 2>&1
sudo "$P" dwrite "$LOOP" "$PHYS_C" 4096 "$CLEAN" >> "$OUT/baseline.txt" 2>&1
sudo "$P" dread  "$LOOP" "$PHYS"   4096 | tee -a "$OUT/baseline.txt" | tee -a "$OUT/run.log"

# --------------------------------------------------------- delay-stack validation
# Ruling: validate the delay stack standalone first — one write, no P&A, nothing
# below before ~W and landing after ~W.
say "validating the delay stack standalone at W=${W_MS}ms"
sudo bash "$STACK" delay "$W_MS" >> "$OUT/run.log" 2>&1
VS=$( { sudo "$P" write "$VICTIM" "$LBA" 8 "$CLEAN" $SGIO_TMO; } 2>&1 | tee "$OUT/validate_write.txt" | grep write_done )
VDUR=$(echo "$VS" | sed -n 's/.*dur_ms=\([0-9.]*\).*/\1/p')
say "standalone delayed write dur_ms=$VDUR (expect >= ${W_MS})"
awk -v d="$VDUR" -v w="$W_MS" 'BEGIN{exit !(d+0 >= w*0.8)}' \
  || { say "INVALID: delay stack not delaying (dur_ms=$VDUR, W=$W_MS)"; sudo bash "$STACK" delay 0 >/dev/null; exit 3; }
sudo bash "$STACK" delay 0 >> "$OUT/run.log" 2>&1
sudo "$P" dwrite "$LOOP" "$PHYS" 4096 "$CLEAN" >> "$OUT/baseline.txt" 2>&1

# ------------------------------------------------------------------- ftrace up
say "arming ftrace (trace_clock=mono)"
sudo bash -c "
  echo 0 > $T/tracing_on
  echo nop > $T/current_tracer
  echo mono > $T/trace_clock
  echo > $T/trace
  echo 100000 > $T/buffer_size_kb
  echo 'scst_pr_do_preempt'        > $T/set_ftrace_filter
  echo 'scst_pr_abort_reg'        >> $T/set_ftrace_filter
  echo 'scst_pr_preempt_and_abort'>> $T/set_ftrace_filter
  echo 'scst_cmd_done_pr_preempt' >> $T/set_ftrace_filter
  echo function > $T/current_tracer
  for e in block_bio_queue block_rq_issue block_rq_complete; do
    echo 'dev==$LOOP_DEVNO || dev==$DM_DEVNO' > $T/events/block/\$e/filter
    echo 1 > $T/events/block/\$e/enable
  done
  echo 1 > $T/tracing_on
" 2>&1 | tee -a "$OUT/run.log"
# The whole timeline rests on ftrace timestamps BEING CLOCK_MONOTONIC.  Record
# the selected clock as evidence; verdict.py refuses to score without it.
sudo cat $T/trace_clock > "$OUT/trace_clock.txt" 2>&1
say "trace_clock: $(cat "$OUT/trace_clock.txt")"
grep -q '\[mono\]' "$OUT/trace_clock.txt" || {
  say "INVALID: trace_clock is not mono — ftrace and userspace stamps are not comparable"
  sudo bash -c "echo 0 > $T/tracing_on; echo nop > $T/current_tracer; echo > $T/set_ftrace_filter"
  exit 3
}

sudo bash "$STACK" delay "$W_MS" >> "$OUT/run.log" 2>&1

# ------------------------------------------------------------------ the trial
say "starting O_DIRECT poller on $LOOP (below dm-delay)"
sudo "$P" poll "$LOOP" "$PHYS" 4096 "$PAT" $((W_MS + 45000)) 50 > "$OUT/poll.txt" 2>&1 &
POLLPID=$!
sleep 0.3

say "victim issues held write: lba=$LBA pattern=$PAT"
sudo "$P" write "$VICTIM" "$LBA" 8 "$PAT" $SGIO_TMO > "$OUT/victim_write.txt" 2>&1 &
WPID=$!

# Gate on an OBSERVED in-flight state, never on a sleep (ruling blocker 4).
# The probe is SCST's OWN per-session active_commands — the victim's task-set
# size read from the target.  That is the exact property the ruling asks about
# ("is the command in the task set?"), not a device-layer proxy: dm-N/inflight
# does not account deferred bio-based dm IO and never rose here.
# $TARGET comes from `stack.sh devmap` and therefore names the target of the
# stack that is ACTUALLY UP.  It used to be the stage-(i) blockio IQN hardcoded
# here, which silently pointed at a nonexistent path in fileio mode: the read
# returned empty, ${WIN:-0} was 0 forever, and the arm would have aborted with
# "write never observed in flight" no matter how the handler behaved.
VSESS="/sys/kernel/scst_tgt/targets/iscsi/$TARGET/sessions/$VICTIM_IQN/active_commands"
say "waiting for the write to enter the victim's task set at $VSESS"
GATED=0
for i in $(seq 1 600); do
  WIN=$(sudo cat "$VSESS" 2>/dev/null)
  if [ "${WIN:-0}" -ge 1 ]; then GATED=1; break; fi
  sleep 0.02
done
T_GATE=$(awk 'BEGIN{ "date +%s.%N" | getline d; print d }' 2>/dev/null)
if [ "$GATED" != 1 ]; then
  say "INVALID: write never observed in flight on the dm device"
  sudo bash -c "echo 0 > $T/tracing_on"; wait $WPID 2>/dev/null; kill $POLLPID 2>/dev/null
  sudo bash "$STACK" delay 0 >/dev/null; exit 3
fi
say "in-flight observed (victim task set active_commands=$WIN, read at the target) — issuing PROUT $SA now"

sudo "$P" prout "$SURVIVOR" "$SA" "$SK" "$VK" $TYPE $SGIO_TMO > "$OUT/prout.txt" 2>&1
say "$(grep prout_done "$OUT/prout.txt")"

# NOTE — the held write is DELIBERATELY not reaped here.
#
# With TAS off, SAM REQUIRES an aborted command to be dropped "without delivery
# or notification", and SCST does exactly that: iscsi_xmit_response logs
# "aborted", req_cmnd_release_force frees the request, and NO PDU is sent.
# libiscsi's eh_cmd_timed_out then returns BLK_EH_RESET_TIMER for as long as the
# connection is healthy, so the initiator never times the command out -- measured
# sess134: still in D state in blk_execute_rq 261 s after a 120 s SG_IO timeout.
# Waiting for it here blocked the 0x05 arm forever.
#
# Nothing this arm concludes needs the held write to RETURN AT THE INITIATOR:
# t_land comes from ftrace on the lower device and the bytes come from an aligned
# O_DIRECT read below dm-delay.  So the whole measurement window runs first and
# the write is reaped afterwards (see "reap" below).

# ------------------------------------------------ property (C): continued exclusion
say "property (C): post-fence victim write at lba=$LBA_C pattern=$PAT_C"
sudo "$P" write "$VICTIM" "$LBA_C" 8 "$PAT_C" $SGIO_TMO > "$OUT/victim_write_post.txt" 2>&1
say "$(grep write_done "$OUT/victim_write_post.txt")"

# Let every delayed bio drain before we touch the table or read conclusions.
say "draining (W + margin) before teardown"
sleep $(awk -v w="$W_MS" 'BEGIN{printf "%.1f", w/1000.0 + 5}')
wait $POLLPID 2>/dev/null

sudo bash -c "echo 0 > $T/tracing_on"
sudo cat $T/trace > "$OUT/trace.txt" 2>&1
sudo bash -c "
  for e in block_bio_queue block_rq_issue block_rq_complete; do
    echo 0 > $T/events/block/\$e/enable; echo 0 > $T/events/block/\$e/filter
  done
  echo nop > $T/current_tracer
  echo > $T/set_ftrace_filter
" 2>&1 | tee -a "$OUT/run.log"

sudo bash "$STACK" delay 0 >> "$OUT/run.log" 2>&1

# ------------------------------------------------------------------ post-state
sudo "$P" prin "$SURVIVOR" 0x03 > "$OUT/pr_after.txt" 2>&1
sudo "$P" prin "$SURVIVOR" 0x01 >> "$OUT/pr_after.txt" 2>&1
sudo "$P" prin "$SURVIVOR" 0x00 >> "$OUT/pr_after.txt" 2>&1
grep -E "prin_full |prin_rsv|prin_keys" "$OUT/pr_after.txt" | tee -a "$OUT/run.log"

sudo "$P" dread "$LOOP" "$PHYS"   4096 > "$OUT/final_read.txt" 2>&1
sudo "$P" dread "$LOOP" "$PHYS_C" 4096 >> "$OUT/final_read.txt" 2>&1
cat "$OUT/final_read.txt" | tee -a "$OUT/run.log"

# Ruling: re-record the extent map AFTER every run.  If the map moved, the
# bytes just read are not necessarily the bytes the target wrote, and the arm
# must be INVALIDATED rather than reinterpreted.
{ echo "### fiemap AFTER (primary $OFF, property-C $OFF_C)"
  sudo bash "$STACK" fiemap "$OFF"   4096 2>&1
  sudo bash "$STACK" fiemap "$OFF_C" 4096 2>&1
} > "$OUT/fiemap_after.txt" 2>&1
PHYS_AFTER=$(lun2phys "$OFF" 4096 || true)
PHYS_C_AFTER=$(lun2phys "$OFF_C" 4096 || true)
EXTENT_STABLE=1
if [ "$PHYS_AFTER" != "$PHYS" ] || [ "$PHYS_C_AFTER" != "$PHYS_C" ]; then
  EXTENT_STABLE=0
  say "INVALID: the extent map MOVED during the run"
  say "  primary    $PHYS -> ${PHYS_AFTER:-<unmappable>}"
  say "  property-C $PHYS_C -> ${PHYS_C_AFTER:-<unmappable>}"
else
  say "extent map stable across the run (phys=$PHYS, phys_c=$PHYS_C)"
fi

sudo dmesg | sed -n "/$DMESG_TOKEN/,\$p" > "$OUT/dmesg.txt" 2>&1
if ! grep -q "$DMESG_TOKEN" "$OUT/dmesg.txt"; then
  say "WARNING: the arm-start kmsg token was evicted from the ring buffer —"
  say "the measurement window's kernel log is LOST, not empty; verdict.py will"
  say "score 4d_dmesg_window_captured VIOLATED rather than pass item 4 vacuously"
fi
say "dmesg window captured: $(wc -l < "$OUT/dmesg.txt") lines"
DMESG_TOKEN2="MXFS-FENCE-ARM-POST-$$-$SA-$(date -u +%s%N)"
echo "$DMESG_TOKEN2" | sudo tee /dev/kmsg >/dev/null
say "measurement window closed — all evidence captured"

# ----------------------------------------------------------------------- reap
# Only now do we care what happened to the held write at the initiator.  Give it
# a bounded grace period; if the target dropped it without a response (the 0x05
# case) nothing but session teardown will ever fail it.
HELD_ANSWERED=0
HELD_RELEASED_BY=none
for i in $(seq 1 20); do
  kill -0 "$WPID" 2>/dev/null || { HELD_ANSWERED=1; HELD_RELEASED_BY=target; break; }
  sleep 0.5
done
if [ "$HELD_ANSWERED" != 1 ]; then
  say "held write still outstanding 10 s after the window — the target dropped it"
  say "without a response (TAS off); releasing it with a victim session teardown"
  sudo bash "$STACK" relogin victim 2>&1 | tee -a "$OUT/run.log"
  for i in $(seq 1 60); do
    kill -0 "$WPID" 2>/dev/null || { HELD_RELEASED_BY=relogin; break; }
    sleep 0.5
  done
fi
# NOTE: the relogin can rename the victim's /dev/sdX.  arm.env deliberately keeps
# the device THIS arm measured; the next arm re-resolves it from stack.sh devmap.
wait $WPID 2>/dev/null
say "held write: answered_by=$HELD_RELEASED_BY $(grep write_done "$OUT/victim_write.txt" || echo '(no write_done — never returned)')"
# The teardown above is initiator error recovery BY CONSTRUCTION.  It happens
# strictly after the measurement window, and is recorded in its own file so it
# is visible rather than hidden -- dmesg.txt must stay EH-free on its own.
sudo dmesg | sed -n "/$DMESG_TOKEN2/,\$p" > "$OUT/dmesg_post.txt" 2>&1

cat > "$OUT/arm.env" <<EOF
HELD_WRITE_ANSWERED=$HELD_ANSWERED
HELD_WRITE_RELEASED_BY=$HELD_RELEASED_BY
SA=$SA
MODE=$MODE
GEN=${GEN:-}
W_MS=$W_MS
LBA=$LBA
OFF=$OFF
PAT=$PAT
LBA_C=$LBA_C
OFF_C=$OFF_C
PAT_C=$PAT_C
CLEAN=$CLEAN
PHYS=$PHYS
PHYS_C=$PHYS_C
PHYS_LBA512=$PHYS_LBA512
PHYS_C_LBA512=$PHYS_C_LBA512
EXTENT_STABLE=$EXTENT_STABLE
LOOP=$LOOP
LOOP_DEVNO=$LOOP_DEVNO
DM_DEVNO=$DM_DEVNO
VICTIM=$VICTIM
SURVIVOR=$SURVIVOR
VICTIM_IQN=$VICTIM_IQN
SURVIVOR_IQN=$SURVIVOR_IQN
OUT=$OUT
EOF

say "arm complete — artifacts in $OUT"
echo "$OUT"
