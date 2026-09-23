#!/bin/bash
# sess494: THE SURVIVOR SCAN'S TERMINAL-GUARD CLASSIFICATION, ARM BY ARM, AT A
# TOTAL OUTAGE (D-BOOTSTRAP-REFUSES-TOTAL-OUTAGE-WITH-QUARANTINED-GUARD-VICTIM-NOIDENT-0493).
#
# The fleet is fully UNMOUNTED (the state the leg Z harness leaves behind), so
# the only occupied heartbeat record is the one this harness forges into an
# unused slot with tools/recov_forge (plus any REAL terminal guard the leg left
# behind — s494f ran beside the leg's slot-0 verdict, so every arm saw two
# guards and two masks; the expectations below hold either way).  One node
# then mounts; what its survivor scan does with the forged record is the
# measurement.  Expected, on 0.70.12:
#
#   term-valid       QUARANTINED + canonical AG-mask verdict: NOT a victim —
#                    P-BOOT-SCAN-TERMINAL-ONLY, ordinary path, the admission
#                    barrier imports the mask BEFORE 'mount ADMITTED with AG
#                    mask' (journal order), the mount claims a slot other than
#                    the guard's, MOUNT_OK, nothing fenced or replayed.
#   term-fswide      the same with an FSWIDE verdict: skipped by the scan, then
#                    admission refuses the mount (P240-QUAR-ADMIT-DENY) — the
#                    right refusal, not P-BOOT-KEY-UNCLASSIFIED.
#   legacy           QUARANTINED with the all-zero outcome region: terminal
#                    (legacy-quarantine), skipped; admission backfills FSWIDE
#                    and refuses (ADMIT-DENY).  The sector CHANGES (backfill).
#   term-badcrc      QUARANTINED, outcome crc broken: TORN — P-BOOT-SCAN-GUARD-
#                    TORN, P-BOOT-SCAN-UNREAD, mount refused, sector untouched.
#   term-slotmismatch outcome names another slot: TORN, as above.
#   live-noident     a sub-terminal descriptor (QUARANTINED clear) with no
#                    identity: a victim as before — P-BOOT-KEY-UNCLASSIFIED,
#                    refused (unchanged behaviour, fail closed).
#   desc-crc         descriptor crc broken: unparseable, a victim as before —
#                    refused P-BOOT-KEY-UNCLASSIFIED, sector untouched.
#   mixed            term-valid guard AND one dead ACTIVE record (X mounts, is
#                    virsh-destroyed): the bootstrap runs for X's slot only
#                    (P-BOOT-SCAN-FROZEN terminal_guards=1, P-BOOT-SEALED, X's
#                    slice replayed), the guard is neither fenced nor replayed
#                    nor zeroed, the mask is imported before admission, MOUNT_OK.
#
# derived time budgets, derived: the survivor scan waits one dead window (~62 s)
# when the table is frozen; a clean mount is ~8-15 s; fence + replay of one
# slice ~60-90 s (mixed).  Mount budget 150 s inner / 200 s outer; umount 60 s;
# X's restart ~40-60 s to ssh (150 s).  ~2 min per arm, ~5 min for mixed.
#
# Usage: GATE=<log> setsid nohup bash tests/sess494_d0493_forged_guard_arms.sh s494f &
set -u
cd /src/mxfs || exit 1
LABEL=${1:-s494f}
GATE=${GATE:-tests/evidence/sess488_ailpin_fleet_umount_s494z.log}
ARMS=${ARMS:-term-valid term-fswide legacy term-badcrc term-slotmismatch live-noident desc-crc mixed}
SLOT=${SLOT:-40}                 # unused on a 32-node rig
M=${M:-test2}                    # the mounting node
P=${P:-test3}                    # runs recov_forge against the LUN
X=${X:-test5}                    # the dead ACTIVE record of the mixed arm
EXPECT_SV=${EXPECT_SV:-B58E6B1C1DB941A1B3E59EE}   # 0.70.12
LOG=tests/evidence/sess494_d0493_forged_guard_arms_$LABEL.log
O=tests/evidence/sess494_d0493_forged_guard_arms_$LABEL
SSH=tools/mxfs_sshpass.sh
FORGE=/src/mxfs/tools/recov_forge
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "$M"; DEV=$MXFS_DEV_RESOLVED
MNT=/mnt/shared
SAVE=/tmp/d0493_forge_slot$SLOT.bin
mkdir -p "$O"
nodes() { seq 1 32 | sed 's/^/test/'; }
node() { timeout "$1" $SSH "$2" "$3" 2>/dev/null; }   # <timeout> <node> <cmd>
is_mounted() { node 30 "$1" "grep -qs ' $MNT mxfs ' /proc/mounts && echo YES || echo NO" | tail -1 | tr -d '[:space:]'; }
sector_crc() { node 30 "$P" "$FORGE $DEV dump $SLOT" | sed -n 's/.*sector_crc32c=\(0x[0-9a-f]*\).*/\1/p' | head -1; }

# mount M with a kmsg mark, capture the bootstrap/admission journal, umount.
# Sets: MOUNT (OK|RC=n), WALL, and the counters read by the arm verdicts.
mount_probe() { # <arm> <node>
    local arm=$1 n=$2 since t0 out il al
    since=$(date -u +'%Y-%m-%d %H:%M:%S'); t0=$(date +%s)
    out=$(node 200 "$n" "echo D0493-ARM-$arm-$LABEL > /dev/kmsg; timeout 150 mount -t mxfs $DEV $MNT && echo MOUNT_OK || echo MOUNT_RC=\$?" | grep -ao 'MOUNT_[A-Z_]*=*[0-9]*' | tail -1)
    WALL=$(( $(date +%s) - t0 )); MOUNT=${out:-MOUNT_?}
    node 60 "$n" "journalctl -k --no-pager --since '$since' 2>/dev/null | grep -aE 'P-BOOT-|P240-QUAR|ADMITTED with AG mask|claimed heartbeat slot|elected|replay of slot|P163-|FENCE|P238-|P-PR-DEPARTURE-UNHELD'" > "$O/journal_${arm}_$n.txt"
    J="$O/journal_${arm}_$n.txt"
    SCAN_TERM=$(grep -ac 'P-BOOT-SCAN-TERMINAL' "$J"); SCAN_FROZEN=$(grep -ac 'P-BOOT-SCAN-FROZEN' "$J")
    TORN=$(grep -ac 'P-BOOT-SCAN-GUARD-TORN' "$J"); UNREAD=$(grep -ac 'P-BOOT-SCAN-UNREAD' "$J")
    UNCLASS=$(grep -ac 'P-BOOT-KEY-UNCLASSIFIED' "$J"); SEALED=$(grep -ac 'P-BOOT-SEALED' "$J")
    IMPORT=$(grep -ac 'P240-QUAR-IMPORT' "$J"); ADMITTED=$(grep -ac 'ADMITTED with AG mask' "$J"); DENY=$(grep -ac 'P240-QUAR-ADMIT-DENY' "$J")
    il=$(grep -an 'P240-QUAR-IMPORT' "$J" | head -1 | cut -d: -f1); al=$(grep -an 'ADMITTED with AG mask' "$J" | head -1 | cut -d: -f1)
    ORDER=$( [ -n "$il" ] && [ -n "$al" ] && [ "$il" -lt "$al" ] && echo 1 || echo 0 )
    CLAIMED=$(grep -ao 'claimed heartbeat slot [0-9]*' "$J" | head -1 | grep -o '[0-9]*$'); CLAIMED=${CLAIMED:--}
    # an ACTUAL fence op, replay, adoption or zeroing naming the forged slot —
    # not the monitor's death-declaration lines (P163-FENCED-SEEN,
    # P-PRKEY-FENCE-REFUSED, P163-RECOVERY-PENDING), which fire for every
    # dead-looking record and refuse to act without a key (s494f: every arm
    # printed 1-3 of those and nothing else)
    GUARD_TOUCHED=$(grep -aE 'P236-FENCE-INTENT|P236-FENCE-CERTIFIED|P238-FENCE-DONE|P-BOOT-REG-FENCE|PREEMPT|elected \(slot|replay of slot [0-9]+ complete|P-BOOT-ADOPT|purged|zeroed' "$J" | grep -ac "slot[= ]$SLOT\b\|slot $SLOT \|victim_slot=$SLOT\b")
    ADOPTED=$(grep -ao 'P-BOOT-ADOPTED slot [0-9]*' "$J" | head -1 | grep -o '[0-9]*$'); [ "$CLAIMED" = - ] && [ -n "$ADOPTED" ] && CLAIMED=$ADOPTED
    MASKS=$(grep -ao 'ag_mask=0x[0-9a-f]*' "$J" | sort | uniq -c | tr -s ' ' | tr '\n' ';')
    [ "$(is_mounted "$n")" = YES ] && node 90 "$n" "timeout 60 umount $MNT; echo UMOUNT_RC=\$?" | tail -1 > "$O/umount_${arm}_$n.txt"
    echo "  PROBE $arm on $n: $MOUNT wall=${WALL}s budget=150s scan_terminal=$SCAN_TERM scan_frozen=$SCAN_FROZEN torn=$TORN unread=$UNREAD unclassified=$UNCLASS sealed=$SEALED quar_import=$IMPORT admitted_mask=$ADMITTED admit_deny=$DENY import_before_admit=$ORDER claimed_slot=$CLAIMED guard_slot_touched=$GUARD_TOUCHED masks=[$MASKS]"
    grep -a 'P-BOOT-SCAN\|P-BOOT-SEALED\|P-BOOT-KEY-UNCLASSIFIED\|P240-QUAR\|ADMITTED with AG mask' "$J" | cut -c1-230 | head -6 | sed 's/^/    J: /'
}

{
  echo "=== sess494 d0493_forged_guard_arms START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) ARMS='$ARMS' SLOT=$SLOT M=$M P=$P X=$X EXPECT_SV=$EXPECT_SV ==="
  gate_dl=$(( $(date +%s) + 21600 ))
  while ! grep -q "^DONE" "$GATE" 2>/dev/null; do
      [ "$(date +%s)" -ge "$gate_dl" ] && { echo "ABORT: gate $GATE never reached DONE within 6 h"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
      sleep 30
  done
  echo "STAGE gate cleared: $GATE"
  bash tests/rig_wait_free.sh 7200 || { echo "ABORT: rig not free"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }

  # preflight: the module under test on the mounting nodes, and a fully
  # unmounted fleet (a mounted node is a live member and no scan can be total)
  for n in $M $P $X; do
      sv=$(node 20 "$n" "cat /sys/module/mxfs/srcversion 2>/dev/null" | tr -d '[:space:]')
      echo "  PREFLIGHT $n srcversion=${sv:-none}"
      [ "$sv" = "$EXPECT_SV" ] || { echo "ABORT: $n runs '${sv:-none}', expected $EXPECT_SV"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  done
  for n in $(nodes); do
      ( m=$(is_mounted "$n"); [ "$m" = YES ] && node 90 "$n" "timeout 60 umount $MNT; echo UMOUNT_RC=\$?" | tail -1; echo "mounted_before=$m" ) > "$O/preflight_$n.txt" 2>&1 &
  done
  wait
  echo "STAGE preflight mounted_before=$(grep -l 'mounted_before=YES' "$O"/preflight_test*.txt | wc -l)/32 now_mounted=$(for n in $(nodes); do is_mounted "$n"; done | grep -c YES)/32"
  pre=$(node 30 "$P" "$FORGE $DEV dump $SLOT"); echo "$pre" | head -2 | sed 's/^/  PRE: /'
  echo "$pre" | grep -q 'flags=ACTIVE' && { echo "ABORT: slot $SLOT is a live heartbeat"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  node 30 "$P" "$FORGE $DEV save $SLOT $SAVE" >/dev/null || { echo "ABORT: save"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  base=$(sector_crc); echo "STAGE saved slot $SLOT sector_crc32c=$base"
  KVER=$(sed -n 's/^#define MXFS_RECOV_DESC_VERSION[[:space:]]*\([0-9]*\).*/\1/p' dlm/disklock.h | head -1)

  npass=0; nrun=0
  for arm in $ARMS; do
      case "$arm" in
          term-valid)        FA="--oc valid --oc-agmask 0x2" ;;
          term-fswide)       FA="--oc fswide" ;;
          legacy)            FA="" ;;
          term-badcrc)       FA="--oc badcrc" ;;
          term-slotmismatch) FA="--oc slotmismatch" ;;
          live-noident)      FA="--live" ;;
          desc-crc)          FA="--break-desc-crc" ;;
          mixed)             FA="--oc valid --oc-agmask 0x2" ;;
          *) echo "  ARM $arm: unknown, skipped"; continue ;;
      esac
      nrun=$((nrun + 1))
      echo "--- arm=$arm forge='$FA' $(date -u +%FT%TZ) ---"
      forged=$(node 30 "$P" "$FORGE $DEV mkguard $SLOT $FA"); echo "$forged" | head -3 | sed 's/^/  FORGED: /'
      FVER=$(echo "$forged" | grep -ao 'desc: ver=[0-9]*' | head -1 | tr -dc '0-9')
      if [ -z "$KVER" ] || [ "$FVER" != "$KVER" ]; then
          echo "  ARM $arm ABORT: forge desc ver '${FVER:-?}' != kernel MXFS_RECOV_DESC_VERSION '${KVER:-?}'"; node 30 "$P" "$FORGE $DEV restore $SLOT $SAVE" >/dev/null; continue
      fi
      fcrc=$(sector_crc)
      if [ "$arm" = mixed ]; then
          # X joins through the terminal-only path, then dies with its ACTIVE record on the platter
          mount_probe "$arm-pre" "$X"; xm=$MOUNT
          if [ "$xm" != MOUNT_OK ]; then echo "  ARM $arm ABORT: $X did not mount ($xm)"; node 30 "$P" "$FORGE $DEV restore $SLOT $SAVE" >/dev/null; continue; fi
          node 200 "$X" "timeout 150 mount -t mxfs $DEV $MNT && echo REMOUNT_OK" | tail -1 | sed 's/^/  X: /'
          timeout 60 sudo virsh -c qemu:///system destroy "$X" > "$O/destroy_$X.txt" 2>&1; echo "  STAGE destroy $X rc=$? at $(date -u +%FT%T.%3NZ)"
          sleep 5
      fi
      mount_probe "$arm" "$M"
      post=$(sector_crc); preserved=$( [ "$post" = "$fcrc" ] && echo 1 || echo 0 )
      v=FAIL
      case "$arm" in
          term-valid)        [ "$MOUNT" = MOUNT_OK ] && [ "$SCAN_TERM" -ge 1 ] && [ "$UNCLASS" = 0 ] && [ "$TORN" = 0 ] && [ "$ORDER" = 1 ] && [ "$CLAIMED" != "$SLOT" ] && [ "$CLAIMED" != - ] && [ "$GUARD_TOUCHED" = 0 ] && [ "$preserved" = 1 ] && v=PASS ;;
          term-fswide)       [ "$MOUNT" != MOUNT_OK ] && [ "$SCAN_TERM" -ge 1 ] && [ "$UNCLASS" = 0 ] && [ "$TORN" = 0 ] && [ "$DENY" -ge 1 ] && [ "$GUARD_TOUCHED" = 0 ] && [ "$preserved" = 1 ] && v=PASS ;;
          legacy)            [ "$MOUNT" != MOUNT_OK ] && [ "$SCAN_TERM" -ge 1 ] && [ "$UNCLASS" = 0 ] && [ "$TORN" = 0 ] && [ "$DENY" -ge 1 ] && [ "$GUARD_TOUCHED" = 0 ] && v=PASS ;;
          term-badcrc|term-slotmismatch)
                             [ "$MOUNT" != MOUNT_OK ] && [ "$TORN" -ge 1 ] && [ "$UNREAD" -ge 1 ] && [ "$SCAN_TERM" = 0 ] && [ "$SEALED" = 0 ] && [ "$preserved" = 1 ] && v=PASS ;;
          live-noident|desc-crc)
                             [ "$MOUNT" != MOUNT_OK ] && [ "$UNCLASS" -ge 1 ] && [ "$SCAN_TERM" = 0 ] && [ "$SEALED" = 0 ] && [ "$preserved" = 1 ] && v=PASS ;;
          mixed)             [ "$MOUNT" = MOUNT_OK ] && [ "$SCAN_FROZEN" -ge 1 ] && grep -aqE 'terminal_guards=[1-9]' "$J" && [ "$SEALED" -ge 1 ] && [ "$UNCLASS" = 0 ] && [ "$ORDER" = 1 ] && [ "$CLAIMED" != "$SLOT" ] && [ "$GUARD_TOUCHED" = 0 ] && [ "$preserved" = 1 ] && v=PASS ;;
      esac
      [ "$v" = PASS ] && npass=$((npass + 1))
      echo "  ARM $arm $v sector_preserved=$preserved forged_crc=$fcrc post_crc=$post"
      node 30 "$P" "$FORGE $DEV restore $SLOT $SAVE" >/dev/null; echo "  restored slot $SLOT sector_crc32c=$(sector_crc) (baseline $base)"
      if [ "$arm" = mixed ]; then
          timeout 60 sudo virsh -c qemu:///system start "$X" >> "$O/destroy_$X.txt" 2>&1; echo "  STAGE restart $X rc=$?"
          t0=$(date +%s); up=0
          while [ $(( $(date +%s) - t0 )) -lt 150 ]; do node 10 "$X" "uptime" >/dev/null 2>&1 && { up=1; break; }; sleep 5; done
          echo "  STAGE $X back up=$up wall=$(( $(date +%s) - t0 ))s budget=150s"
      fi
  done
  echo "RESULT arms_pass=$npass/$nrun"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
