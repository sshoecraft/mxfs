#!/bin/bash
# After the victim (pve9-4, 192.168.120.212) is back: poll both nested-pair-B hosts
# every 5 s, for at most BUDGET seconds, until both have /mnt/shared mounted and
# DRBD Connected Primary/Primary UpToDate.  Logs one line per poll to EVDIR/remount.log.
# Usage: wedged_umount_reboot_remount.sh EVDIR SCR T0EPOCH BUDGET
# Exit 0 when both are mounted and UpToDate, 2 when BUDGET is spent.
set -u
EV=${1:?evidence dir}
SCR=${2:?scratch dir}
T0=${3:?T0 epoch}
BUDGET=${4:?budget seconds}
SSH=/home/steve/src/mxfs/tools/mxfs_sshpass.sh
BANNER='Warning:|Unauthorized|disconnect immediately|^If you'
CMD='grep " cs:" /proc/drbd; grep -c " /mnt/shared mxfs " /proc/mounts; systemctl is-active mxfs-drbd@mxfs'

probe() { timeout 10 "$SSH" "$1" "$CMD" > "$2.raw" 2>&1; echo $? > "$2.rc"; }
flat() { grep -avE "$BANNER" "$1.raw" | tr -s ' ' | tr '\n' '|'; }

start=$(date +%s.%N)
while :; do
  now=$(date +%s.%N)
  rel=$(awk -v a=$now -v b=$start 'BEGIN{printf "%d", a-b}')
  sinceT0=$(awk -v a=$now -v b=$T0 'BEGIN{printf "%d", a-b}')
  if [ $rel -gt $BUDGET ]; then echo "REMOUNT_BUDGET_EXHAUSTED rel=${rel}s sinceT0=${sinceT0}s" | tee -a $EV/remount.log; exit 2; fi
  probe 192.168.120.211 $SCR/r3 &
  probe 192.168.120.212 $SCR/r4 &
  wait
  a=$(flat $SCR/r3)
  b=$(flat $SCR/r4)
  echo "$(date -u +%FT%T.%NZ) rel=${rel}s sinceT0=${sinceT0}s pve9-3[rc=$(cat $SCR/r3.rc)]=$a pve9-4[rc=$(cat $SCR/r4.rc)]=$b" | tee -a $EV/remount.log
  ok=1
  for h in r3 r4; do
    f=$(flat $SCR/$h)
    case $f in
      *"cs:Connected ro:Primary/Primary ds:UpToDate/UpToDate"*"|1|"*) ;;
      *) ok=0 ;;
    esac
  done
  if [ $ok -eq 1 ]; then echo "REMOUNTED rel=${rel}s sinceT0=${sinceT0}s" | tee -a $EV/remount.log; exit 0; fi
  sleep 5
done
