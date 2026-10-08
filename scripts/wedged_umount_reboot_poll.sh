#!/bin/bash
# Drives the wedged-umount reboot reproduction on nested pair B:
#   pve9-3 192.168.120.211 (survivor), pve9-4 192.168.120.212 (victim).
# Two modes, so the mutating step and the observation are separate calls:
#   trigger EVDIR SCR        arm dbg_teardown_lease_hold_ms on the victim, record T0,
#                            request the reboot
#   poll EVDIR SCR NPOLLS    run up to NPOLLS polls on a fixed 15 s grid from T0;
#                            exits 0 on a NEW victim boot_id, 2 when the 1500 s
#                            budget is spent, 3 when NPOLLS ran with neither
# Touches no other host.  Screenshots of the victim go to SCR (ppm) and EVDIR (png).
set -u
mode=${1:?mode}
EV=${2:?evidence dir}
SCR=${3:?scratch dir}
SSH=/home/steve/src/mxfs/tools/mxfs_sshpass.sh
VIC=192.168.120.212
SUR=192.168.120.211
BANNER='Warning:|Unauthorized|disconnect immediately|^If you'
STATE=$SCR/state
MAXS=1500
INTERVAL=15
UUID='^[0-9a-f-]{36}$'

probe() { timeout "$1" "$SSH" "$2" "$3" > "$4.raw" 2>&1; echo $? > "$4.rc"; }
clean() { grep -avE "$BANNER" "$1.raw"; }

trigger() {
  probe 20 $VIC 'cat /proc/sys/kernel/random/boot_id' $SCR/pre
  old=$(clean $SCR/pre | grep -aE "$UUID" | tail -1)
  probe 20 $VIC 'echo 1500000 > /sys/module/mxfs/parameters/dbg_teardown_lease_hold_ms; cat /sys/module/mxfs/parameters/dbg_teardown_lease_hold_ms' $SCR/arm
  echo "arm rc=$(cat $SCR/arm.rc) readback: $(clean $SCR/arm | tr '\n' ' ')"
  T0=$(date +%s.%N)
  probe 20 $VIC 'systemd-run --no-block systemctl reboot' $SCR/reb
  echo "T0=$T0 T0utc=$(date -u -d @${T0%.*} +%Y-%m-%dT%H:%M:%SZ) old_boot=$old"
  echo "reboot-request rc=$(cat $SCR/reb.rc) out: $(clean $SCR/reb | tr '\n' ' ')"
  printf 'T0=%s\nOLD=%s\nK=0\nUC=0\nSS=0\n' "$T0" "$old" > $STATE
}

poll() {
  . $STATE
  n=0
  while [ $n -lt "$1" ]; do
    target=$(awk -v t=$T0 -v k=$K -v i=$INTERVAL 'BEGIN{printf "%.3f", t+k*i}')
    now=$(date +%s.%N)
    gap=$(awk -v a=$target -v b=$now 'BEGIN{d=a-b; if(d<0)d=0; printf "%.3f", d}')
    sleep $gap
    el=$(awk -v a=$(date +%s.%N) -v b=$T0 'BEGIN{printf "%d", a-b}')
    if [ $el -gt $MAXS ]; then echo "BUDGET_EXHAUSTED el=$el" | tee -a $EV/poll.log; exit 2; fi
    probe 10 $VIC 'cat /proc/sys/kernel/random/boot_id' $SCR/p4 &
    probe 10 $SUR 'grep " cs:" /proc/drbd; grep -c " /mnt/shared mxfs " /proc/mounts' $SCR/p3 &
    timeout 2 ping -c1 -W1 $VIC > /dev/null 2>&1
    prc=$?
    wait
    bid=$(clean $SCR/p4 | grep -aE "$UUID" | tail -1)
    p3=$(clean $SCR/p3 | tr -s ' ' | tr '\n' '|')
    if [ -z "$bid" ]; then
      bs="UNREACH(sshrc=$(cat $SCR/p4.rc))"
    else
      bs=$bid
    fi
    printf '%5ds k=%d p4boot=%s ping=%s p3=[%s] p3rc=%s\n' "$el" "$K" "$bs" "$prc" "$p3" "$(cat $SCR/p3.rc)" | tee -a $EV/poll.log
    if [ -z "$bid" ]; then
      UC=$((UC+1))
      if [ $((K % 4)) -eq 0 ] && [ $SS -lt 30 ]; then
        f=$SCR/shot-$(printf %05d $el).ppm
        timeout 20 virsh -c qemu:///system screenshot pve9-4 $f > $SCR/shot.out 2>&1
        echo "  screenshot rc=$? $(tr '\n' ' ' < $SCR/shot.out)" | tee -a $EV/poll.log
        SS=$((SS+1))
        cp $f $EV/shot-$(printf %05d $el).png 2>&1 | tee -a $EV/poll.log
      fi
    fi
    K=$((K+1))
    n=$((n+1))
    printf 'T0=%s\nOLD=%s\nK=%d\nUC=%d\nSS=%d\n' "$T0" "$OLD" "$K" "$UC" "$SS" > $STATE
    if [ -n "$bid" ] && [ "$bid" != "$OLD" ]; then
      echo "NEWBOOT el=$el id=$bid" | tee -a $EV/poll.log
      exit 0
    fi
  done
  exit 3
}

case $mode in
  trigger) trigger ;;
  poll) poll "${4:?npolls}" ;;
  *) echo "bad mode"; exit 64 ;;
esac
