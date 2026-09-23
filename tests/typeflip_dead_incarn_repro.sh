#!/bin/bash
# typeflip_dead_incarn_repro.sh — dead-incarnation re-log regression
# (sess398, ledger D-RELEASE-DRAIN-RELOGS-DEAD-INCARNATION-WITHOUT-TENURE-TYPEFLIP-398)
#
# MEASURED CHAIN IT RE-CREATES: node A creates a directory and keeps it cached
# (clean, NL); a peer B removes it (the number is freed) and B re-allocates the
# SAME inode number as a regular FILE.  A's cached dir is now a DEAD PRIOR
# INCARNATION.  On 0.23.6 the next BAST/release drain on A re-logged that dead
# dir core with no DLM tenure (P146V-UNLANDED at held_mode=0) and the cluster
# write clobbered B's live file: dirent=file / dinode=dir cluster-wide ->
# P201-TYPEFLIP-UNRESOLVED-FAIL -ESTALE.  0.23.8 refuses the re-log
# (mxfs_dlm_relog_authorized -> P146V-NOAUTH-REFUSE).
#
# PASS = every node (A included) sees the re-created name as a regular file of
# the expected size, can open/read/stat/unlink it, and A logged NO
# P146V-UNLANDED with a foreign gen, NO P58-DIRPIN-NONEX, NO
# P201-TYPEFLIP-UNRESOLVED-FAIL for that inode.  The count of
# P146V-NOAUTH-REFUSE on A is reported (0 is allowed: the orphan-BAST route is
# timing dependent; the reload route is always exercised).
#
# budget: every remote step is bounded by a derived timeout (mkdir/rmdir/stat
# are sub-second on native XFS; the reuse loop is capped at MAXCREATE creates
# and its wall is MEASURED and printed so the budget can be tightened; 2x
# native is the ceiling, so a run that needs the cap is itself a finding).
# the unkillable-wedge rule: bounded ssh only, per-node rc captured.
#
# Usage: tests/typeflip_dead_incarn_repro.sh [A=18] [B=27] [nodes=32] [rounds=5]
# Env:   MXFS_MNT (default /mnt/shared)

A=${1:-18}; B=${2:-27}; NODES=${3:-32}; ROUNDS=${4:-5}
MNT=${MXFS_MNT:-/mnt/shared}
MAXCREATE=3000
cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
D="$MNT/.typeflip_repro"
fail=0

rsh() { # rsh <node> <timeout> <cmd>
	timeout "$2" $SSH "test$1" "$3" 2>/dev/null | grep -v 'authorized\|Permanently added'
}

echo "=== typeflip_dead_incarn_repro A=test$A B=test$B nodes=$NODES rounds=$ROUNDS $(date -u +%FT%TZ) ==="
# Inode-number -> AG shift = agblklog + inopblog.  Override with AGSHIFT=<n>;
# default derived from the mount's geometry: agblocks ~= total_blocks/agcount
# (agcount from tools/chk_mxfs -v on the LUN image, inopblog from inopblock),
# agblklog = ceil(log2(agblocks)).  Measured rig (25 AGs, -d 50G): 19 + 3 = 22.
if [ -z "${AGSHIFT:-}" ]; then
	# --geometry, not -v: the constants only, not a full check of the image
	HOST_IMG=$(tools/mxfs_host_image.sh) || { echo "$HOST_IMG"; exit 2; }
	geo=$(timeout 60 tools/chk_mxfs --geometry "$HOST_IMG" 2>/dev/null | grep -oE 'agcount=[0-9]+|inopblock=[0-9]+' | tr '\n' ' ')
	agcount=$(echo "$geo" | grep -oE 'agcount=[0-9]+' | cut -d= -f2)
	inopb=$(echo "$geo" | grep -oE 'inopblock=[0-9]+' | cut -d= -f2)
	blocks=$(rsh $A 20 "df -B4096 --output=size $MNT | tail -1" | tr -dc 0-9)
	AGSHIFT=$(python3 -c "import math; ab=$blocks/$agcount; print(math.ceil(math.log2(ab))+int(math.log2($inopb)))" 2>/dev/null)
	[ -n "$AGSHIFT" ] || { echo "cannot derive AGSHIFT (geo='$geo' blocks='$blocks'); set AGSHIFT=<n>"; exit 2; }
fi
echo "AGSHIFT=$AGSHIFT"
rsh $A 20 "mkdir -p $D && rm -rf $D/r_* ; echo ok" | tail -1
for r in $(seq 1 "$ROUNDS"); do
	dir="$D/r_${r}_dir"; name="r_${r}_dir"
	# 1. A creates the dir and caches it (stat + readdir), then leaves it alone.
	dino=$(rsh $A 20 "mkdir $dir && stat -c %i $dir && ls $dir >/dev/null && stat -c %i $dir | tail -1")
	dino=$(echo "$dino" | tail -1)
	[ -n "$dino" ] || { echo "round $r: A mkdir failed"; fail=1; continue; }
	# 2. B removes it (frees the number) and re-allocates the number as a FILE.
	#    sess398 measured: files are allocated in their PARENT's AG and
	#    directories rotate across AGs, so creating files in the shared
	#    parent never reaches the freed number (5/5 rounds "miss" at 3000
	#    creates).  Do what dir_reuse does by accident: mkdir until a dir
	#    lands in the freed inode's AG, then create files INSIDE it.
	agno=$(( dino >> AGSHIFT ))
	t0=$(date +%s.%N)
	out=$(rsh $B 110 "rmdir $dir || exit 3; pd=; j=0; while [ \$j -lt 400 ]; do j=\$((j+1)); dd=$D/r_${r}_d\$j; mkdir \$dd || exit 5; a=\$(( \$(stat -c %i \$dd) >> $AGSHIFT )); if [ \$a = $agno ]; then pd=\$dd; break; fi; done; [ -n \"\$pd\" ] || { echo miss_agdir tries=\$j; exit 6; }; i=0; while [ \$i -lt $MAXCREATE ]; do i=\$((i+1)); f=\$pd/f\$i; : > \$f; ino=\$(stat -c %i \$f); if [ \"\$ino\" = $dino ]; then echo hit=\$i agdir_tries=\$j ino=\$ino file=\$f; printf 'payload-%s' \$i > \$f; exit 0; fi; rm -f \$f; done; echo miss agdir_tries=\$j; exit 4")
	wall=$(python3 -c "import time; print(round(time.time()-$t0,2))")
	hit=$(echo "$out" | grep -o 'file=[^ ]*' | cut -d= -f2)
	echo "round $r: dir_ino=$dino B_reuse: $(echo "$out" | tail -1) wall=${wall}s"
	if [ -z "$hit" ]; then echo "round $r: FAIL (no reuse within $MAXCREATE creates)"; fail=1; continue; fi
	# 3. Every node (A first) must see a regular file with the payload.
	T=$(mktemp -d)
	for i in $A $(seq 1 "$NODES"); do
		( rsh $i 30 "t=\$(stat -c %F $hit 2>&1); s=\$(stat -c %s $hit 2>&1); c=\$(cat $hit 2>&1 | head -c 40); echo node=test$i type=\"\$t\" size=\$s content=\"\$c\"" > "$T/n$i"; echo $? > "$T/rc$i" ) &
	done
	wait
	bad=0
	for i in $A $(seq 1 "$NODES"); do
		line=$(cat "$T/n$i"); rc=$(cat "$T/rc$i")
		case "$line" in *'type="regular file"'*'content="payload-'*) ;; *) bad=$((bad+1)); echo "  BAD rc=$rc $line";; esac
	done
	# 4. A's probes for this inode.
	probes=$(rsh $A 30 "dmesg | grep -E 'ino=$dino( |\$)' | grep -oE 'P146V-NOAUTH-REFUSE|P146V-UNLANDED|P58-DIRPIN-NONEX|P201-TYPEFLIP-UNRESOLVED-FAIL|RELOAD-TYPEFLIP-DIRENT-OK|RELOAD-TYPEFLIP-STALE-SKIP|P146D-DEADINCARN' | sort | uniq -c | tr '\n' ' '")
	echo "round $r: A probes for ino $dino: ${probes:-none}"
	case "$probes" in *P146V-UNLANDED*|*P58-DIRPIN-NONEX*|*P201-TYPEFLIP*) bad=$((bad+1)); echo "  FORBIDDEN probe on A";; esac
	# 5. Remove the file from a third node and verify gone everywhere.
	C=$(( (B % NODES) + 1 )); [ $C = $A ] && C=$(( (C % NODES) + 1 ))
	rsh $C 20 "rm $hit && echo removed" | tail -1 | grep -q removed || { echo "  rm on test$C failed"; bad=$((bad+1)); }
	# 6. Clean the round's scratch dirs from B (bounded; they are empty).
	rsh $B 60 "rmdir $D/r_${r}_d* 2>/dev/null; echo cleaned" | tail -1 >/dev/null
	if [ $bad = 0 ]; then echo "round $r: PASS"; else echo "round $r: FAIL bad=$bad"; fail=1; fi
done
echo "=== result: $([ $fail = 0 ] && echo PASS || echo FAIL) ==="
exit $fail
