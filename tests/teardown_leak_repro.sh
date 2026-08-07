#!/bin/bash
# teardown_leak_repro.sh — deliberate reproducer for D-DWORK-TEARDOWN-LASTREF-LEAK.
#
# Chain to reproduce (captured live sess36, ino 31457413, build 0.11.308):
#   shutdown mid-activity -> unmount-era release fails (P9-ICD-FAIL rerr=-5)
#   -> stranded (-ESTALE) -> P6G-REL-STALE arms the bast dwork with an igrab
#   ref that becomes the inode's LAST ref -> eviction never runs -> 4ms timer
#   outlives xfs_free_perag -> P142-DWORK-STALE (pag=NULL) -> P142-DWORK-
#   LASTREF "ref intentionally leaked" -> P202-LEAKED-INODE at unload.
#
# The 0.11.310 fix gates the arm (P6G-REL-STALE-TEARDOWN, no igrab) when
# unmounting/shutdown/DLM-gone.  On a fixed build this script should show
# TEARDOWN lines and ZERO P142-DWORK-LASTREF / P202 leaks.
#
# USAGE: tests/teardown_leak_repro.sh [N] [cycles]     (cluster must be
# prepped at N first; each cycle leaves the cluster UNMOUNTED+rmmod'd and
# re-preps at the start of the next via run.sh prep_cluster.)
set -u
N="${1:-8}"; CYCLES="${2:-1}"
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd -- "$SCRIPT_DIR/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
MNT=/mnt/shared
cd "$REPO" || exit 2

leaks_total=0
for c in $(seq 1 "$CYCLES"); do
	echo "=========== teardown cycle $c/$CYCLES (N=$N) ==========="
	MXFS_FORCE_PREP=1 timeout 580 ./run.sh "$N" caw prep_cluster 2>&1 | tail -1
	# churn: cross-node create/rm in ONE shared dir (stranded releases need
	# cross-node grant-gen movement), 10s, backgrounded on every node
	for i in $(seq 1 "$N"); do
		( timeout 30 "$SSH" "test$i" "
			mkdir -p $MNT/tdlr 2>/dev/null
			end=\$((SECONDS+10))
			while [ \$SECONDS -lt \$end ]; do
				mkdir $MNT/tdlr/n${i}_\$RANDOM 2>/dev/null
				rm -rf \$(ls -d $MNT/tdlr/n${i}_* 2>/dev/null | head -2) 2>/dev/null
			done" >/dev/null 2>&1 ) &
	done
	sleep 6		# mid-churn...
	# ...force shutdown on HALF the nodes (odd ranks) while churn continues.
	# sess37: xfs_io -x shutdown is a SILENT NO-OP on mxfs (its FSGEOMETRY
	# probe gets ENOTTY and it exits before sending) — use the direct
	# XFS_IOC_GOINGDOWN helper instead.
	for i in $(seq 1 2 "$N"); do
		( timeout 15 "$SCRIPT_DIR/mxfs_shutdown.sh" "test$i" "$MNT" \
			>/dev/null 2>&1 ) &
	done
	wait
	# teardown: unmount + rmmod everywhere, then census the signature
	for i in $(seq 1 "$N"); do
		( timeout 60 "$SSH" "test$i" "
			umount -f $MNT 2>/dev/null; umount -l $MNT 2>/dev/null
			rmmod mxfs 2>/dev/null; sleep 1; rmmod mxfs 2>/dev/null
			true" >/dev/null 2>&1 ) &
	done
	wait
	cyc_leak=0
	for i in $(seq 1 "$N"); do
		r=$(timeout 15 "$SSH" "test$i" "
			a=\$(dmesg | grep -c 'P142-DWORK-LASTREF')
			b=\$(dmesg | grep -c 'P202-LEAKED-INODE-AT-UNLOAD')
			g=\$(dmesg | grep -c 'P6G-REL-STALE-TEARDOWN')
			s=\$(dmesg | grep -c 'P6G-REL-STALE ')
			w=\$(dmesg | grep -c 'P6S-ARMSWEEP')
			x=\$(dmesg | grep -c 'P6S-ARM-REFUSED')
			e=\$(dmesg | grep -c 'P6S-SWEEP-BADREF')
			echo \"\$a \$b \$g \$s \$w \$x \$e\"" 2>/dev/null)
		set -- $r
		[ "${1:-0}" -gt 0 ] || [ "${2:-0}" -gt 0 ] && {
			echo "  LEAK test$i: P142-LASTREF=${1:-?} P202=${2:-?}"
			cyc_leak=$((cyc_leak+1))
			timeout 15 "$SSH" "test$i" \
				"dmesg | grep -E 'P6G-REL-STALE|P142-DWORK|P202-LEAKED' | tail -8" 2>/dev/null | sed 's/^/    /'
		}
		[ "${3:-0}" -gt 0 ] && echo "  test$i: TEARDOWN-gate engaged ${3}x (P6G-stranded=${4:-0})"
		[ "${5:-0}${6:-0}" != "00" ] && echo "  test$i: P6S sweep=${5:-0} refused=${6:-0} badref=${7:-0}"
	done
	echo "  cycle $c: leaking_nodes=$cyc_leak"
	leaks_total=$((leaks_total+cyc_leak))
done
echo "=== teardown repro done: cycles=$CYCLES leaking_nodes_total=$leaks_total ==="
[ "$leaks_total" -eq 0 ]
