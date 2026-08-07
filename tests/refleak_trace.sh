#!/bin/bash
# refleak_trace.sh — kernel-side per-inode refcount event trace for
# D-UNMOUNT-BUSY-INODES (sess27 GPT track, built sess36).
#
# Arms tracefs kprobes on the four real refcount symbols (6.8.0-101-generic,
# verified in kallsyms):  igrab, ihold, __iget, iput.  Each event logs the
# inode POINTER, the inode NUMBER (+80(%di) per BTF), and the entry-time
# i_count (+344(%di)), plus the automatic pid/comm/timestamp.  This sees the
# VFS-side releases (dput->iput, d_splice_alias's internal iput) that are
# structurally invisible to module-side chokepoints — the reason every
# pairing instrument (P202/P203/P205) dead-ended.
#
# Analysis model (LIFO-free): for the leaked ino, compute per-(pid) net
# balance grabs+holds+igets-iputs.  The leaked-local hypothesis predicts one
# task with net +1 beyond the known cross-task arm hand-offs (arm igrab in
# syscall task, irele in kworker — enumerable via the module's bastq prints).
#
# Offsets are for 6.8.0-101-generic ONLY (BTF-verified: i_sb=+56 i_ino=+80
# i_count=+344).  Re-derive on a kernel change:
#   bpftool btf dump file /sys/kernel/btf/vmlinux | awk "/STRUCT 'inode' /{f=1}
#     f && /'i_ino'|'i_sb'|'i_count'/{print}"   (bits/8)
#
# USAGE:
#   tests/refleak_trace.sh arm <node>      — arm probes + stream to /root/mxref_trace.txt
#   tests/refleak_trace.sh disarm <node>   — stop stream, disable probes (file kept)
#   tests/refleak_trace.sh fetch <node> <outfile> — copy the node's trace here
#   tests/refleak_trace.sh armall <N> / disarmall <N> — all test1..testN
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd -- "$SCRIPT_DIR/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
T=/sys/kernel/tracing

arm_one() {
	local n="$1"
	timeout 25 "$SSH" "$n" "
		set -e
		cd $T
		# clear any prior mxref probes (ignore busy errors)
		for p in iput igrab ihold iget; do
			echo \"-:mxref/\$p\" >> kprobe_events 2>/dev/null || true
		done
		echo 24576 > buffer_size_kb
		echo 'p:mxref/igrab igrab ptr=%di ino=+80(%di):u64 cnt=+344(%di):s32' >> kprobe_events
		echo 'p:mxref/ihold ihold ptr=%di ino=+80(%di):u64 cnt=+344(%di):s32' >> kprobe_events
		echo 'p:mxref/iget __iget ptr=%di ino=+80(%di):u64 cnt=+344(%di):s32' >> kprobe_events
		echo 'p:mxref/iput iput ptr=%di ino=+80(%di):u64 cnt=+344(%di):s32' >> kprobe_events
		echo > trace
		echo 1 > events/mxref/enable
		rm -f /root/mxref_trace.txt
		nohup sh -c 'cat $T/trace_pipe > /root/mxref_trace.txt' >/dev/null 2>&1 &
		echo armed
	" 2>/dev/null
}

disarm_one() {
	local n="$1"
	timeout 25 "$SSH" "$n" "
		cd $T 2>/dev/null || exit 0
		echo 0 > events/mxref/enable 2>/dev/null
		pkill -f 'cat $T/trace_pipe' 2>/dev/null
		sleep 0.3
		for p in iput igrab ihold iget; do
			echo \"-:mxref/\$p\" >> kprobe_events 2>/dev/null || true
		done
		wc -l /root/mxref_trace.txt 2>/dev/null || echo 'no trace file'
	" 2>/dev/null
}

case "${1:?arm|disarm|fetch|armall|disarmall}" in
arm)	arm_one "${2:?node}" ;;
disarm)	disarm_one "${2:?node}" ;;
fetch)	timeout 60 "$SSH" "${2:?node}" "cat /root/mxref_trace.txt" > "${3:?outfile}" 2>/dev/null
	wc -l "$3" ;;
armall)	for i in $(seq 1 "${2:?N}"); do arm_one "test$i" & done; wait ;;
disarmall) for i in $(seq 1 "${2:?N}"); do disarm_one "test$i" & done; wait ;;
esac
