#!/bin/bash
# stall_catch.sh — run ON a node.  Repeatedly sample the kernel stack of any
# task executing in the mxfs/xfs create path (open/create) AND any task blocked
# >0 in D/uninterruptible state, for DUR seconds.  Captures the frame where a
# concurrent-create stall sits (it is NOT always D-state; can be S in a DLM
# wait_event).  Output to a node-local file.
DUR="${1:-90}"
OUT="${2:-/root/stall_catch.log}"
: > "$OUT"
end=$(( SECONDS + DUR ))
while [ "$SECONDS" -lt "$end" ]; do
  for t in /proc/[0-9]*; do
    pid=${t#/proc/}
    comm=$(cat "$t/comm" 2>/dev/null) || continue
    st=$(awk '{print $3}' "$t/stat" 2>/dev/null)
    # interested in our test shells, dd, sync, and any kworker doing mxfs bast
    wchan=$(cat "$t/wchan" 2>/dev/null)
    case "$comm" in
      bash|sh|sync|dd|touch|ls|cat|mv|ln|kworker*)
        # dump stack only if blocked (state D or S with an mxfs/dlm wchan)
        if [ "$st" = "D" ] || [ "$st" = "R" ]; then
          stk=$(cat "$t/stack" 2>/dev/null)
          if echo "$stk" | grep -qiE 'mxfs|dlm|xfs_create|xfs_dir|xfs_trans|down_|rwsem|xfs_ilock|caw'; then
            echo "=== $(date +%T.%N) pid=$pid comm=$comm st=$st wchan=$wchan ===" >> "$OUT"
            echo "$stk" | head -18 >> "$OUT"
          fi
        fi
        ;;
    esac
  done
  sleep 0.4
done
echo "STALL_CATCH_DONE" >> "$OUT"
