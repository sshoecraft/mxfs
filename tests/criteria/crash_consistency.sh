#!/bin/bash
# Criterion: Acknowledged writes (post-fsync, post-close) survive any
# node death.  Verifier: writer node writes N records to a file, fsyncs
# after each, records the last-fsync'd record id.  Then virsh-destroy
# the writer node.  Reader on a different surviving node opens the
# file and verifies every record up to and including the recorded id
# is present.  Threshold: 100% of acknowledged records readable; 0 loss.

set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"
result_init "crash_consistency"
set_script_timeout 600

parse_common_args "$@"
[ "${#NODES[@]}" -ge 2 ] || result_fail "n/a" "need-2-nodes" "crash test requires >= 2 nodes"
WRITER="${NODES[0]}"
READER="${NODES[1]}"
REST=("${NODES[@]:1}")  # everything except writer mounts
RECORDS=200

teardown_all "${NODES[*]}"
# Crash recovery is gated by the disklock dead-declaration window —
# defaults to 62 s (31 stale heartbeat samples × 2 s) for production
# conservatism.  Test rigs need much faster fail-detect, so override it
# to 16 s via the v0.5.0 lease_timeout_ms module param (read at insmod,
# plumbed from fresh_cluster_mount via INSMOD_OPTS).  NOTE the old
# mxfs_lease_* names never existed as params — insmod silently ignored
# them and detection ran at the 62 s default (sess18 root cause).
INSMOD_OPTS="lease_timeout_ms=16000" \
fresh_cluster_mount "$WRITER" "${REST[@]}" \
    || result_fail "n/a" "mount-ok" "cluster mount failed"

FILE="$MXFS_MOUNT/crash_consistency_test"
ssh_node_quiet "$WRITER" "rm -f $FILE; sync"

# Writer: append RECORDS lines, fsync after each, record progress to
# /tmp/last_fsync.  When ~half done, kill the writer node.
LAST_RECORD_FILE="/tmp/${$}_last_fsync.txt"
( ssh_node "$WRITER" "
    : > /tmp/last_fsync
    for k in \$(seq 1 $RECORDS); do
        printf 'record_%06d\n' \$k >> $FILE
        # fsync via python so we don't have to depend on coreutils-fsync
        python3 -c \"import os; fd=os.open('$FILE', os.O_RDWR); os.fsync(fd); os.close(fd)\"
        echo \$k > /tmp/last_fsync
        # Sleep just long enough to make timing controllable
        sleep 0.02
    done
" >/tmp/writer.log 2>&1 ) &
WRITER_BG=$!

# Wait until writer is roughly half done, then kill the VM
target=$(( RECORDS / 2 ))
deadline=$(( $(date +%s) + 30 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    progress=$(ssh_node "$WRITER" "cat /tmp/last_fsync 2>/dev/null" 2>/dev/null | tail -1 | tr -d ' \r\n')
    progress=${progress:-0}
    if [ "$progress" -ge "$target" ]; then break; fi
    sleep 0.5
done

# Record the last-acknowledged record before the kill
acked=$(ssh_node "$WRITER" "cat /tmp/last_fsync 2>/dev/null" | tail -1 | tr -d ' \r\n')
acked=${acked:-0}
[ "$acked" -gt 0 ] || { kill -9 $WRITER_BG 2>/dev/null; result_fail "acked=0" "acked>0" "writer made no progress"; }

# Kill the writer hard.  virsh destroy is the cleanest hard-kill.
virsh -c qemu:///system destroy "$WRITER" >/dev/null 2>&1
kill -9 $WRITER_BG 2>/dev/null

# Wait for the survivors' fencing to remove the writer.  TCP DLM
# eviction is gated by lease expiry (we pinned that to 30 s above)
# plus journal replay (a few s).  60 s gives the recovery thread
# ample headroom; bump if recovery becomes longer.
sleep 60

# On the reader, count how many records up to $acked are visible
out=$(ssh_node "$READER" "
    if ! mount | grep -q ' on $MXFS_MOUNT type mxfs'; then echo READER_NOT_MOUNTED; exit 1; fi
    if [ ! -f $FILE ]; then echo READER_NO_FILE; exit 2; fi
    visible=\$(wc -l < $FILE 2>/dev/null | tr -d ' ')
    visible=\${visible:-0}
    # Verify records 1..acked are all there in order
    bad=\$(awk -v want=$acked '
        { got = \$0
          n = NR
          expected = sprintf(\"record_%06d\", n)
          if (got != expected) { bad++; if (bad<3) print \"mismatch line=\" n \" got=\" got \" expected=\" expected > \"/dev/stderr\" }
          if (n == want) { exit }
        }
        END { if (NR < want) print \"short: NR=\" NR \" want=\" want > \"/dev/stderr\"; print bad+0 }
    ' $FILE)
    echo VISIBLE=\$visible
    echo BAD=\$bad
")
visible=$(echo "$out" | sed -n 's/^VISIBLE=//p' | tail -1)
bad=$(echo "$out" | sed -n 's/^BAD=//p' | tail -1)
visible=${visible:-0}; bad=${bad:-1}
# Distinguish "reader couldn't look" (sentinel) from genuine record loss —
# sess17: visible=0 was untraceable because the sentinel was swallowed here.
sentinel=$(echo "$out" | grep -oE 'READER_NOT_MOUNTED|READER_NO_FILE' | head -1)

# Resurrect the killed writer synchronously — DON'T background, or the
# next test that uses this node will hit a partially-booted VM (state
# leak).  Wait until SSH + NFS-served module file is reachable.
virsh -c qemu:///system start "$WRITER" >/dev/null 2>&1
for try in $(seq 1 30); do
    if timeout 8 "$MXFS_SSH" "$WRITER" "$MXFS_PASS" "
        mkdir -p /src
        mountpoint -q /src || mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null
        [ -f $MXFS_MODULE ]
    " >/dev/null 2>&1; then break; fi
    sleep 2
done

# Clean up survivors
parallel_ssh_quiet "${REST[*]}" "umount $MXFS_MOUNT 2>/dev/null; rmmod mxfs 2>/dev/null"
wait

[ -n "$sentinel" ] && result_fail "acked=$acked visible=$visible sentinel=$sentinel" \
    "visible>=acked bad=0" "reader-side failure: $sentinel"
if [ "$visible" -lt "$acked" ]; then
    result_fail "acked=$acked visible=$visible bad=$bad" "visible>=acked bad=0" \
        "$(( acked - visible )) acknowledged records lost after crash"
fi
[ "$bad" = "0" ] || result_fail "acked=$acked visible=$visible bad=$bad" "visible>=acked bad=0" \
    "$bad records corrupted/reordered"
result_pass "acked=$acked visible=$visible bad=0" "visible>=acked bad=0"
