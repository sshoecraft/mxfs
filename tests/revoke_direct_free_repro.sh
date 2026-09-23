#!/bin/bash
# tests/revoke_direct_free_repro.sh <label> [poisons]
#
# Directed reproducer for D-TCP-INCARN-REVOKE-WORKER-IRELE-HITS-IPUT-BUG-NODE-PANIC.
#
# The hypothesis under test: an incarnation revocation (mxfs_incarn_poison ->
# igrab -> queued mxfs_incarn_revoke_work_fn) can be queued on an inode that
# xfs_iget_cache_miss has not inserted into the cache yet, and that function's
# error exit (out_destroy) frees such an inode directly, ignoring i_count.  The
# worker then releases a reference on a freed object: iput's BUG_ON(I_CLEAR).
#
# The natural shape is a three-way race (a lookup's coordinated reload meeting
# a peer's new incarnation behind a protected cluster buffer, then failing
# ENOENT) with no deterministic exerciser, so this arms dbg_poison_direct_free
# on test1, which poisons the next N inodes the miss path frees directly, and
# drives that exit on demand: open_by_handle_at on inode numbers adjacent to a
# fresh file, which the untrusted iget finds free (xfs_imap -EINVAL ->
# out_destroy).  Everything after the poison is the shipping code.
#
# Verdicts, read from test1's kernel log and the netconsole capture:
#   REPRODUCED  P-REVOKE-DIRECT-FREE fired, or test1 oopsed/panicked
#   CLEAN       poisons were injected (P-DBG-POISON-DIRECT-FREE > 0), no
#               direct free with a revocation outstanding, no oops, and test1
#               still has its mount
#   VACUOUS     no poison was injected — the exit was never driven
#
# derived time budgets: prep 400 s (tests/dirent_durability_loop.sh's bound
# for the same 2/tcp prep); 64 handle opens, each one untrusted iget under the
# AG DLM (ms each), 30 s; the revocation runs 3-68 ms after its poison
# (measured, xfs_inode.c retire-arm comment), so 3 s settles every worker.
set -u
cd /src/mxfs || exit 2
LABEL=${1:?label}
POISONS=${2:-8}
NC=tests/evidence/netconsole.log
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_revdf_$LABEL
mkdir -p "$OUT"
SSH=tools/mxfs_sshpass.sh
PROBE=/src/mxfs/tools/handle_probe
[ -x "$PROBE" ] || cc -O2 -static -o "$PROBE" tools/handle_probe.c \
    || { echo "RESULT: ABORT label=$LABEL stage=handle_probe-build"; exit 2; }
nc_mark=$(wc -l < "$NC" 2>/dev/null || echo 0)
echo "=== revdf $LABEL START $(date -u +%FT%TZ) VERSION=$(cat VERSION) sv=$(modinfo -F srcversion mxfs.ko) poisons=$POISONS out=$OUT netconsole_from_line=$nc_mark ==="

timeout 400 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1 \
    || { echo "RESULT: ABORT label=$LABEL stage=prep evidence=$OUT"; exit 2; }

# The workload, run on test1 as one remote script.
cat > "$OUT/node_work.sh" <<EOF
set -u
D=/mnt/shared/revdf.\$\$
mkdir -p \$D || exit 3
for i in 1 2 3 4; do echo x > \$D/f\$i; done
sync
read -r TYPE HEX < <($PROBE encode \$D/f1)
echo "handle type=\$TYPE hex=\$HEX"
MARK="REVDF-MARK-\$\$-\$(date +%s%N)"
echo "\$MARK" > /dev/kmsg
echo $POISONS > /sys/module/mxfs/parameters/dbg_poison_direct_free
opened=0; failed=0
for off in \$(seq 1 64); do
    NHEX=\$(python3 -c '
import sys
t, h, off = int(sys.argv[1]), bytes.fromhex(sys.argv[2]), int(sys.argv[3])
w = 8 if t & 0x80 else 4
ino = int.from_bytes(h[:w], "little") + off
sys.stdout.write((ino.to_bytes(w, "little") + h[w:]).hex())
' "\$TYPE" "\$HEX" "\$off")
    if timeout 30 $PROBE open /mnt/shared "\$TYPE" "\$NHEX" 1 >/dev/null 2>&1; then
        opened=\$((opened + 1))
    else
        failed=\$((failed + 1))
    fi
done
echo "handle_opens opened=\$opened failed=\$failed"
sleep 3
echo 0 > /sys/module/mxfs/parameters/dbg_poison_direct_free
echo "mounted=\$(grep -c ' /mnt/shared mxfs ' /proc/mounts)"
for p in P-DBG-POISON-DIRECT-FREE P-POISON-UNINSERTED P-REVOKE-DIRECT-FREE P-REVOKE-REF-LOST P-REVOKE-EVICT-EARLY P34H-INCARN-REVOKED; do
    echo "count \$p \$(dmesg | sed -n "/\$MARK/,\\\$p" | grep -ac -- "\$p")"
done
rm -rf \$D
EOF

timeout 60 "$SSH" test1 "bash -s" < "$OUT/node_work.sh" > "$OUT/node_work.out" 2>&1
rc=$?
sleep 3
timeout 20 "$SSH" test1 "dmesg" > "$OUT/test1_dmesg.txt" 2>&1
tail -n +"$((nc_mark + 1))" "$NC" > "$OUT/netconsole_window.txt"
panics=$(grep -ac 'invalid opcode\|Kernel panic\|BUG:\|Oops' "$OUT/netconsole_window.txt")
cnt() { awk -v p="$1" '$1=="count" && $2==p {print $3}' "$OUT/node_work.out" | tail -1; }
inj=$(cnt P-DBG-POISON-DIRECT-FREE); unins=$(cnt P-POISON-UNINSERTED)
dfree=$(cnt P-REVOKE-DIRECT-FREE); rlost=$(cnt P-REVOKE-REF-LOST)
mounted=$(awk -F= '/^mounted=/ {print $2}' "$OUT/node_work.out" | tail -1)
grep -a '^handle_opens\|^handle type' "$OUT/node_work.out"
echo "rc=$rc injected=${inj:-?} uninserted=${unins:-?} direct_free=${dfree:-?} ref_lost=${rlost:-?} mounted=${mounted:-?} netconsole_oops=$panics"
grep -a -m3 'P-REVOKE-DIRECT-FREE\|P-POISON-UNINSERTED' "$OUT/test1_dmesg.txt" | cut -c1-240
grep -a -m6 'invalid opcode\|RIP:\|Workqueue:\|Kernel panic' "$OUT/netconsole_window.txt" | cut -c1-200

if [ "${dfree:-0}" -gt 0 ] || [ "$panics" -gt 0 ]; then
    echo "RESULT: REPRODUCED label=$LABEL evidence=$OUT"; exit 1
fi
if [ "${inj:-0}" -gt 0 ] && [ "${mounted:-0}" = 1 ] && [ "$rc" = 0 ]; then
    echo "RESULT: CLEAN label=$LABEL injected=$inj evidence=$OUT"; exit 0
fi
if [ "${inj:-0}" = 0 ] && [ "$rc" = 0 ]; then
    echo "RESULT: VACUOUS label=$LABEL — no poison injected, the direct-free exit was never driven evidence=$OUT"; exit 1
fi
echo "RESULT: FAIL label=$LABEL rc=$rc mounted=${mounted:-?} evidence=$OUT"; exit 1
