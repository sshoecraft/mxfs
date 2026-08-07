#!/bin/bash
# racebail_loss_join.sh — does P34J-RELOAD-RACE-BAIL fire on the SAME directory
# that lost an entry?
#
# WHY (ccloop c7ee71c6 sess27, D-SILENT-MKDIR-LOSS)
#   Caught at 8/caw on 0.11.237: dirent_durability FAIL, test3
#   durable_loss=5 late_ok=15 at a 91s wall, and the scoped window held
#   P34J-RELOAD-RACE-BAIL=5 with EVERY other mechanism marker at zero
#   (P195/P194/P32E/P189/P146V/P177/P188/P65 all 0).  5 == 5 is a strong hint
#   but only a COUNT.  The bails were on 5 distinct inodes, all
#   'demoter=1 epoch==entry_epoch' (the foreign-drain arm).
#
#   The join could not be done from surviving state because TEARDOWN_LAG=10
#   removes the losing rounds before anything can stat them.  So
#   dirent_durability now stamps `MXFS_DD_LOSS ... dir_ino=<round dir inode>`
#   into /dev/kmsg, inside the same MXFS_DIRENT_WINDOW scope the census uses.
#   That inode is the join key: the bail names the inode whose reload it
#   abandoned, and the round directory is the parent whose entries went
#   missing.
#
#   INTERSECTION NON-EMPTY -> the race bail is the producer, and the fix is the
#   sess22-shaped bounded RETRY of the reload rather than abandoning it.
#   INTERSECTION EMPTY with both counts nonzero -> the 5==5 is coincidence and
#   the bail is exonerated; look elsewhere and record that.
#
# NOTE ON WHAT THE SYMPTOM IS.  In the 8/caw capture every entry was PRESENT
# minutes later, and SETTLE_MS is 4000ms.  So this shape is a bounded-staleness
# violation (a committed mkdir invisible to a peer for >4s), not permanent loss.
# Still a correctness defect; describe it accurately.
#
# USAGE  tests/racebail_loss_join.sh [iters] [nodecount]
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO"
ITERS="${1:-6}"
N="${2:-8}"

# RULE 0: derived from the manifest budget plus measured harness overhead.
# Measured this session at 8/caw: prep 35s, dirent_durability 91-119s.
PREP_BUDGET=$((300 + 40))
DD_BUDGET=$((240 + 40))
# aging batch: crash 90 + dir_reuse 120 + fence 60 + netpart 60 + soak 60
AGE_BUDGET=$((390 + 60))
SSH_BUDGET=60

for k in $(seq 1 "$ITERS"); do
    echo "########## iteration $k of $ITERS (${N}/caw) ##########"
    MXFS_FORCE_PREP=1 timeout "$PREP_BUDGET" ./run.sh "$N" caw prep_cluster 2>&1 | tail -1
    # AGE THE MOUNT FIRST.  The 8/caw capture did NOT come from
    # prep-then-dirent_durability: it came during the matrix sweep, after this
    # exact P6 batch had run on the same mount.  Seven fresh-prep iterations
    # produced ZERO failures, so the aging is load-bearing — same lesson as the
    # typeflip reproducer, where cache_coherency only fails AFTER an aging pass
    # and passes on a fresh mount (which is why the board showed it green).
    timeout "$AGE_BUDGET" ./run.sh "$N" caw crash_consistency dir_reuse_coherency \
        fence_during_write fault_netpartition soak 2>&1 \
        | grep -E "  (FAIL|BLOCK|ABORT)" || true
    out=$(timeout "$DD_BUDGET" ./run.sh "$N" caw dirent_durability 2>&1 | grep -E "  (PASS|FAIL|BLOCK)")
    echo "$out"
    case "$out" in
        *FAIL*) ;;
        *) continue ;;
    esac

    echo "--- FAILED: harvesting the join on all $N nodes (capture BEFORE teardown) ---"
    d=$(mktemp -d)
    for i in $(seq 1 "$N"); do
        n="test$i"
        timeout "$SSH_BUDGET" tools/mxfs_sshpass.sh "$n" '
            L=$(dmesg | grep -n MXFS_DIRENT_WINDOW | tail -1 | cut -d: -f1)
            if [ -n "$L" ]; then dmesg | tail -n +$((L+1)) > /tmp/rbj.txt
            else dmesg > /tmp/rbj.txt; fi
            grep -E "MXFS_DD_LOSS|P34J-RELOAD-RACE-BAIL" /tmp/rbj.txt' \
            2>/dev/null | grep -vE 'Warning|Unauthorized|authorized user' \
            > "$d/$n" &
        while [ "$(jobs -rp | wc -l)" -ge 8 ]; do wait -n; done
    done
    wait

    python3 - "$d" <<'PY'
import sys, os, re, glob
d = sys.argv[1]
tot_loss = tot_bail = tot_hit = 0
for f in sorted(glob.glob(os.path.join(d, 'test*'))):
    node = os.path.basename(f)
    losses, bails = {}, {}
    for line in open(f, errors='replace'):
        m = re.search(r'MXFS_DD_LOSS round=(\d+) rank=(\d+) dir_ino=(\d+) missing=(\S+)', line)
        if m:
            losses[int(m.group(3))] = (m.group(1), m.group(4))
            continue
        m = re.search(r'P34J-RELOAD-RACE-BAIL ino=(\d+)', line)
        if m:
            bails[int(m.group(1))] = bails.get(int(m.group(1)), 0) + 1
    if not losses and not bails:
        continue
    hit = set(losses) & set(bails)
    tot_loss += len(losses); tot_bail += len(bails); tot_hit += len(hit)
    print(f'  {node}: losses={len(losses)} bailed_inodes={len(bails)} '
          f'INTERSECTION={len(hit)}')
    for ino in sorted(hit):
        rnd, miss = losses[ino]
        print(f'      *** JOIN ino={ino} round=r{rnd} missing=[{miss}] '
              f'bails={bails[ino]}')
    for ino in sorted(set(losses) - set(bails)):
        rnd, miss = losses[ino]
        print(f'      no-bail  ino={ino} round=r{rnd} missing=[{miss}]')
print(f'  TOTALS: loss_dirs={tot_loss} bailed_inodes={tot_bail} '
      f'intersection={tot_hit}')
if tot_loss == 0:
    v = 'NO LOSS RECORDED — the MXFS_DD_LOSS kmsg stamp did not land; fix the harness before reading anything else'
elif tot_hit > 0:
    v = (f'{tot_hit} of {tot_loss} losing directories WERE race-bailed — '
         'the bail is on the losing directory')
elif tot_bail == 0:
    v = 'losses occurred with ZERO race bails in the window — the bail is NOT necessary for this failure'
else:
    v = (f'{tot_bail} bails and {tot_loss} losses but ZERO overlap — the '
         'equal-counts coincidence is REFUTED; the bail is exonerated here')
print('  VERDICT: ' + v)
PY
    echo "    raw: $d"
    exit 10
done
echo "=== no failure in $ITERS iterations — the bail/loss join was not exercised ==="
