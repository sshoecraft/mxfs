#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Gate 2 — NET2 core engine / midcomms (DLM_IMPL_PLAN.md §11 step 2).
#
# User-mode part (default): the §13.1 midcomms matrix against the real
# engine over localhost TCP — loss/dup/reorder/delay incl. ACK loss,
# TCP reset at framing points, per-class backpressure, restart with
# slot reuse, epoch change mid-op, window/SACK/serial boundaries,
# malformed + cross-cluster, COMM_AMBIGUOUS.  Runs the compressed
# matrix at 3 seeds + the pinned real-time subset (spec-default
# tunables) + an AddressSanitizer sweep of the matrix.  Matrix = the
# wire statics + §13.1 midcomms group (`run midcomms`): gate 4 owns the
# shard group and gate 5 the mepoch group, each with its own full-suite
# ASan sweep — re-running them here would double-bill their budgets
# (same re-scope gate 1 got when gate 2 took the matrix).
#
# Kernel part (--kernel-smoke, SEPARATE INVOCATION): 2-node echo smoke
# over mxfs.ko.  GATED on Kbuild checkpoint A — refuses to run unless
# mxfs.ko actually contains the net2 objects, so it cannot be invoked
# before the user has approved the Kbuild edit.
#
# ── RULE-0 budget (written BEFORE first run; tighten after healthy PASS) ──
#   infra    = harness clean build ×2 (normal + ASan): measured ~10 s
#   workload = matrix: 19 scenarios ≈ 3 s/run compressed
#              × 3 seeds + rt subset (~3 s) + ASan run (~6 s) ≈ 18 s
#              native == the harness itself  =>  ×2 = 36 s
#   SCEN_BUDGET_S (everything after first build) = 45
#   (calibrated 2026-07-17: actual 27 s on clyde; provisional 60
#   tightened toward it per RULE 0)
#   RULE0_CALIBRATE=1 => measure + report, do not enforce (budget-
#   pinning run).  A timeout or overrun is a FAIL (RULE 0.3), never a
#   retry-with-bigger-timeout.
#
# Usage: gate2_midcomms.sh                 (user-mode gate)
#        gate2_midcomms.sh --kernel-smoke  (after checkpoint A only)

set -u
cd "$(dirname "$0")"
REPO="$(cd ../.. && pwd)"
SCEN_BUDGET_S="${SCEN_BUDGET_S:-45}"
CAL="${RULE0_CALIBRATE:-0}"
SEEDS="0xF422 0xBEEF 0x1234"

fail=0

if [ "${1:-}" = "--kernel-smoke" ]; then
    # ── Kernel 2-node smoke (checkpoint-A-gated) ──
    if ! modinfo "$REPO/mxfs.ko" >/dev/null 2>&1; then
        echo "RESULT: FAIL | test=net2_gate2_smoke | nodes=2 | measured=- | reason=no-mxfs.ko"
        exit 1
    fi
    if ! grep -q 'net2_midcomms' "$REPO/Kbuild"; then
        echo "gate2: Kbuild does not list the net2 objects."
        echo "gate2: checkpoint A (explicit user go-ahead) has not happened;"
        echo "gate2: refusing to run the kernel smoke."
        echo "RESULT: FAIL | test=net2_gate2_smoke | nodes=2 | measured=- | reason=checkpoint-A-not-approved"
        exit 1
    fi
    # ── RULE-0 budget (written BEFORE first run; success.md provisional):
    #    infra    = node reset ×2: umount+rmmod fast path ~15 s each,
    #               power-cycle fallback ~50 s + NFS ensure  => ≤ 120 s
    #    workload = insmod stagger ~5 s + 16-msg echo both ways (native
    #               LAN RTT: sub-second) + marker-poll granularity 3 s;
    #               the in-module deadline is 60 s, so the harvest poll
    #               runs 75 s to COLLECT a FAIL marker (that longer
    #               harvest only happens on the already-failed path)
    #    SMOKE_BUDGET_S: provisional was 180 (reset 120 + workload 60);
    #    first healthy PASS measured 13 s (fast-path reset, no
    #    power-cycle) => pinned 60 (RULE-0 tighten-toward-actual; the
    #    power-cycle fallback path exceeding it is a diagnosable FAIL,
    #    not routine — smoke nodes are idle by construction).
    #    Overrun = FAIL (RULE 0.3).
    SSH="$REPO/tools/mxfs_sshpass.sh"
    PF=/tmp/.mxfs_pass
    T1=192.168.120.186
    T2=192.168.120.182
    SMOKE_BUDGET_S="${SMOKE_BUDGET_S:-60}"
    start_s=$SECONDS

    MODINFO=$(command -v modinfo || echo /usr/sbin/modinfo)
    WANT_SV=$("$MODINFO" "$REPO/mxfs.ko" 2>/dev/null | awk '/^srcversion/{print $2}')
    if [ -z "$WANT_SV" ]; then
        echo "RESULT: FAIL | test=net2_gate2_smoke | nodes=2 | measured=- | reason=no-srcversion"
        exit 1
    fi

    rsh() { # host cmd
        timeout 30 "$SSH" "$1" "$PF" "$2" 2>&1 | \
            grep -vE '^Warning|^Unauthorized|^If you'
    }

    # Reset one node: umount + rmmod (3 tries), ensure /src NFS.
    # Prints NODE_READY on success.
    node_reset() { # host
        timeout 90 "$SSH" "$1" "$PF" 'sudo bash -s' 2>&1 <<'EOS' | \
            grep -vE '^Warning|^Unauthorized|^If you'
set -u
umount -f /mnt/shared 2>/dev/null; umount -l /mnt/shared 2>/dev/null
ok=0
for i in 1 2 3; do
    if ! lsmod | grep -q '^mxfs '; then ok=1; break; fi
    if rmmod mxfs 2>/dev/null; then ok=1; break; fi
    sleep 5
done
[ "$ok" = 1 ] || { echo UNLOAD_FAIL; exit 1; }
if ! mountpoint -q /src; then
    mkdir -p /src
    mount -t nfs 192.168.1.4:/src /src \
        -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp,rsize=1048576,wsize=1048576 \
        || { echo NFS_FAIL; exit 1; }
fi
[ -f /src/mxfs/mxfs.ko ] || { echo NO_KO; exit 1; }
echo NODE_READY
EOS
    }

    # Power-cycle fallback for a wedged unload (VM reset is allowed;
    # the HOST is never touched — RULE 2).
    node_powercycle() { # vmname host
        sudo virsh destroy "$1" >/dev/null 2>&1
        sudo virsh start "$1" >/dev/null 2>&1
        for try in $(seq 1 30); do
            if timeout 3 "$SSH" "$2" "$PF" 'echo R' 2>/dev/null | grep -q R; then
                return 0
            fi
            sleep 3
        done
        return 1
    }

    ensure_ready() { # vmname host
        local out
        out=$(node_reset "$2")
        if ! echo "$out" | grep -q NODE_READY; then
            echo "gate2: $1 reset failed ($out) — power-cycling the VM"
            node_powercycle "$1" "$2" || { echo "gate2: $1 ssh never came back"; return 1; }
            out=$(node_reset "$2")
            echo "$out" | grep -q NODE_READY || { echo "gate2: $1 still not ready ($out)"; return 1; }
        fi
        return 0
    }

    # Clear dmesg + insmod with selftest params; prints INSMOD_OK sv=<sv>.
    node_insmod() { # host self_slot peer_ip peer_slot
        timeout 60 "$SSH" "$1" "$PF" \
            "sudo bash -s -- $2 $3 $4" 2>&1 <<'EOS' | \
            grep -vE '^Warning|^Unauthorized|^If you'
set -u
dmesg -C
insmod /src/mxfs/mxfs.ko net2_selftest=1 \
    net2_selftest_slot="$1" net2_selftest_peer="$2" \
    net2_selftest_peer_slot="$3" || { echo INSMOD_FAIL; exit 1; }
echo "INSMOD_OK sv=$(cat /sys/module/mxfs/srcversion)"
EOS
    }

    echo "== gate2 kernel smoke: reset test1+test2 =="
    ensure_ready test1 "$T1" || { echo "RESULT: FAIL | test=net2_gate2_smoke | nodes=2 | measured=- | reason=t1-reset"; exit 1; }
    ensure_ready test2 "$T2" || { echo "RESULT: FAIL | test=net2_gate2_smoke | nodes=2 | measured=- | reason=t2-reset"; exit 1; }

    echo "== gate2 kernel smoke: insmod (t1 slot0 <-> t2 slot1) =="
    out1=$(node_insmod "$T1" 0 "$T2" 1)
    out2=$(node_insmod "$T2" 1 "$T1" 0)
    echo "t1: $out1"
    echo "t2: $out2"
    sv1=$(echo "$out1" | sed -n 's/.*INSMOD_OK sv=//p' | tr -d '\r')
    sv2=$(echo "$out2" | sed -n 's/.*INSMOD_OK sv=//p' | tr -d '\r')

    echo "== gate2 kernel smoke: harvest markers =="
    l1=""; l2=""
    for i in $(seq 1 25); do   # 25 × 3 s = 75 s harvest window
        [ -z "$l1" ] && l1=$(rsh "$T1" "sudo dmesg | grep -m1 'net2_selftest: '" | tail -1)
        [ -z "$l2" ] && l2=$(rsh "$T2" "sudo dmesg | grep -m1 'net2_selftest: '" | tail -1)
        [ -n "$l1" ] && [ -n "$l2" ] && break
        sleep 3
    done
    echo "t1 marker: ${l1:-NO_MARKER}"
    echo "t2 marker: ${l2:-NO_MARKER}"

    echo "== gate2 kernel smoke: unload =="
    rsh "$T1" "sudo rmmod mxfs && echo T1_RMMOD_OK"
    rsh "$T2" "sudo rmmod mxfs && echo T2_RMMOD_OK"

    wall=$((SECONDS - start_s))
    verdict=PASS; reason=""
    case "$l1" in *"net2_selftest: PASS"*) : ;; *) verdict=FAIL; reason="t1-marker" ;; esac
    case "$l2" in *"net2_selftest: PASS"*) : ;; *) verdict=FAIL; reason="${reason:+$reason,}t2-marker" ;; esac
    if [ "$sv1" != "$WANT_SV" ] || [ "$sv2" != "$WANT_SV" ]; then
        verdict=FAIL; reason="${reason:+$reason,}srcversion(sv1=$sv1,sv2=$sv2,want=$WANT_SV)"
    fi
    if [ "$wall" -gt "$SMOKE_BUDGET_S" ]; then
        verdict=FAIL; reason="${reason:+$reason,}rule0-budget($wall>${SMOKE_BUDGET_S}s)"
    fi
    [ -n "$reason" ] || reason=-
    echo "RESULT: $verdict | test=net2_gate2_smoke | nodes=2 | measured=wall_s=$wall,budget_s=$SMOKE_BUDGET_S,sv=$WANT_SV | reason=$reason"
    [ "$verdict" = PASS ] && exit 0 || exit 1
fi

t0=$(date +%s)
echo "== gate2: harness clean build =="
make clean >/dev/null 2>&1
if ! make 2>&1 | tail -5; then
    echo "RESULT: FAIL | test=net2_gate2 | nodes=1 | measured=- | reason=harness-build-failed"
    exit 1
fi
t_build=$(( $(date +%s) - t0 ))
echo "build_wall_s=$t_build"

run_matrix() {
    local label="$1"; shift
    local out
    out="$("$@" 2>/dev/null | grep '^RESULT:')"
    echo "$out"
    local pass ntot
    pass=$(echo "$out" | grep -c 'RESULT: PASS')
    ntot=$(echo "$out" | grep -c 'RESULT:')
    if [ "$ntot" -eq 0 ] || [ "$pass" -ne "$ntot" ]; then
        echo "gate2: $label: $pass/$ntot passed — FAIL"
        fail=1
    else
        echo "gate2: $label: $pass/$ntot passed"
    fi
}

t1=$(date +%s)
for seed in $SEEDS; do
    echo "== gate2: full matrix, seed $seed =="
    run_matrix "matrix seed=$seed" ./net2_harness run midcomms --seed "$seed"
done

echo "== gate2: pinned real-time subset (spec-default tunables) =="
run_matrix "rt-subset" ./net2_harness run rt

echo "== gate2: AddressSanitizer sweep =="
make clean >/dev/null 2>&1
if ! make CFLAGS="-O1 -g -std=gnu11 -Wall -Wextra -Werror -fsanitize=address" >/dev/null 2>&1; then
    echo "RESULT: FAIL | test=net2_gate2 | nodes=1 | measured=- | reason=asan-build-failed"
    exit 1
fi
asan_log=$(mktemp)
run_matrix "asan matrix" ./net2_harness run midcomms
./net2_harness run midcomms >/dev/null 2>"$asan_log" || true
if grep -qE 'ERROR: (Address|Leak)Sanitizer' "$asan_log"; then
    echo "gate2: sanitizer errors:"
    grep -E 'ERROR: (Address|Leak)Sanitizer' "$asan_log" | head -5
    fail=1
fi
rm -f "$asan_log"

# Leave a normal (non-sanitizer) binary behind.
make clean >/dev/null 2>&1
make >/dev/null 2>&1

t_scen=$(( $(date +%s) - t1 ))
echo "scenario_wall_s=$t_scen budget_s=$SCEN_BUDGET_S"
if [ "$CAL" != "1" ] && [ "$t_scen" -gt "$SCEN_BUDGET_S" ]; then
    echo "RULE-0 overrun: ${t_scen}s > ${SCEN_BUDGET_S}s — FAIL"
    fail=1
fi

status=PASS
[ "$fail" -ne 0 ] && status=FAIL
echo "RESULT: $status | test=net2_gate2 | nodes=1 | measured=build_s=$t_build,scen_s=$t_scen,budget_s=$SCEN_BUDGET_S | reason=$([ $fail -eq 0 ] && echo - || echo failures-above)"
[ "$fail" -eq 0 ]
