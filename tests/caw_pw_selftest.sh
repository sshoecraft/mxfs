#!/bin/bash
# caw_pw_selftest.sh [mode] [node] [victim]
#
#   mode    basic | wrap | kill | all      (default: all)
#   node    node that runs the selftest    (default: test1)
#   victim  kill-mode victim               (default: test2)
#
# Driver for the in-kernel CAW PW/tenure-token selftest (0.11.462,
# dlm/v5_mount.c:mxfs_v5_dlm_caw_pw_selftest, debugfs trigger
# /sys/kernel/debug/mxfs/<s_id>/caw_pw_selftest).  Evidence vehicle for
# ledger #15 D-EX-GRANT-EPOCH-NOT-UNIQUE-TENURE-ID (sess169 edge-mint,
# sess170 vehicle ruling, sess171 kernel landing).
#
# The kernel side is the test; this script only triggers it and checks the
# externally observable contract:
#   write(2) rc          count on PASS, -EREMOTEIO on assertion failure,
#                        -EBUSY concurrent, -ENODEV/-ESHUTDOWN/-EOPNOTSUPP
#   verdict              mxfs: P274-PWTEST <PASS|FAIL> run= ino= t1= t3= t4=
#   preserve probes      dlm_caw: P274-GEP-PRESERVE rt= rk=<ino> ...  >= 3
#                        (a1-convert-ex, a1-reconvert-ex, a2-acquire-ex; the
#                        EX->PW downgrade takes caw_slot_clearing and emits
#                        none — the reconvert==T1 round-trip is that check;
#                        CAS -EAGAIN retries can add extras, hence >=)
#   upgrade probe        mxfs: P109-CLR-UPGRADE type=I id=<ino>
#                        old_mode=4 new_mode=5   >= 1, instr-gated
#
# Modes:
#   basic  one run, auto key (write 0), assert the contract above.
#   wrap   arm /sys/module/mxfs/parameters/caw_inject_gep_wrap (consumable),
#          re-run: first fresh mint consumes it -> P274-GEPWRAP-INJECT rk=K
#          prev=... forced=~0 and T1==1 on the PASS line (wrap skips 0,
#          sess169 ruling).  Any other fresh mint on the node can steal the
#          injection -> detected by rk mismatch, re-armed and retried (3x).
#   kill   ruling condition B: capture victim's key K_v with one PASS run,
#          spin the selftest in a tight loop on the victim, virsh-destroy it
#          mid-loop (near-certain death inside a hold window), then assert
#          the cluster survives (observer selftest PASS), the victim rejoins
#          (tests/setup/prep_node.sh -> NODE_PREP_OK), and an EXPLICIT re-run
#          on K_v passes — i.e. the slot the dead node held mid-tenure grants
#          again after purge.  Epoch continuity across purge is a #15-ledger
#          question and is deliberately NOT asserted here; purge-anomaly
#          probes (P23x) in the observer window are REPORTED, not asserted.
#
# RULE 0 budgets (native op is ms; walls are ssh + boot dominated):
#   basic 30s   wrap 90s (3 tries)   kill ~300s expected, 480s hard
#   (kill = 45s purge window + boot wait <=240s + prep <=120s + 3 selftests)
#
# Exit 0 = every requested mode PASS; 1 = any FAIL; 2 = usage/infra refusal.

set -u
REPO=/src/mxfs
SSH="$REPO/tools/mxfs_sshpass.sh"
VIRSH="virsh -c qemu:///system"
DEV="${MXFS_DEV:-/dev/mapper/mpatha}"
MODE="${1:-all}"
NODE="${2:-test1}"
VICTIM="${3:-test2}"
STAMP=$(date -u +%Y%m%dT%H%M%S)
OUT=$(mktemp -d)
FAILS=0

say() { echo "[pwtest] $*"; }

# ── node-side trigger: marker -> instr on -> write key -> restore -> harvest.
# One ssh per case so marker/run/harvest cannot interleave with anything else
# we do.  $1=marker $2=key (0=auto) $3=arm_wrap (0|1).  Output: WRITE_RC=,
# WRITE_ERR= (on failure), WRAP_KNOB_AFTER=, then the marker-scoped dmesg.
NODE_TRIGGER='
set -u
MARK="$1"; KEY="$2"; ARM="$3"
DBG=$(ls /sys/kernel/debug/mxfs/*/caw_pw_selftest 2>/dev/null | head -1)
[ -n "$DBG" ] || { echo "WRITE_RC=NO_DEBUGFS_FILE"; exit 0; }
INSTR=/sys/module/mxfs/parameters/instr
WRAP=/sys/module/mxfs/parameters/caw_inject_gep_wrap
old=$(cat "$INSTR" 2>/dev/null || echo 0)
echo 1 > "$INSTR"
[ "$ARM" = 1 ] && echo 1 > "$WRAP"
echo "$MARK" > /dev/kmsg
e=$(mktemp)
printf "%s" "$KEY" > "$DBG" 2>"$e"; rc=$?
echo "$old" > "$INSTR"
# END marker: reserving the next printk record FINALIZES the verdict record,
# without which /dev/kmsg readers deterministically miss the trailing line
# (measured 2/2 on 6.8.0-101: dmesg ms later still ended one record short).
echo "$MARK-END" > /dev/kmsg
echo "WRITE_RC=$rc"
[ "$rc" -ne 0 ] && echo "WRITE_ERR=$(tr -d "\n" < "$e")"
[ "$ARM" = 1 ] && echo "WRAP_KNOB_AFTER=$(cat "$WRAP" 2>/dev/null)"
dmesg | awk -v m="$MARK" "index(\$0,m){f=1} f"
'

# run_case <node> <tag> <key> <arm_wrap>; harvest -> $OUT/<tag>.log; parsed
# facts -> globals R_RC R_INO R_PASS R_FAIL R_PRESERVE R_P109 R_T1 R_T3 R_T4
run_case() {
    local node="$1" tag="$2" key="$3" arm="$4" log mark
    mark="MXFS_PWTEST_${tag}_${STAMP}"
    log="$OUT/$tag.log"
    timeout 30 "$SSH" "$node" "bash -s -- '$mark' '$key' '$arm'" \
        <<<"$NODE_TRIGGER" > "$log" 2>&1
    R_RC=$(sed -n 's/^WRITE_RC=//p' "$log" | head -1)
    R_INO=$(sed -n 's/.*P274-PWTEST START run=[0-9]* ino=\([0-9]*\).*/\1/p' "$log" | tail -1)
    R_PASS=$(grep -c "P274-PWTEST PASS" "$log")
    R_FAIL=$(grep -c "P274-PWTEST FAIL" "$log")
    if [ -n "$R_INO" ]; then
        R_PRESERVE=$(grep -Ec "P274-GEP-PRESERVE rt=[0-9]+ rk=$R_INO " "$log")
        R_P109=$(grep -c "P109-CLR-UPGRADE type=I id=$R_INO old_mode=4 new_mode=5" "$log")
    else
        R_PRESERVE=0; R_P109=0
    fi
    R_T1=; R_T3=; R_T4=
    eval "$(sed -n 's/.*P274-PWTEST PASS run=[0-9]* ino=[0-9]* t1=\([0-9]*\) t3=\([0-9]*\) t4=\([0-9]*\).*/R_T1=\1 R_T3=\2 R_T4=\3/p' "$log" | tail -1)"
}

basic_one() {                       # basic_one <node> <tag> <key>
    local node="$1" tag="$2" key="${3:-0}" ok=1
    run_case "$node" "$tag" "$key" 0
    say "$tag($node): write_rc=$R_RC ino=${R_INO:-none} pass=$R_PASS fail=$R_FAIL preserve=$R_PRESERVE p109=$R_P109 t1=${R_T1:--} t3=${R_T3:--} t4=${R_T4:--}"
    [ "$R_RC" = 0 ]        || { say "  ASSERT write rc==0 FAILED ($(sed -n 's/^WRITE_ERR=//p' "$OUT/$tag.log" | head -1))"; ok=0; }
    [ "$R_PASS" -ge 1 ]    || { say "  ASSERT >=1 PASS verdict FAILED"; ok=0; }
    [ "$R_FAIL" -eq 0 ]    || { say "  ASSERT 0 FAIL verdicts FAILED"; ok=0; }
    [ "$R_PRESERVE" -ge 3 ] || { say "  ASSERT >=3 GEP-PRESERVE rk=$R_INO FAILED"; ok=0; }
    [ "$R_P109" -ge 1 ]    || { say "  ASSERT >=1 P109-CLR-UPGRADE FAILED (instr gate?)"; ok=0; }
    [ "$ok" = 1 ] && { say "$tag($node): PASS"; return 0; }
    say "$tag($node): FAIL — evidence $OUT/$tag.log"; return 1
}

mode_basic() { basic_one "$NODE" basic 0 || FAILS=$((FAILS+1)); }

mode_wrap() {
    local try ok=0
    for try in 1 2 3; do
        run_case "$NODE" "wrap$try" 0 1
        local inj injrk knob
        inj=$(grep "P274-GEPWRAP-INJECT" "$OUT/wrap$try.log" | tail -1)
        injrk=$(echo "$inj" | sed -n 's/.*rk=\([0-9]*\).*/\1/p')
        knob=$(sed -n 's/^WRAP_KNOB_AFTER=//p' "$OUT/wrap$try.log" | head -1)
        say "wrap try$try($NODE): write_rc=$R_RC ino=${R_INO:-none} t1=${R_T1:--} inject_rk=${injrk:-none} knob_after=${knob:-?}"
        if [ -n "$injrk" ] && [ "$injrk" = "${R_INO:-x}" ]; then
            if [ "$R_RC" = 0 ] && [ "$R_FAIL" -eq 0 ] && [ "${R_T1:-0}" = 1 ]; then
                say "wrap($NODE): PASS — injected prev=~0 wrapped to t1=1 on rk=$injrk"
                ok=1; break
            fi
            say "wrap($NODE): FAIL — inject consumed by rk=$injrk but t1=${R_T1:--} rc=$R_RC fail=$R_FAIL"
            break
        fi
        say "wrap try$try: injection raced away (consumed by rk=${injrk:-nobody}), retrying"
    done
    # disarm if a retry exhausted with the knob still pending
    timeout 15 "$SSH" "$NODE" "echo 0 > /sys/module/mxfs/parameters/caw_inject_gep_wrap" >/dev/null 2>&1
    [ "$ok" = 1 ] || { say "wrap($NODE): FAIL — evidence $OUT/wrap*.log"; FAILS=$((FAILS+1)); }
}

wait_ssh_clean() {                  # wait_ssh_clean <node>  (post virsh start)
    local n="$1" t out
    for t in $(seq 1 48); do
        out=$(timeout 6 "$SSH" "$n" 'echo H=$(hostname); lsmod | grep -q "^mxfs " && echo L || echo C' 2>&1)
        echo "$out" | grep -q "H=$n" && echo "$out" | grep -q '^C$' && return 0
        sleep 5
    done
    return 1
}

mode_kill() {
    local obs="$NODE" kv
    [ "$obs" = "$VICTIM" ] && obs=test1 && [ "$VICTIM" = test1 ] && obs=test2

    say "kill: pre-kill selftest on $VICTIM (captures its key)"
    basic_one "$VICTIM" kill-pre 0 || { say "kill: FAIL — victim not healthy pre-kill"; FAILS=$((FAILS+1)); return; }
    kv="$R_INO"

    say "kill: spinning selftest loop on $VICTIM (key $kv), observer marker on $obs"
    timeout 15 "$SSH" "$obs" "echo MXFS_PWTEST_killwin_$STAMP > /dev/kmsg" >/dev/null 2>&1
    timeout 15 "$SSH" "$VICTIM" "nohup sh -c 'D=\$(ls /sys/kernel/debug/mxfs/*/caw_pw_selftest | head -1); while :; do printf 0 > \"\$D\" 2>/dev/null; done' >/dev/null 2>&1 & echo LOOP_UP" | grep -q LOOP_UP \
        || { say "kill: FAIL — could not start victim loop"; FAILS=$((FAILS+1)); return; }
    sleep 2

    say "kill: virsh destroy $VICTIM"
    $VIRSH destroy "$VICTIM" >/dev/null 2>&1
    say "kill: 45s purge window"
    sleep 45

    timeout 20 "$SSH" "$obs" "dmesg | awk -v m=MXFS_PWTEST_killwin_$STAMP 'index(\$0,m){f=1} f'" > "$OUT/killwin-$obs.log" 2>&1
    say "kill: observer window probes: $(grep -oE 'P23[0-9]-[A-Z-]+' "$OUT/killwin-$obs.log" | sort | uniq -c | tr '\n' ' ' || echo none)"

    say "kill: observer selftest on $obs (cluster alive?)"
    basic_one "$obs" kill-obs 0 || { FAILS=$((FAILS+1)); return; }

    say "kill: restarting $VICTIM"
    $VIRSH start "$VICTIM" >/dev/null 2>&1
    wait_ssh_clean "$VICTIM" || { say "kill: FAIL — $VICTIM did not come back"; FAILS=$((FAILS+1)); return; }

    say "kill: rejoining $VICTIM via prep_node.sh"
    # fresh boot has no NFS /src yet and prep_node.sh lives there (run.sh:517 idiom)
    timeout 120 "$SSH" "$VICTIM" "mountpoint -q /src || { mkdir -p /src; timeout 12 mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp; }; MXFS_DEV='$DEV' bash /src/mxfs/tests/setup/prep_node.sh caw" > "$OUT/rejoin.log" 2>&1
    grep -q NODE_PREP_OK "$OUT/rejoin.log" || { say "kill: FAIL — rejoin: $(tail -2 "$OUT/rejoin.log" | tr '\n' ' ')"; FAILS=$((FAILS+1)); return; }

    say "kill: re-running selftest on $VICTIM with the EXPLICIT pre-kill key $kv"
    basic_one "$VICTIM" kill-post "$kv" || { FAILS=$((FAILS+1)); return; }
    say "kill: PASS — death mid-hold, survivors fine, purged key re-grants"
}

say "mode=$MODE node=$NODE victim=$VICTIM out=$OUT build=$(modinfo "$REPO/mxfs.ko" 2>/dev/null | awk '/^srcversion/{print $2}')"
case "$MODE" in
    basic) mode_basic ;;
    wrap)  mode_wrap ;;
    kill)  mode_kill ;;
    all)   mode_basic; mode_wrap; mode_kill ;;
    *) echo "usage: $0 [basic|wrap|kill|all] [node] [victim]"; exit 2 ;;
esac

if [ "$FAILS" -eq 0 ]; then
    say "CAW_PW_SELFTEST $MODE VERDICT: PASS (evidence $OUT)"
    exit 0
fi
say "CAW_PW_SELFTEST $MODE VERDICT: FAIL ($FAILS case(s), evidence $OUT)"
exit 1
