#!/bin/bash
# scst_pr_abort_shutdown_race.sh — D-HOST-SCST-PR-ABORT-SESSION-SHUTDOWN-PANIC-408
# verification: drive SCST's PERSISTENT RESERVE OUT / PREEMPT AND ABORT into the
# registrant-session teardown window that panicked clyde on 2026-08-23, on the
# FIXED target (+caw-abort-reclaim.5), and assert it is handled on both sides of
# the window and the host stays up.
#
# THE DEFECT (scst core, not MXFS): reg->tgt_dev keeps pointing at a session from
# scst_unregister_session() (shut_phase=SHUTDOWN, refcnt killed) until
# scst_free_session() clears it under dev_pr_mutex.  A PREEMPT AND ABORT from
# another initiator naming that registrant's key ran scst_pr_abort_reg() ->
# scst_rx_mgmt_fn_lun() on the dying session: percpu_ref_get on a killed (maybe
# zero) ref, then the READY sBUG in scst_post_rx_mgmt_cmd() -> host panic.  On
# the rig that window opens on EVERY kill-fence whose P&A lands ~60 s after the
# kill (iSCSI nop-in 30 s + response timeout 30 s).
#
# THE FIX (.5): scst_pr_abort_reg pins the session with percpu_ref_tryget
# (fails at zero -> "already released ... skipping"); a core-originated
# PR_ABORT_ALL is exempt from the READY sBUG ("PR ABORT ALL admitted on session
# ... in shut_phase N"); scst_rx_mgmt_fn rolls the PR counters back on a failed
# post.  Test-only module parameter scst.pr_abort_shutdown_delay_ms holds a
# session (a) in SHUTDOWN before the refcount kill and (b) after the refcount
# reached zero before its tgt_devs are freed, so both windows can be hit on
# purpose.
#
# ARMS
#   window  (default) deterministic, knob armed at DELAY ms:
#     A: X registers KX1 on its path-1 session only; X logs path 1 out; at
#        +DELAY/3 the peer Y issues PREEMPT AND ABORT on KX1 -> target must log
#        "PR ABORT ALL admitted on session ... (initiator X) in shut_phase 1".
#     B: X registers KX2 on its path-2 session only; X logs path 2 out; at
#        +DELAY+DELAY/3 (refcount is zero, tgt_devs still linked) Y issues
#        PREEMPT AND ABORT on KX2 -> target must log "PR ABORT: registrant ...
#        session ... is already released ... skipping".
#     Both P&As must return rc=0 at Y, both keys must be gone from PR IN
#     afterwards, and the host kernel log must carry no BUG/Oops/CRITICAL.
#   stress  knob OFF (the natural ~ms window): ITERS x { X registers KX on path
#     1, logs out, Y fires P&A on KX immediately, X logs back in }.  Asserts
#     no BUG/Oops/CRITICAL and every P&A rc=0; reports how many landed in the
#     window (either INFO line) — informational, the natural window is narrow.
#
# PRECONDITIONS: X and Y have NO mxfs mount (their sessions carry no MXFS PR
# key; the test keys are registered with --register-ignore and removed again).
# Other nodes may be mounted: only the test keys are ever preempted.  The knob
# delays EVERY session teardown on the host while armed; it is reset to 0 on
# exit (trap) and scripts/clyde_preflight.sh refuses a rig run while it is set.
#
# budget: every ssh bounded; window arm budget = 2 x (logout + DELAY*2 + login)
# ~ 2 x 12 s at DELAY=4000 plus ~10 ssh round trips -> 60 s; stress arm ~3 s
# per iteration.  the unkillable-wedge rule: no pgrep/ps.  the source-tree rule: lives in tests/.
#
# Usage: tests/scst_pr_abort_shutdown_race.sh <label> [window|stress] [X=test1] [Y=test2] [DELAY_MS=4000] [ITERS=20]
# Env:   SPR_OUT (evidence dir, default tests/evidence/<label>_spr), MXFS_SCST_TGT
set -u
LABEL=${1:?label}; ARM=${2:-window}; X=${3:-test1}; Y=${4:-test2}; DELAY=${5:-4000}; ITERS=${6:-20}
case $ARM in window|stress) ;; *) echo "arm must be window or stress"; exit 2;; esac
[ "$X" = "$Y" ] && { echo "X and Y must differ"; exit 2; }
cd "$(dirname "$0")/.." || exit 2
OUT=${SPR_OUT:-tests/evidence/${LABEL}_spr}; mkdir -p "$OUT"
SSH=tools/mxfs_sshpass.sh
TGT=${MXFS_SCST_TGT:-iqn.2026-05.local.mxfs:shared}
KNOB=/sys/module/scst/parameters/pr_abort_shutdown_delay_ms
SUDO=""; [ "$(id -u)" -eq 0 ] || SUDO="sudo -n"
KX1=0xabcd40801; KX2=0xabcd40802; KY=0xabcd40809
t0=$(date +%s)
flt() { grep -av '^Unauthorized\|^Warning:\|^If you'; }
rsh() { local h=$1; shift; timeout 25 $SSH "$h" "$*" 2>/dev/null | flt; }
echo "=== scst_pr_abort_shutdown_race label=$LABEL arm=$ARM X=$X Y=$Y delay=${DELAY}ms iters=$ITERS out=$OUT $(date -u +%FT%TZ) ==="

# --- host preconditions ------------------------------------------------------
sver=$(modinfo scst 2>/dev/null | awk '/^version:/{print $2}')
lver=$(cat /sys/module/scst/version 2>/dev/null)
minor=$(printf '%s' "$lver" | sed -n 's/.*+caw-abort-reclaim\.\([0-9]\+\)$/\1/p')
echo "scst: installed=$sver loaded=$lver"
[ -n "$minor" ] && [ "$minor" -ge 5 ] || { echo "FAIL: loaded scst '$lver' predates +caw-abort-reclaim.5 — NEVER run this against the unfixed target (it panics the host)"; exit 3; }
[ -f "$KNOB" ] || { echo "FAIL: $KNOB missing — loaded scst lacks the test knob"; exit 3; }
knob0=$(cat "$KNOB"); [ "$knob0" = 0 ] || echo "WARN: knob already armed ($knob0) at start"
setknob() { echo "$1" | $SUDO tee "$KNOB" >/dev/null; echo "knob=$(cat "$KNOB")"; }
trap 'setknob 0 >/dev/null 2>&1' EXIT

# --- node preconditions: no mxfs mount on X/Y; learn their per-portal disks ----
for n in $X $Y; do
    m=$(rsh $n "grep -c ' mxfs ' /proc/mounts" | tail -1 | tr -dc 0-9)
    [ "${m:-1}" = 0 ] || { echo "FAIL: $n has an mxfs mount (count=$m) — unmount it first; the test keys would collide with its PR registration"; exit 3; }
done
# portal -> sd device map from the initiator's own view (iscsiadm -P3)
learn_paths() {   # prints "portal_ip disk" lines for this target
    rsh "$1" "iscsiadm -m session -P3 2>/dev/null | awk '/^Target: /{t=\$2} /Current Portal:/{p=\$3; sub(/:3260.*/,\"\",p)} /Attached scsi disk/{ if (t ~ /$TGT/) print p, \$4 }'"
}
XP=$(learn_paths $X); YP=$(learn_paths $Y)
XP1_IP=$(printf '%s\n' "$XP" | sed -n 1p | awk '{print $1}'); XP1_DEV=$(printf '%s\n' "$XP" | sed -n 1p | awk '{print $2}')
XP2_IP=$(printf '%s\n' "$XP" | sed -n 2p | awk '{print $1}'); XP2_DEV=$(printf '%s\n' "$XP" | sed -n 2p | awk '{print $2}')
YP1_IP=$(printf '%s\n' "$YP" | sed -n 1p | awk '{print $1}'); YP1_DEV=$(printf '%s\n' "$YP" | sed -n 1p | awk '{print $2}')
echo "paths: X path1=$XP1_IP:/dev/$XP1_DEV path2=$XP2_IP:/dev/$XP2_DEV  Y path1=$YP1_IP:/dev/$YP1_DEV"
[ -n "$XP1_DEV" ] && [ -n "$XP2_DEV" ] && [ -n "$YP1_DEV" ] || { echo "FAIL: could not learn 2 iSCSI paths on $X and 1 on $Y (X='$XP' Y='$YP')"; exit 3; }
XIQN=$(rsh $X "cat /etc/iscsi/initiatorname.iscsi | sed -n 's/^InitiatorName=//p'" | tail -1)
echo "X iqn: $XIQN"

# Y's own registration (needed to issue PR OUT); --register-ignore overwrites any stale test key
yr=$(rsh $Y "sg_persist --out --register-ignore --param-sark=$KY /dev/$YP1_DEV 2>&1 | grep -v 'Peripheral device type\|SCST_FIO'; echo rc=\${PIPESTATUS[0]}" | tr '\n' ' ')
echo "Y register $KY on /dev/$YP1_DEV: $yr"
case "$yr" in *rc=0*) ;; *) echo "FAIL: Y could not register its key"; exit 3;; esac
pa() {   # PREEMPT AND ABORT key $1 from Y; echoes "rc=N <text>"
    # --prout-type is mandatory for PREEMPT (type 5 = WE-RO, what MXFS fences with);
    # without it SCST answers ILLEGAL REQUEST before the PR path is even reached.
    rsh $Y "sg_persist --out --preempt-abort --prout-type=5 --param-rk=$KY --param-sark=$1 /dev/$YP1_DEV 2>&1 | grep -v 'Peripheral device type\|SCST_FIO'; echo rc=\${PIPESTATUS[0]}" | tr '\n' ' '
}
keycount() { rsh $Y "sg_persist --in --read-keys /dev/$YP1_DEV 2>&1 | grep -ci '${1#0x}\$'" | tail -1 | tr -dc 0-9; }
logout_path() { rsh $1 "iscsiadm -m node -T $TGT -p $2:3260 -u 2>&1 | tail -1; echo rc=\$?" | tr '\n' ' '; }
login_path()  { rsh $1 "iscsiadm -m node -T $TGT -p $2:3260 -l 2>&1 | tail -1; echo rc=\$?" | tr '\n' ' '; }
hostlog() { journalctl -k --since "$1" --until "$2" 2>/dev/null; }

fail=0
if [ "$ARM" = window ]; then
    # register the two test keys, one per X session
    r1=$(rsh $X "sg_persist --out --register-ignore --param-sark=$KX1 /dev/$XP1_DEV 2>&1 | grep -v 'Peripheral device type\|SCST_FIO'; echo rc=\${PIPESTATUS[0]}" | tr '\n' ' ')
    r2=$(rsh $X "sg_persist --out --register-ignore --param-sark=$KX2 /dev/$XP2_DEV 2>&1 | grep -v 'Peripheral device type\|SCST_FIO'; echo rc=\${PIPESTATUS[0]}" | tr '\n' ' ')
    echo "X register $KX1 on path1: $r1 | $KX2 on path2: $r2"
    echo "pr-in before: KX1=$(keycount $KX1) KX2=$(keycount $KX2) KY=$(keycount $KY)"
    setknob "$DELAY"
    third=$(( DELAY / 3000 )); [ $third -ge 1 ] || third=1
    # --- window A: SHUTDOWN with the initial ref still held -------------------
    TA=$(date -u +%FT%T.%3NZ); ta=$(date +%s)
    lo=$(logout_path $X $XP1_IP); echo "A: X logout path1 at $TA: $lo"
    sleep $third
    paA=$(pa $KX1); echo "A: P&A $KX1 from Y at +$(( $(date +%s) - ta ))s: $paA"
    # wait out the rest of both holds so session 1 is fully freed before B
    sleep $(( (2 * DELAY) / 1000 + 1 ))
    # --- window B: refcount zero, tgt_devs still linked ------------------------
    TB=$(date -u +%FT%T.%3NZ); tb=$(date +%s)
    lo=$(logout_path $X $XP2_IP); echo "B: X logout path2 at $TB: $lo"
    sleep $(( DELAY / 1000 + third ))
    paB=$(pa $KX2); echo "B: P&A $KX2 from Y at +$(( $(date +%s) - tb ))s: $paB"
    sleep $(( DELAY / 1000 + 1 ))
    setknob 0
    TE=$(date -u +%FT%T.%3NZ)
    hostlog "$TA" "$TE" > "$OUT/host_kmsg.txt"
    echo "pr-in after: KX1=$(keycount $KX1) KX2=$(keycount $KX2) KY=$(keycount $KY)"
    li1=$(login_path $X $XP1_IP); li2=$(login_path $X $XP2_IP); echo "X re-login: path1 $li1 | path2 $li2"
    adm=$(grep -ac "PR ABORT ALL admitted on session .*${X}-mxfs-node" "$OUT/host_kmsg.txt")
    rel=$(grep -ac "PR ABORT: registrant .* is already released" "$OUT/host_kmsg.txt")
    holdA=$(grep -ac "holding session .*${X}-mxfs-node.* in SHUTDOWN" "$OUT/host_kmsg.txt")
    holdB=$(grep -ac "holding released session .*${X}-mxfs-node" "$OUT/host_kmsg.txt")
    bad=$(grep -ac 'BUG:\|Oops\|CRITICAL ERROR\|New mgmt cmd while shutting down\|SCST_PR_ABORT_ALL failed' "$OUT/host_kmsg.txt")
    echo "host: admitted_during_shutdown=$adm released_skip=$rel holdA=$holdA holdB=$holdB bad=$bad  (host_kmsg.txt $(wc -l < "$OUT/host_kmsg.txt") lines)"
    grep -a 'PR ABORT\|holding' "$OUT/host_kmsg.txt" | cut -c1-220 | sed 's/^/  /'
    case "$paA" in *rc=0*) ;; *) echo "FAIL: window-A P&A did not return rc=0: $paA"; fail=1;; esac
    case "$paB" in *rc=0*) ;; *) echo "FAIL: window-B P&A did not return rc=0: $paB"; fail=1;; esac
    [ "$adm" -ge 1 ] || { echo "FAIL: window A not exercised — no 'PR ABORT ALL admitted on session' line for $X (holdA=$holdA)"; fail=1; }
    [ "$rel" -ge 1 ] || { echo "FAIL: window B not exercised — no 'already released ... skipping' line for $X (holdB=$holdB)"; fail=1; }
    [ "$(keycount $KX1)" = 0 ] && [ "$(keycount $KX2)" = 0 ] || { echo "FAIL: a test key survived its PREEMPT AND ABORT"; fail=1; }
    [ "$bad" = 0 ] || { echo "FAIL: BUG/Oops/CRITICAL/unexpected error on the host during the window"; fail=1; }
else
    TA=$(date -u +%FT%T.%3NZ)
    echo "pr-in before: KX1=$(keycount $KX1) KY=$(keycount $KY)"
    ok=0; inwin=0
    for i in $(seq 1 $ITERS); do
        rsh $X "sg_persist --out --register-ignore --param-sark=$KX1 /dev/$XP1_DEV >/dev/null 2>&1; iscsiadm -m node -T $TGT -p $XP1_IP:3260 -u >/dev/null 2>&1 &" >/dev/null
        r=$(pa $KX1)
        case "$r" in *rc=0*) ok=$((ok+1));; *) echo "iter $i: P&A $r";; esac
        rsh $X "iscsiadm -m node -T $TGT -p $XP1_IP:3260 -l >/dev/null 2>&1; echo" >/dev/null
        XP1_DEV=$(learn_paths $X | awk -v ip="$XP1_IP" '$1==ip{print $2}' | head -1)
        [ -n "$XP1_DEV" ] || { echo "iter $i: path1 did not come back on $X"; break; }
    done
    sleep 2
    TE=$(date -u +%FT%T.%3NZ)
    hostlog "$TA" "$TE" > "$OUT/host_kmsg.txt"
    inwin=$(grep -ac "PR ABORT ALL admitted on session\|PR ABORT: registrant .* is already released" "$OUT/host_kmsg.txt")
    bad=$(grep -ac 'BUG:\|Oops\|CRITICAL ERROR\|New mgmt cmd while shutting down\|SCST_PR_ABORT_ALL failed' "$OUT/host_kmsg.txt")
    echo "stress: iters=$ITERS pa_ok=$ok in_window_lines=$inwin bad=$bad"
    [ "$ok" = "$ITERS" ] || { echo "FAIL: only $ok/$ITERS P&As returned rc=0"; fail=1; }
    [ "$bad" = 0 ] || { echo "FAIL: BUG/Oops/CRITICAL/unexpected error on the host"; fail=1; }
fi

# cleanup: drop Y's test key; X keys are gone by preemption (or dropped here).
# SCST re-links a surviving registrant to a re-logged-in session by TransportID,
# and the sd names may have moved after the re-login — re-learn them first.
XP=$(learn_paths $X)
XP1_DEV=$(printf '%s\n' "$XP" | awk -v ip="$XP1_IP" '$1==ip{print $2}' | head -1)
XP2_DEV=$(printf '%s\n' "$XP" | awk -v ip="$XP2_IP" '$1==ip{print $2}' | head -1)
rsh $X "sg_persist --out --register --param-rk=$KX1 --param-sark=0 /dev/${XP1_DEV:-null} >/dev/null 2>&1; sg_persist --out --register --param-rk=$KX2 --param-sark=0 /dev/${XP2_DEV:-null} >/dev/null 2>&1; echo" >/dev/null
rsh $Y "sg_persist --out --register --param-rk=$KY --param-sark=0 /dev/$YP1_DEV >/dev/null 2>&1; echo" >/dev/null
echo "cleanup: KX1=$(keycount $KX1) KX2=$(keycount $KX2) KY=$(keycount $KY) knob=$(cat "$KNOB")"
if [ $fail = 0 ]; then echo "VERDICT PASS"; else echo "VERDICT FAIL"; fi
echo "=== done label=$LABEL total=$(( $(date +%s) - t0 ))s out=$OUT ==="
exit $fail
