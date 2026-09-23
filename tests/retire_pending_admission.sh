#!/bin/bash
# retire_pending_admission.sh — verification of the RETIRE_PENDING two-phase
# departure's settlement (D-PR-RETIREMENT-FAILURE-NOT-FAIL-CLOSED-377 /
# D-CLEAN-RELEASE-THEN-UNREGISTER-FAIL-LEAVES-UNFENCEABLE-STALE-REGISTRANT-0356).
#
# 0.59.1 (sess451) arms — the sess450 design-consult STOP-SHIP fixes:
#
#   sameboot  (merge criterion 4 — the P305 lone-node remount regression)
#     VICTIM departs with the unregister failure AND the skipped re-stamp
#     (dbg_pr_unregister_fail=1 + dbg_retire_skip_restamp=1: the record stays
#     RETIRE_PENDING, the key stays registered), then remounts INSIDE the
#     30 s retirement grace.  Expected: P305-PR-SAME-BOOT-RETIRE-PENDING +
#     P305-RETIRE-SETTLED(-OWN) on the victim, mount rc=0, the victim can
#     write, no peer expired/fenced that key (P304-RETIRE-EXPIRED-WITHDRAWN=0,
#     P236-FENCE-CERTIFIED=0, P-PRKEY-FENCED=0 fleet-wide), the key table is
#     unchanged (the remount re-registered the same derived key).
#
#   joiner    (merge criterion 3 — RETIRE_PENDING in the admission barrier)
#     JOINER leaves cleanly first (its own record must settle EMPTY so it
#     cannot confound), VICTIM departs as above, and JOINER mounts inside the
#     grace.  THE INVARIANT: mount(2) must not return on the joiner while the
#     victim's key is still registered — the barrier settles the record
#     immediately (P304-RETIRE-EXPIRED-WITHDRAWN ... immediate=1 on the
#     joiner), somebody fences the key (P236-FENCE-CERTIFIED), and only then
#     is the joiner admitted.
#
# 0.59.2 (sess452) arms — the sess451 design-consult STOP-SHIP #2 required tests
# (deterministic UNKNOWN, slow PR off the heartbeat, joiner under UNKNOWN,
# same-boot remount vs peer expiry in both orderings, generation movement
# inside a bracket, multiple same-boot records).  Knobs: dbg_pr_read_keys_fail,
# dbg_pr_read_resv_fail, dbg_pr_read_keys_trunc, dbg_pr_read_keys_delay_ms,
# dbg_pr_bracket_fail (pal/linux/kern.c).  Every arm disarms every knob on
# every node before it exits (trap), so a failed arm cannot poison the next.
#
#   unknown / unknownresv
#     Every PEER's READ KEYS (resp. READ RESERVATION) fails.  VICTIM departs
#     with the crash model (record RETIRE_PENDING, key registered).  Expected
#     for >= 40 s: P304-RETIRE-PENDING-SEEN ... state=UNKNOWN, then
#     P304-RETIRE-UNKNOWN-STALLED after the grace, NO EMPTY (COMPLETED-BY-PEER
#     =0), NO WITHDRAWN (EXPIRED=0), no fence, the key still registered.  Then
#     the knob is cleared: the record (already past its grace) goes PRESENT →
#     WITHDRAWN at once, the key is fenced and gone.  UNKNOWN never settles.
#
#   trunc
#     One-shot: odd peers report their next READ KEYS view truncated
#     (P-PR-VIEW-TRUNC), even peers fail their next READ RESERVATION.  VICTIM
#     departs CLEANLY (key unregistered).  Expected: the injected bracket on
#     each armed peer answers UNKNOWN (no EMPTY from it — TRUNC/RESV-FAIL line
#     precedes any COMPLETED line on that node), the next bracket proves
#     ABSENT and exactly one peer publishes EMPTY (COMPLETED-BY-PEER == 1).
#
#   slowpr
#     Every PEER's READ KEYS sleeps 10 s (a bracket takes >= 20 s).  VICTIM
#     departs cleanly.  Expected: the retirement still completes (one peer's
#     bracket proves ABSENT) and NO heartbeat-side symptom appears fleet-wide
#     (P-HBFALSE, P-HB-SLOW, P-HB-MONSLOW, HB-STALL all 0; no fence): the PR
#     INs run on the probe thread, never on the heartbeat.
#
#   joinerunk
#     JOINER leaves cleanly; every node's key-state BRACKET is failed
#     (dbg_pr_bracket_fail) so nobody can classify; VICTIM departs with the
#     crash model; JOINER mounts.  Expected: the barrier holds
#     (P-ADMIT-RETIRE-PENDING-HELD) and the mount is ABORTED at its 30 s bound
#     (rc != 0, "MXFS mount ABORTED"), with the victim's key still registered
#     and no EMPTY published anywhere.  Then all knobs cleared: peers expire
#     the record, fence the key; the joiner remounts fine.
#
#   race
#     Two orderings of the same-boot remount against the peers' expiry.
#     A: VICTIM departs (crash model) and remounts at once (inside the
#        grace) — P305 must settle its own record (SETTLED-OWN) and no peer
#        may expire/fence it.
#     B: VICTIM departs and remounts at T+29 s, straddling the 30 s grace —
#        EITHER P305 settles it first (then no expiry, no fence), OR a peer
#        expires it first (then P305 sees the record changed, the remount is
#        refused as a same-boot dirty predecessor while the key is still on
#        the nexus, the peers fence the key and recover; the victim's later
#        remount succeeds).  NEVER both a SETTLED-OWN and an EXPIRED for the
#        same record, never an EMPTY published while the key was registered,
#        never a shutdown.
#
#   genmove
#     Every PEER's READ KEYS sleeps 1.5 s (a bracket spans >= 3 s while the
#     record is pending), VICTIM departs (crash model) and remounts at once:
#     its REGISTER PROUTs land inside peers' brackets.  Expected: >= 1
#     P-PR-BRACKET-INCOHERENT fleet-wide (generation moved → no proof), the
#     same-boot remount still succeeds and no peer published EMPTY / expired /
#     fenced the key.
#
#   multipending
#     Two consecutive same-boot cycles (depart crash-model → remount) —
#     each remount must enumerate and settle exactly its predecessor's
#     record (SETTLED-OWN == 1 per cycle, P305-RETIRE-MULTI never fires).
#     NOTE: two SIMULTANEOUS same-boot pending records are unreachable by
#     protocol (P305 settles every same-boot record before the claim), so
#     the enumeration is exercised by sequential cycles.
#
# Every arm ends with the victim remounted via prep_node (knobs off) and the
# key table restored, so the fleet is left as found.
#
# Usage: tests/retire_pending_admission.sh <N> <victim> <joiner> [probe] [arm]
#   victim != joiner != probe; probe default test1
# derived time budgets (native umount/mount are seconds):
#   sameboot   200 s   joiner 270 s      unknown/unknownresv 170 s
#   trunc      120 s   slowpr 130 s      joinerunk 280 s
#   race       300 s   genmove 200 s     multipending 170 s
# Exit 0 PASS, 1 FAIL, 2 INFRA-FAIL.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
N="${1:?usage: retire_pending_admission.sh <N> <victim> <joiner> [probe] [arm]}"
VICTIM="${2:?usage}"
JOINER="${3:?usage}"
PROBE="${4:-test1}"
ARM="${5:-sameboot}"
MNT=/mnt/shared
PARAMS=/sys/module/mxfs/parameters
KNOB=$PARAMS/dbg_pr_unregister_fail
KNOB2=$PARAMS/dbg_retire_skip_restamp
CHK=/src/mxfs/tools/chk_mxfs
GRACE_S=30
ALL_KNOBS="dbg_pr_unregister_fail dbg_retire_skip_restamp dbg_pr_read_keys_fail dbg_pr_read_resv_fail dbg_pr_read_keys_trunc dbg_pr_read_keys_delay_ms dbg_pr_bracket_fail"
case "$ARM" in
    sameboot|joiner|unknown|unknownresv|trunc|slowpr|joinerunk|race|genmove|multipending) ;;
    *) echo "FAIL: arm $ARM"; exit 1;;
esac
for a in "$VICTIM:$JOINER" "$VICTIM:$PROBE" "$JOINER:$PROBE"; do
    [ "${a%%:*}" = "${a##*:}" ] && { echo "FAIL: victim/joiner/probe must be distinct ($a)"; exit 1; }
done
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT="$REPO/tests/evidence/${STAMP}_retire_adm_$ARM"
mkdir -p "$OUT"
FAILS=0
say() { echo "[retire_adm/$ARM] $*"; }
fail() { say "FAIL: $*"; FAILS=$((FAILS+1)); }

DEV=$("$SSH" "$VICTIM" "mount -t mxfs | awk '{print \$1; exit}'" 2>/dev/null | tr -d ' \r\n')
[ -n "$DEV" ] || { say "INFRA-FAIL: $VICTIM has no mxfs mount"; exit 2; }
"$SSH" "$JOINER" "mount -t mxfs | grep -q mxfs" 2>/dev/null || { say "INFRA-FAIL: $JOINER has no mxfs mount"; exit 2; }
keys() { timeout 40 "$SSH" "$PROBE" "$CHK --pr-keys $DEV" 2>/dev/null | grep -oE '^  0x[0-9a-f]+' | tr -d ' ' | sort -u; }
# sess455: the kernel prints keys with 0x%llx (no zero padding: 0x7fca569fb753541)
# while chk_mxfs --pr-keys prints 16 padded digits (0x07fca569fb753541); every
# exact-match compare against keys() must go through this, or a key whose top
# nibble is 0 (1 in 16) reads as ABSENT (chain 77 unknownresv false FAIL).
normkey() { [ -n "${1:-}" ] && printf '0x%016x' "$1" 2>/dev/null; }
fleet_clear() { local i; for i in $(seq 1 "$N"); do "$SSH" "test$i" "dmesg --clear" >/dev/null 2>&1 & done; wait; }
# per-node counters of the markers this harness reasons about, one ssh each
# (the unkillable-wedge rule: bounded, parallel, per-node files)
MARKS='P304-RETIRE-EXPIRED-WITHDRAWN|P236-FENCE-CERTIFIED|P-PRKEY-FENCED|P304-RETIRE-COMPLETED-BY-PEER|P304-RETIRE-PENDING-SEEN|P163-CLEAN-DEPART|P-ADMIT-RETIRE-PENDING-HELD|P304-RETIRE-UNKNOWN-STALLED|P304-RETIRE-KEY-CONFLICT|P305-RETIRE-SETTLED-OWN|P305-RETIRE-MULTI|P305-RETIRE-OWN-CHANGED|P305-RETIRE-OWN-UNPROVEN|P305-PR-SAME-BOOT-DIRTY-PREDECESSOR|P-PR-VIEW-TRUNC|P-DBG-PR-READ-KEYS-TRUNC|P-DBG-PR-READ-RESV-FAIL|P-DBG-PR-READ-KEYS-FAIL|P-DBG-PR-BRACKET-FAIL|P-PR-BRACKET-INCOHERENT|P-PR-BRACKET-DISCARDED|P-PR-ABSENCE-UNPROVABLE|P-HBFALSE|P-HB-SLOW|P-HB-MONSLOW|HB-STALL|MXFS mount ABORTED|P304-RETIRE-QUIESCED|P304-RETIRE-NOT-QUIESCED|P304-RETIRE-IO-AFTER-FREEZE|P163-RECOVERY-COMPLETE|P163-RECOVERED|P163-FENCED-SEEN|P300-CLAIM-EXHAUSTED|P304-RETIRE-WORKER|P-PR-SETTLE-ABSENT|P-PR-SETTLE-UNHELD|P-PR-PROOF-REFUSED|P304-CAS-NOCAW|Filesystem has been shut down|forced shutdown|kernel BUG|BUG:|Oops|general protection'
sweep() { # <tag>: writes $OUT/<tag>_testN.txt with "MARK=count" lines and the raw dmesg
    local tag="$1" i
    for i in $(seq 1 "$N"); do
        ( timeout 25 "$SSH" "test$i" "D=\$(dmesg); for m in $(echo "$MARKS" | tr '|' '\n' | sed "s/.*/'&'/" | tr '\n' ' '); do echo \"\$m=\$(printf '%s\n' \"\$D\" | grep -ac \"\$m\")\"; done; echo ---; printf '%s\n' \"\$D\"" > "$OUT/${tag}_test$i.txt" 2>/dev/null ) &
    done; wait
}
count() { # <tag> <mark> [exclude-node] → fleet sum
    local tag="$1" m="$2" ex="${3:-}" i s=0 c
    for i in $(seq 1 "$N"); do
        [ "test$i" = "$ex" ] && continue
        c=$(grep -a -m1 "^$m=" "$OUT/${tag}_test$i.txt" 2>/dev/null | sed 's/.*=//' | tr -dc '0-9')
        s=$((s + ${c:-0}))
    done; echo "$s"
}
node_count() { # <tag> <node> <mark>
    grep -a -m1 "^$3=" "$OUT/${1}_$2.txt" 2>/dev/null | sed 's/.*=//' | tr -dc '0-9'
}
write_ok() { timeout 30 "$SSH" "$1" "echo ok > $MNT/.retire_adm_$1 && sync -f $MNT && rm -f $MNT/.retire_adm_$1 && echo WRITE_OK" 2>/dev/null | grep -c WRITE_OK; }

# set one knob on a set of nodes, parallel, per-node rc (the request-batching rule)
set_knob() { # <knob> <value> <node...>
    local k="$1" v="$2" n d; shift 2
    d=$(mktemp -d)
    for n in "$@"; do
        ( timeout 15 "$SSH" "$n" "echo $v > $PARAMS/$k && cat $PARAMS/$k" > "$d/$n.out" 2>&1; echo $? > "$d/$n.rc" ) &
    done; wait
    for n in "$@"; do
        [ "$(cat "$d/$n.rc")" = 0 ] && [ "$(tail -1 "$d/$n.out" | tr -d '[:space:]')" = "$v" ] || { say "INFRA-FAIL: $k=$v not set on $n ($(tail -1 "$d/$n.out"))"; exit 2; }
    done
}
peers() { local i; for i in $(seq 1 "$N"); do [ "test$i" = "$VICTIM" ] || echo "test$i"; done; }
disarm_all() {
    local i k d; d=$(mktemp -d)
    for i in $(seq 1 "$N"); do
        ( for k in $ALL_KNOBS; do timeout 15 "$SSH" "test$i" "echo 0 > $PARAMS/$k" >/dev/null 2>&1; done ) &
    done; wait
}
trap disarm_all EXIT

echo "=== retire_pending_admission arm=$ARM N=$N victim=$VICTIM joiner=$JOINER probe=$PROBE dev=$DEV @ $STAMP ==="
keys > "$OUT/keys_before.txt"; say "keys before: $(wc -l < "$OUT/keys_before.txt")"

# ── the departure under the crash model: RETIRE_PENDING stays, key stays ──
depart_victim() {
    local v
    v=$("$SSH" "$VICTIM" "echo 1 > $KNOB && cat $KNOB" 2>/dev/null | tail -1 | tr -d '[:space:]')
    [ "$v" = 1 ] || { say "INFRA-FAIL: dbg_pr_unregister_fail not armed on $VICTIM"; exit 2; }
    v=$("$SSH" "$VICTIM" "echo 1 > $KNOB2 && cat $KNOB2" 2>/dev/null | tail -1 | tr -d '[:space:]')
    [ "$v" = 1 ] || { say "INFRA-FAIL: dbg_retire_skip_restamp not armed on $VICTIM"; exit 2; }
    T_DEPART=$(date +%s)
    "$SSH" "$VICTIM" "timeout 60 umount $MNT; echo UMOUNT_RC=\$?; sleep 1; dmesg" > "$OUT/victim_umount${1:-}.log" 2>&1
    say "victim umount wall $(( $(date +%s) - T_DEPART )) s rc=$(sed -n 's/^UMOUNT_RC=//p' "$OUT/victim_umount${1:-}.log")"
    KEY=$(normkey "$(grep -o 'P301-DEPARTURE-INCOMPLETE PR key 0x[0-9a-f]*' "$OUT/victim_umount${1:-}.log" | head -1 | grep -o '0x[0-9a-f]*')")
    local rel skip p303 q
    rel=$(grep -c 'P304-RETIRE-PENDING-RELEASED' "$OUT/victim_umount${1:-}.log")
    skip=$(grep -c 'P-DBG-RETIRE-SKIP-RESTAMP' "$OUT/victim_umount${1:-}.log")
    p303=$(grep -c 'P303-RETIRE-PENDING-RESTAMPED.*rc=0' "$OUT/victim_umount${1:-}.log")
    q=$(grep -c 'P304-RETIRE-QUIESCED' "$OUT/victim_umount${1:-}.log")
    say "victim: RELEASED=$rel skip=$skip P303=$p303 QUIESCED=$q key=${KEY:-?}"
    [ "$rel" -ge 1 ] || fail "release did not stamp RETIRE_PENDING"
    [ "$q" -ge 1 ] || fail "no P304-RETIRE-QUIESCED before the release stamp (0.59.2)"
    [ "$(grep -c 'P304-RETIRE-NOT-QUIESCED\|P304-RETIRE-IO-AFTER-FREEZE' "$OUT/victim_umount${1:-}.log")" -eq 0 ] || fail "departure reported NOT quiesced / I/O after freeze"
    [ "$skip" -ge 1 ] || fail "crash knob did not fire (vacuous)"
    [ "$p303" -eq 0 ] || fail "the re-stamp ran despite the crash model"
    [ -n "$KEY" ] || fail "no P301 key on the victim"
    if [ -n "$KEY" ] && ! keys | grep -qx "$KEY"; then fail "key $KEY absent right after the departure — the knob did not keep it registered"; fi
}

# ── a CLEAN departure (knobs off): the key is unregistered ──
depart_victim_clean() {
    T_DEPART=$(date +%s)
    "$SSH" "$VICTIM" "echo 0 > $KNOB; echo 0 > $KNOB2; timeout 60 umount $MNT; echo UMOUNT_RC=\$?; sleep 1; dmesg" > "$OUT/victim_umount_clean.log" 2>&1
    say "victim clean umount wall $(( $(date +%s) - T_DEPART )) s rc=$(sed -n 's/^UMOUNT_RC=//p' "$OUT/victim_umount_clean.log")"
    grep -q 'UMOUNT_RC=0' "$OUT/victim_umount_clean.log" || fail "clean umount rc != 0"
    [ "$(grep -c 'P301\|P303' "$OUT/victim_umount_clean.log")" -eq 0 ] || fail "clean umount printed P301/P303"
    [ "$(grep -c 'P304-RETIRE-QUIESCED' "$OUT/victim_umount_clean.log")" -ge 1 ] || fail "no P304-RETIRE-QUIESCED on the clean departure"
    KEY=$(normkey "$(grep -o 'P302-PR-KEY-RETAINED[^ ]* key 0x[0-9a-f]*\|unregistered key 0x[0-9a-f]*' "$OUT/victim_umount_clean.log" | head -1 | grep -o '0x[0-9a-f]*')")
}

# ── the ordinary remount at the end, so the fleet is left as found ──
restore_victim() {
    disarm_all
    # sess453 (D-0519; D-376's transient form): after a fence the victim's old
    # slot stays under the recovery lease until the elected replayer prints
    # P163-RECOVERY-COMPLETE; with 31 live members on a 32-slice volume the
    # remount has no slot until then (P300-CLAIM-EXHAUSTED -> mount(2)
    # ENOTCONN, chain 72 unknown/unknownresv).  Wait for it, bounded, and
    # print the fence->complete latency: 93 s on 0.59.3 (the 31-sample stale
    # window on every non-prover peer), expected seconds once D-0519 lands.
    sweep pre_restore
    if [ "$(count pre_restore P236-FENCE-CERTIFIED)" -ge 1 ]; then
        local T_R0 rdone
        T_R0=$(date +%s)
        rdone=$(wait_count recov P163-RECOVERY-COMPLETE 1 150 "$VICTIM")
        say "restore: a fence was certified this arm; P163-RECOVERY-COMPLETE=$rdone after $(( $(date +%s) - T_R0 )) s more (fence->complete latency, D-0519)"
        [ "$rdone" -ge 1 ] || fail "the fenced slot's recovery did not complete within 150 s of the restore"
    fi
    # sess452 chain 71: prep_node.sh defaults MXFS_DEV to /dev/sda, which the
    # multipath map claims on this rig ("already mounted or mount point busy")
    # — pass the device the victim was actually mounted on.
    "$SSH" "$VICTIM" "mount -t mxfs | grep -q mxfs && timeout 60 umount $MNT; dmesg --clear; MXFS_DEV=$DEV timeout 120 /src/mxfs/tests/setup/prep_node.sh caw; echo PREP_RC=\$?; dmesg | grep -c 'P305-PR-PREDECESSOR-KEY-PRESENT\|P305-PR-SAME-BOOT-DIRTY-PREDECESSOR\|P305-RETIRE-UNSETTLED\|P305-RETIRE-KEY-FOREIGN\|P305-RETIRE-OWN-UNPROVEN\|P305-RETIRE-KEY0'" > "$OUT/victim_restore.log" 2>&1
    grep -q NODE_PREP_OK "$OUT/victim_restore.log" || fail "victim did not remount at the end (prep_node)"
    [ "$(tail -1 "$OUT/victim_restore.log")" = 0 ] || fail "victim's final remount hit a P305 refusal"
}

# wait until a fleet marker count (excluding a node) reaches >= want, bounded
wait_count() { # <tag> <mark> <want> <bound_s> [exclude]
    local tag="$1" m="$2" want="$3" b="$4" ex="${5:-}" c=0 end=$((SECONDS + $4))
    while [ $SECONDS -lt $end ]; do sweep "$tag"; c=$(count "$tag" "$m" "$ex"); [ "$c" -ge "$want" ] && break; sleep 5; done
    echo "$c"
}

# same-boot remount of the victim: prints the classification into $OUT/<tag>.log
remount_victim() { # <tag> → sets R_RC R_FOUND R_SETTLED R_OWN R_UNS R_DIRTY R_WALL R_SINCE
    local tag="$1" T1
    T1=$(date +%s)
    "$SSH" "$VICTIM" "dmesg --clear; blockdev --flushbufs $DEV; timeout 120 mount -t mxfs $DEV $MNT; echo MOUNT_RC=\$?; dmesg" > "$OUT/$tag.log" 2>&1
    R_WALL=$(( $(date +%s) - T1 )); R_SINCE=$(( $(date +%s) - T_DEPART ))
    R_RC=$(sed -n 's/^MOUNT_RC=//p' "$OUT/$tag.log")
    R_FOUND=$(grep -c 'P305-PR-SAME-BOOT-RETIRE-PENDING' "$OUT/$tag.log")
    R_SETTLED=$(grep -c 'P305-RETIRE-SETTLED' "$OUT/$tag.log")
    R_OWN=$(grep -c 'P305-RETIRE-SETTLED-OWN' "$OUT/$tag.log")
    R_UNS=$(grep -c 'P305-RETIRE-UNSETTLED\|P305-RETIRE-KEY-FOREIGN-PRESENT\|P305-RETIRE-OWN-UNPROVEN' "$OUT/$tag.log")
    R_DIRTY=$(grep -c 'P305-PR-SAME-BOOT-DIRTY-PREDECESSOR\|P305-PR-PREDECESSOR-KEY-PRESENT' "$OUT/$tag.log")
    R_CHANGED=$(grep -c 'P305-RETIRE-OWN-CHANGED' "$OUT/$tag.log")
    say "$tag: rc=${R_RC:-?} wall=${R_WALL}s since_depart=${R_SINCE}s SAME-BOOT-RETIRE-PENDING=$R_FOUND SETTLED=$R_SETTLED SETTLED-OWN=$R_OWN unsettled/foreign=$R_UNS dirty/refused=$R_DIRTY changed=$R_CHANGED"
}

sameboot_asserts() { # after remount_victim: the 0.59.1/0.59.2 same-boot invariants
    [ "${R_RC:-1}" = 0 ] || fail "same-boot remount failed rc=${R_RC:-?}"
    [ "$R_FOUND" -ge 1 ] || fail "P305 scan did not report this boot's RETIRE_PENDING record"
    [ "$R_OWN" -ge 1 ] || fail "no P305-RETIRE-SETTLED-OWN (0.59.2: the own-key record must be settled by the P305-only path with a fresh proof)"
    [ "$R_UNS" -eq 0 ] || fail "settlement refused (unsettled/foreign/unproven)"
    [ "$R_DIRTY" -eq 0 ] || fail "remount hit a dirty-predecessor refusal"
    [ "$R_SINCE" -lt "$GRACE_S" ] || fail "budget: the remount completed ${R_SINCE}s after the departure, outside the ${GRACE_S}s grace — the arm's premise (settle before any peer expires it) was not exercised"
    [ "$(write_ok "$VICTIM")" = 1 ] || fail "remounted victim cannot write"
    sleep 5
    sweep "after${1:-}"
    local exp cert pkf comp_peers held unk conf
    exp=$(count "after${1:-}" P304-RETIRE-EXPIRED-WITHDRAWN "$VICTIM"); cert=$(count "after${1:-}" P236-FENCE-CERTIFIED); pkf=$(count "after${1:-}" P-PRKEY-FENCED)
    comp_peers=$(count "after${1:-}" P304-RETIRE-COMPLETED-BY-PEER "$VICTIM"); held=$(count "after${1:-}" P-ADMIT-RETIRE-PENDING-HELD); unk=$(count "after${1:-}" P304-RETIRE-UNKNOWN-STALLED); conf=$(count "after${1:-}" P304-RETIRE-KEY-CONFLICT)
    say "fleet after remount: peers EXPIRED=$exp FENCE-CERTIFIED=$cert PRKEY-FENCED=$pkf peers-COMPLETED=$comp_peers HELD=$held UNKNOWN-STALLED=$unk KEY-CONFLICT=$conf"
    [ "$exp" -eq 0 ] || fail "a peer expired the record to WITHDRAWN although the same-boot mount owned the key"
    [ "$cert" -eq 0 ] || fail "somebody fenced during the same-boot remount"
    [ "$pkf" -eq 0 ] || fail "the re-registered key was preempted"
    [ "$comp_peers" -eq 0 ] || fail "a peer published EMPTY while the key was registered (ABSENT without proof)"
    [ "$conf" -eq 0 ] || fail "key conflict reported"
    keys > "$OUT/keys_after_remount${1:-}.txt"
    [ "$(wc -l < "$OUT/keys_after_remount${1:-}.txt")" -eq "$(wc -l < "$OUT/keys_before.txt")" ] || fail "key table has $(wc -l < "$OUT/keys_after_remount${1:-}.txt") keys, expected $(wc -l < "$OUT/keys_before.txt") (same-boot remount must reuse its derived key)"
    if [ -n "${KEY:-}" ] && ! grep -qx "$KEY" "$OUT/keys_after_remount${1:-}.txt"; then fail "the derived key $KEY is not registered after the remount"; fi
}

case "$ARM" in
sameboot)
    fleet_clear
    depart_victim
    remount_victim victim_remount
    sameboot_asserts
    # control: a CLEAN departure (knobs off) now completes by a peer, then the fleet-as-found remount
    fleet_clear
    "$SSH" "$VICTIM" "echo 0 > $KNOB; echo 0 > $KNOB2; timeout 60 umount $MNT; echo UMOUNT_RC=\$?; dmesg | grep -c 'P301\|P303'" > "$OUT/victim_control.log" 2>&1
    [ "$(tail -1 "$OUT/victim_control.log")" = 0 ] || fail "control umount printed P301/P303 with the knobs off"
    ccomp=$(wait_count ctl P304-RETIRE-COMPLETED-BY-PEER 1 60 "$VICTIM")
    say "control: peers COMPLETED-BY-PEER=$ccomp CLEAN-DEPART=$(count ctl P163-CLEAN-DEPART "$VICTIM") fence=$(count ctl P236-FENCE-CERTIFIED)"
    [ "$ccomp" -ge 1 ] || fail "no peer completed the clean retirement after the control umount"
    [ "$(count ctl P236-FENCE-CERTIFIED)" -eq 0 ] || fail "the clean control fired a fence"
    restore_victim
    ;;
joiner)
    fleet_clear
    "$SSH" "$JOINER" "echo 0 > $KNOB 2>/dev/null; echo 0 > $KNOB2 2>/dev/null; timeout 60 umount $MNT; echo UMOUNT_RC=\$?" > "$OUT/joiner_umount.log" 2>&1
    grep -q 'UMOUNT_RC=0' "$OUT/joiner_umount.log" || { say "INFRA-FAIL: joiner clean umount failed"; exit 2; }
    jc=$(wait_count jset P304-RETIRE-COMPLETED-BY-PEER 1 60 "$JOINER")
    say "joiner's own clean release completed by a peer: $jc"
    [ "$jc" -ge 1 ] || { say "INFRA-FAIL: the joiner's own record did not settle EMPTY within 60 s (would confound the arm)"; exit 2; }
    fleet_clear
    depart_victim
    T1=$(date +%s)
    "$SSH" "$JOINER" "dmesg --clear; blockdev --flushbufs $DEV; timeout 180 mount -t mxfs $DEV $MNT; echo MOUNT_RC=\$?; dmesg" > "$OUT/joiner_mount.log" 2>&1
    T2=$(date +%s)
    keys > "$OUT/keys_at_joiner_mounted.txt"
    wall=$((T2 - T1)); since=$((T1 - T_DEPART))
    rc=$(sed -n 's/^MOUNT_RC=//p' "$OUT/joiner_mount.log")
    imm=$(grep -c 'P304-RETIRE-EXPIRED-WITHDRAWN.*immediate=1' "$OUT/joiner_mount.log")
    heldj=$(grep -c 'P-ADMIT-RETIRE-PENDING-HELD' "$OUT/joiner_mount.log")
    compj=$(grep -c 'P304-RETIRE-COMPLETED-BY-PEER' "$OUT/joiner_mount.log")
    say "joiner mount: rc=${rc:-?} wall=${wall}s started ${since}s after the departure; EXPIRED-immediate=$imm HELD=$heldj COMPLETED=$compj"
    [ "${rc:-1}" = 0 ] || fail "joiner mount failed rc=${rc:-?}"
    [ "$since" -lt "$GRACE_S" ] || fail "budget: the joiner's mount started ${since}s after the departure, outside the ${GRACE_S}s grace — the peers' expiry may have done the barrier's job"
    if [ -n "${KEY:-}" ] && grep -qx "$KEY" "$OUT/keys_at_joiner_mounted.txt"; then fail "INVARIANT: mount(2) returned on the joiner while the departed key $KEY was still registered (admission beside an unretired registration)"; else say "key ${KEY:-?} absent when the joiner's mount returned"; fi
    [ $((imm + heldj)) -ge 1 ] || fail "the joiner's barrier neither settled the record immediately nor held on it"
    [ "$compj" -eq 0 ] || fail "the joiner published EMPTY for a record whose key was registered"
    sleep 5
    sweep after
    cert=$(count after P236-FENCE-CERTIFIED); pkf=$(count after P-PRKEY-FENCED); unk=$(count after P304-RETIRE-UNKNOWN-STALLED)
    say "fleet after joiner mount: FENCE-CERTIFIED=$cert PRKEY-FENCED=$pkf UNKNOWN-STALLED=$unk"
    [ "$cert" -ge 1 ] || fail "nobody certified a fence of the departed key"
    [ "$(write_ok "$JOINER")" = 1 ] || fail "joiner cannot write after admission"
    restore_victim
    ;;
unknown|unknownresv)
    K=dbg_pr_read_keys_fail; INJ=P-DBG-PR-READ-KEYS-FAIL
    [ "$ARM" = unknownresv ] && { K=dbg_pr_read_resv_fail; INJ=P-DBG-PR-READ-RESV-FAIL; }
    fleet_clear
    set_knob "$K" 100000 $(peers)
    depart_victim
    say "holding 40 s with every peer's PR IN failing ($K)"
    sleep 40
    sweep hold
    seen=$(count hold P304-RETIRE-PENDING-SEEN "$VICTIM"); unk=$(count hold P304-RETIRE-UNKNOWN-STALLED "$VICTIM")
    comp=$(count hold P304-RETIRE-COMPLETED-BY-PEER "$VICTIM"); exp=$(count hold P304-RETIRE-EXPIRED-WITHDRAWN "$VICTIM")
    cert=$(count hold P236-FENCE-CERTIFIED); inj=$(count hold "$INJ" "$VICTIM"); unprov=$(count hold P-PR-ABSENCE-UNPROVABLE "$VICTIM")
    hbf=$(( $(count hold P-HBFALSE) + $(count hold P-HB-SLOW) + $(count hold P-HB-MONSLOW) + $(count hold HB-STALL) ))
    seen_unknown=$(grep -a -l 'P304-RETIRE-PENDING-SEEN.*state=UNKNOWN' "$OUT"/hold_test*.txt 2>/dev/null | wc -l)
    say "hold: SEEN=$seen (nodes seeing UNKNOWN=$seen_unknown) UNKNOWN-STALLED=$unk injected=$inj UNPROVABLE=$unprov COMPLETED=$comp EXPIRED=$exp FENCE=$cert hb-symptoms=$hbf"
    [ "$inj" -ge 1 ] || fail "the injection never fired (vacuous)"
    [ "$seen" -ge 1 ] || fail "no peer saw the RETIRE_PENDING record"
    [ "$seen_unknown" -ge 1 ] || fail "no peer classified the record UNKNOWN on first sight"
    [ "$unk" -ge 1 ] || fail "no P304-RETIRE-UNKNOWN-STALLED after the grace — UNKNOWN did not escalate"
    [ "$comp" -eq 0 ] || fail "a peer published EMPTY under a failing PR IN (ABSENT manufactured from no evidence)"
    [ "$exp" -eq 0 ] || fail "a peer expired the record to WITHDRAWN under UNKNOWN (aged a lack of evidence into a fence)"
    [ "$cert" -eq 0 ] || fail "a fence fired under UNKNOWN"
    [ "$hbf" -eq 0 ] || fail "heartbeat symptoms ($hbf) while PR INs failed — PR work leaked onto the heartbeat"
    if [ -n "${KEY:-}" ] && ! keys | grep -qx "$KEY"; then fail "the key $KEY disappeared during the UNKNOWN hold"; fi
    # clear the injection: the record is past its grace → PRESENT → WITHDRAWN at once, fenced
    set_knob "$K" 0 $(peers)
    exp=$(wait_count rel P304-RETIRE-EXPIRED-WITHDRAWN 1 40 "$VICTIM")
    cert=$(wait_count rel2 P236-FENCE-CERTIFIED 1 30)
    say "after clearing: EXPIRED=$exp FENCE-CERTIFIED=$cert"
    [ "$exp" -ge 1 ] || fail "the record was not expired once PR INs worked again"
    [ "$cert" -ge 1 ] || fail "the key was not fenced after the expiry"
    if [ -n "${KEY:-}" ] && keys | grep -qx "$KEY"; then fail "the key $KEY is still registered after the fence"; fi
    restore_victim
    ;;
trunc)
    fleet_clear
    # sess455 (0.61.0 worker model): brackets run only on the worker of a peer
    # that has QUEUED the record, so only the peers whose monitor lap saw it
    # before the first successful settle ever bracket (chain 77: two brackets
    # total, RESV-FAIL never consumed on the even half).  Arm BOTH one-shots on
    # EVERY peer: whichever peer publishes must first have burned its own
    # truncation (bracket discarded) and its own RESV failure (UNKNOWN), so
    # both injections are exercised on the publishing node by construction.
    all=(); for p in $(peers); do all+=("$p"); done
    set_knob dbg_pr_read_keys_trunc 1 "${all[@]}"
    set_knob dbg_pr_read_resv_fail 1 "${all[@]}"
    depart_victim_clean
    comp=$(wait_count t P304-RETIRE-COMPLETED-BY-PEER 1 60 "$VICTIM")
    sleep 3; sweep t
    comp=$(count t P304-RETIRE-COMPLETED-BY-PEER "$VICTIM"); tr=$(count t P-DBG-PR-READ-KEYS-TRUNC "$VICTIM"); trb=$(count t P-PR-VIEW-TRUNC "$VICTIM"); rf=$(count t P-DBG-PR-READ-RESV-FAIL "$VICTIM")
    cert=$(count t P236-FENCE-CERTIFIED); exp=$(count t P304-RETIRE-EXPIRED-WITHDRAWN "$VICTIM")
    say "trunc: COMPLETED-BY-PEER=$comp TRUNC-injected=$tr (seen by a bracket: $trb) RESV-FAIL-injected=$rf EXPIRED=$exp FENCE=$cert"
    [ "$tr" -ge 1 ] || fail "no READ KEYS truncation fired (vacuous)"
    [ "$rf" -ge 1 ] || fail "no READ RESERVATION failure fired (vacuous)"
    [ "$comp" -eq 1 ] || fail "expected exactly one EMPTY publication, got $comp"
    [ "$exp" -eq 0 ] || fail "a clean departure was expired to WITHDRAWN"
    [ "$cert" -eq 0 ] || fail "a clean departure was fenced"
    # ordering: on any node where an injection fired AND an EMPTY was published, the injection line precedes it
    # sess452 chain 71: the sweep files start with the "MARK=count" header
    # (which contains every marker name) and a '---' line; order only the
    # dmesg section below it, or the header's own lines match.
    for p in $(peers); do
        f="$OUT/t_$p.txt"
        li=$(sed -n '/^---$/,$p' "$f" | grep -a -n 'P-DBG-PR-READ-KEYS-TRUNC\|P-DBG-PR-READ-RESV-FAIL' | tail -1 | cut -d: -f1)
        lc=$(sed -n '/^---$/,$p' "$f" | grep -a -n 'P304-RETIRE-COMPLETED-BY-PEER' | head -1 | cut -d: -f1)
        if [ -n "$li" ] && [ -n "$lc" ] && [ "$lc" -lt "$li" ]; then fail "$p published EMPTY before its injected bracket failed — the failed bracket did not answer UNKNOWN"; fi
        if [ -n "$li" ] && [ -n "$lc" ]; then say "$p: injection at dmesg line $li, EMPTY at $lc (next bracket proved absence)"; fi
    done
    restore_victim
    ;;
slowpr)
    fleet_clear
    set_knob dbg_pr_read_keys_delay_ms 10000 $(peers)
    depart_victim_clean
    comp=$(wait_count s P304-RETIRE-COMPLETED-BY-PEER 1 90 "$VICTIM")
    sleep 3; sweep s
    comp=$(count s P304-RETIRE-COMPLETED-BY-PEER "$VICTIM"); dl=$(count s P-DBG-PR-READ-KEYS-DELAY "$VICTIM" 2>/dev/null)
    hbf=$(count s P-HBFALSE); hbs=$(count s P-HB-SLOW); hbm=$(count s P-HB-MONSLOW); hst=$(count s HB-STALL)
    cert=$(count s P236-FENCE-CERTIFIED); exp=$(count s P304-RETIRE-EXPIRED-WITHDRAWN "$VICTIM")
    say "slowpr: COMPLETED-BY-PEER=$comp HBFALSE=$hbf HB-SLOW=$hbs HB-MONSLOW=$hbm HB-STALL=$hst EXPIRED=$exp FENCE=$cert"
    [ "$comp" -ge 1 ] || fail "the clean retirement never completed under slow PR INs"
    [ "$hbf" -eq 0 ] || fail "P-HBFALSE under slow PR — a false death"
    [ "$hbs" -eq 0 ] || fail "P-HB-SLOW under slow PR — the heartbeat waited on PR I/O"
    [ "$hbm" -eq 0 ] || fail "P-HB-MONSLOW under slow PR — the monitor lap waited on PR I/O"
    [ "$hst" -eq 0 ] || fail "HB-STALL under slow PR"
    [ "$cert" -eq 0 ] || fail "a fence fired under slow PR"
    [ "$exp" -eq 0 ] || fail "a clean departure was expired to WITHDRAWN under slow PR"
    set_knob dbg_pr_read_keys_delay_ms 0 $(peers)
    restore_victim
    ;;
joinerunk)
    fleet_clear
    "$SSH" "$JOINER" "echo 0 > $KNOB 2>/dev/null; echo 0 > $KNOB2 2>/dev/null; timeout 60 umount $MNT; echo UMOUNT_RC=\$?" > "$OUT/joiner_umount.log" 2>&1
    grep -q 'UMOUNT_RC=0' "$OUT/joiner_umount.log" || { say "INFRA-FAIL: joiner clean umount failed"; exit 2; }
    jc=$(wait_count jset P304-RETIRE-COMPLETED-BY-PEER 1 60 "$JOINER")
    [ "$jc" -ge 1 ] || { say "INFRA-FAIL: the joiner's own record did not settle EMPTY within 60 s"; exit 2; }
    fleet_clear
    # nobody can classify: every node's bracket fails (the joiner's admission checks still pass)
    all=(); for i in $(seq 1 "$N"); do all+=("test$i"); done
    set_knob dbg_pr_bracket_fail 100000 "${all[@]}"
    depart_victim
    T1=$(date +%s)
    "$SSH" "$JOINER" "dmesg --clear; blockdev --flushbufs $DEV; timeout 120 mount -t mxfs $DEV $MNT; echo MOUNT_RC=\$?; mount -t mxfs | grep -c mxfs; dmesg" > "$OUT/joiner_mount_unk.log" 2>&1
    T2=$(date +%s)
    keys > "$OUT/keys_at_joiner_returned.txt"
    rc=$(sed -n 's/^MOUNT_RC=//p' "$OUT/joiner_mount_unk.log"); mounted=$(sed -n '/^MOUNT_RC=/{n;p}' "$OUT/joiner_mount_unk.log" | head -1)
    held=$(grep -c 'P-ADMIT-RETIRE-PENDING-HELD' "$OUT/joiner_mount_unk.log"); abort=$(grep -c 'MXFS mount ABORTED' "$OUT/joiner_mount_unk.log")
    bf=$(grep -c 'P-DBG-PR-BRACKET-FAIL' "$OUT/joiner_mount_unk.log"); compj=$(grep -c 'P304-RETIRE-COMPLETED-BY-PEER' "$OUT/joiner_mount_unk.log")
    expj=$(grep -c 'P304-RETIRE-EXPIRED-WITHDRAWN' "$OUT/joiner_mount_unk.log")
    say "joiner mount under UNKNOWN: rc=${rc:-?} mounted=$mounted wall=$((T2 - T1))s HELD=$held ABORTED=$abort bracket-fail=$bf COMPLETED=$compj EXPIRED=$expj"
    [ "${rc:-0}" != 0 ] || fail "INVARIANT: the joiner was ADMITTED beside an unclassifiable RETIRE_PENDING record"
    [ "${mounted:-1}" = 0 ] || fail "the joiner reports an mxfs mount after the refused mount"
    [ "$held" -ge 1 ] || fail "no P-ADMIT-RETIRE-PENDING-HELD on the joiner"
    [ "$abort" -ge 1 ] || fail "no 'MXFS mount ABORTED' at the barrier bound"
    [ "$bf" -ge 1 ] || fail "the bracket failure never fired on the joiner (vacuous)"
    [ "$compj" -eq 0 ] || fail "the joiner published EMPTY under a failing bracket"
    [ "$expj" -eq 0 ] || fail "the joiner expired the record under UNKNOWN"
    if [ -n "${KEY:-}" ] && ! grep -qx "$KEY" "$OUT/keys_at_joiner_returned.txt"; then fail "the victim's key $KEY vanished while nobody could classify it"; fi
    sweep unkhold
    [ "$(count unkhold P304-RETIRE-COMPLETED-BY-PEER)" -eq 0 ] || fail "some node published EMPTY with every bracket failing"
    [ "$(count unkhold P304-RETIRE-EXPIRED-WITHDRAWN)" -eq 0 ] || fail "some node expired the record with every bracket failing"
    [ "$(count unkhold P236-FENCE-CERTIFIED)" -eq 0 ] || fail "a fence fired with every bracket failing"
    # clear: peers expire (past grace) and fence; the joiner remounts
    set_knob dbg_pr_bracket_fail 0 "${all[@]}"
    exp=$(wait_count rel P304-RETIRE-EXPIRED-WITHDRAWN 1 40 "$VICTIM"); cert=$(wait_count rel2 P236-FENCE-CERTIFIED 1 30)
    say "after clearing: EXPIRED=$exp FENCE-CERTIFIED=$cert"
    [ "$exp" -ge 1 ] || fail "no expiry once brackets worked again"
    [ "$cert" -ge 1 ] || fail "no fence after the expiry"
    "$SSH" "$JOINER" "dmesg --clear; blockdev --flushbufs $DEV; timeout 180 mount -t mxfs $DEV $MNT; echo MOUNT_RC=\$?" > "$OUT/joiner_remount.log" 2>&1
    grep -q 'MOUNT_RC=0' "$OUT/joiner_remount.log" || fail "joiner remount after clearing failed"
    [ "$(write_ok "$JOINER")" = 1 ] || fail "joiner cannot write after admission"
    if [ -n "${KEY:-}" ] && keys | grep -qx "$KEY"; then fail "the key $KEY is still registered after the fence"; fi
    restore_victim
    ;;
race)
    # ordering A: remount at once
    fleet_clear
    depart_victim _A
    remount_victim race_A
    sameboot_asserts _A
    # ordering B: remount straddling the grace
    fleet_clear
    "$SSH" "$VICTIM" "timeout 60 umount $MNT; echo UMOUNT_RC=\$?" > "$OUT/victim_umount_A_end.log" 2>&1
    wait_count ctlB P304-RETIRE-COMPLETED-BY-PEER 1 60 "$VICTIM" >/dev/null   # A's clean release settles
    # sess452 chain 71: ordering B departs from a MOUNTED victim — remount it
    # (knobs off, plain mount) after A's clean teardown settled.
    "$SSH" "$VICTIM" "echo 0 > $KNOB; echo 0 > $KNOB2; dmesg --clear; blockdev --flushbufs $DEV; timeout 120 mount -t mxfs $DEV $MNT; echo MOUNT_RC=\$?" > "$OUT/victim_mount_B_pre.log" 2>&1
    grep -q 'MOUNT_RC=0' "$OUT/victim_mount_B_pre.log" || { say "INFRA-FAIL: victim could not be remounted between orderings A and B"; restore_victim; exit 2; }
    fleet_clear
    depart_victim _B
    delay=$(( T_DEPART + 29 - $(date +%s) )); [ "$delay" -gt 0 ] && sleep "$delay"
    remount_victim race_B
    sleep 8; sweep B
    expB=$(count B P304-RETIRE-EXPIRED-WITHDRAWN "$VICTIM"); certB=$(count B P236-FENCE-CERTIFIED); compB=$(count B P304-RETIRE-COMPLETED-BY-PEER "$VICTIM")
    say "race B: peers EXPIRED=$expB FENCE=$certB peers-COMPLETED=$compB victim SETTLED-OWN=$R_OWN changed=$R_CHANGED dirty-refused=$R_DIRTY rc=${R_RC:-?}"
    [ "$compB" -eq 0 ] || fail "a peer published EMPTY while the key was registered"
    if [ "$R_OWN" -ge 1 ]; then
        say "ordering B resolved as P305-first"
        [ "$expB" -eq 0 ] || fail "BOTH a SETTLED-OWN and a peer EXPIRED for the same record"
        [ "$certB" -eq 0 ] || fail "a fence fired although P305 settled the record"
        [ "${R_RC:-1}" = 0 ] || fail "P305 settled but the mount failed rc=${R_RC:-?}"
    else
        say "ordering B resolved as peer-expiry-first"
        [ "$expB" -ge 1 ] || fail "neither P305 settled nor a peer expired the record"
        [ "$R_CHANGED" -ge 1 ] || fail "P305 did not observe the record changed under it"
        if [ "${R_RC:-1}" = 0 ]; then
            [ "$R_DIRTY" -eq 0 ] || fail "mount rc=0 with a dirty-predecessor refusal logged"
        else
            [ "$R_DIRTY" -ge 1 ] || fail "the remount was refused without a same-boot dirty-predecessor line"
        fi
        cert=$(wait_count B2 P236-FENCE-CERTIFIED 1 40)
        [ "$cert" -ge 1 ] || fail "the expired record was never fenced"
    fi
    # whichever ordering: the fleet must be consistent afterwards
    sleep 5; sweep Bfinal
    [ "$(count Bfinal 'Filesystem has been shut down')" -eq 0 ] || fail "a shutdown in the race"
    restore_victim
    ;;
genmove)
    fleet_clear
    set_knob dbg_pr_read_keys_delay_ms 1500 $(peers)
    depart_victim
    sleep 2      # let every peer see the record and start bracketing
    remount_victim victim_remount
    sameboot_asserts
    inc=$(count after P-PR-BRACKET-INCOHERENT "$VICTIM"); disc=$(count after P-PR-BRACKET-DISCARDED)
    say "genmove: INCOHERENT=$inc DISCARDED=$disc"
    [ "$inc" -ge 1 ] || fail "no peer observed the PR generation moving inside a bracket (with 1.5 s per READ KEYS on $((N-1)) peers this is the injected condition)"
    set_knob dbg_pr_read_keys_delay_ms 0 $(peers)
    restore_victim
    ;;
multipending)
    for cyc in 1 2; do
        fleet_clear
        depart_victim "_c$cyc"
        remount_victim "remount_c$cyc"
        sameboot_asserts "_c$cyc"
        [ "$R_OWN" -eq 1 ] || fail "cycle $cyc: expected exactly one SETTLED-OWN, got $R_OWN"
        [ "$(grep -c 'P305-RETIRE-MULTI' "$OUT/remount_c$cyc.log")" -eq 0 ] || fail "cycle $cyc: P305-RETIRE-MULTI fired for a single record"
    done
    restore_victim
    ;;
esac

# fleet health over the whole arm
sweep final
faults=$(count final 'kernel BUG'); faults=$((faults + $(count final 'BUG:') + $(count final Oops) + $(count final 'general protection')))
shut=$(( $(count final 'Filesystem has been shut down') + $(count final 'forced shutdown') ))
[ "$faults" -eq 0 ] || fail "kernel faults=$faults"
[ "$shut" -eq 0 ] || fail "$shut shutdown line(s) in the fleet"
keys > "$OUT/keys_end.txt"
[ "$(wc -l < "$OUT/keys_end.txt")" -eq "$(wc -l < "$OUT/keys_before.txt")" ] || fail "key table at the end has $(wc -l < "$OUT/keys_end.txt") keys, expected $(wc -l < "$OUT/keys_before.txt")"

echo "evidence: $OUT"
if [ "$FAILS" = 0 ]; then echo "=== retire_pending_admission $ARM PASS @ $(date -u +%FT%TZ) ==="; exit 0; fi
echo "=== retire_pending_admission $ARM FAIL fails=$FAILS @ $(date -u +%FT%TZ) ==="; exit 1
