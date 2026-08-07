#!/bin/bash
# p248_inject.sh — deterministic fault-injection verification of the P248
# teardown tenure retire (D-RELEASEALL-LREQ-RETIRE-MISSING, fixed 0.11.455,
# sess153 GPT ruling + sess154 implementation).
#
# WHAT IS UNDER TEST (dlm/dlm_caw.c):
#   fix A — caw_owed_release retires the local tenure record when a teardown
#           obligation completes with no attempt and no publication possible
#           (attempted && !pending && ops_closed && release_all_done), with
#           two fail-closed tripwires (live attempts / post-freeze publication
#           generation bump -> P266-RETIRE-REFUSED, tenure kept).
#   fix B — release_all re-issues a slot CAS exactly once after -ESHUTDOWN
#           (transport UA absorbed in-line) before recording an obligation.
#
# INJECTION KNOBS (module params, consumable dec-and-true counters):
#   K1 caw_inject_ra_casfail    release_all CAS -> -ESHUTDOWN
#   K2 caw_inject_owed_enoent   owed resolve rc=0 -> -ENOENT (terminal lie)
#   K5 caw_inject_dow_casfail   drop_own_waiter CAS -> -EIO (transient)
#   K4 caw_inject_pubfreeze_bump  bump lreq_finish_gen after phase-4 freeze
#   K3 caw_drain_budget_ms      override MXFS_CAW_OWED_DRAIN_MS (not consumable)
#
# CASES (run order isolates the two dirty-LUN cases behind re-preps):
#   c1  K1=2            first slot: CAS + fix-B retry both -ESHUTDOWN -> owed;
#                       drain discharges -> retire.  Expect P257-RESIDUE owed=1,
#                       P268 n=1, P263 x1, P267 retired=1; no P248/P254/P259.
#   c4  K1=2 K5=1       owed discharge -EIO once (transient) -> requeue ->
#                       2nd sweep real -> retire.  Same expectations as c1
#                       plus K5 consumed.
#   c6  K1=2 K4=1       publication-generation bump lands after the phase-4
#                       freeze -> retire REFUSED (fail closed).  Expect P266,
#                       P248-LEAK-ENT + P248-LEAK entries=1; no P263/P267.
#                       LUN left clean (the discharge itself succeeded).
#   c5  2-node churn, K5=1 armed mid-run: a mid-run owed discharge failure
#                       must NOT retire tenures (sess117 guard preserved).
#                       Non-vacuity: knob consumed (readback 0), <=3 churn
#                       rounds.  Assert zero P263/P266 in the churn window on
#                       BOTH nodes; clean unmount both; no P248/P259.
#   -- re-prep --
#   c3  K1=2 K5=50 K3=1 drain budget exhausted with discharge held off ->
#                       P254 left=1, departure refused (P259), entry survives
#                       to the destroy report (P248 entries=1); no P263/P267.
#                       K5=50 is a deliberate deviation from the sess154
#                       recipe: the drain loop checks the deadline BEFORE the
#                       first sweep but hands the deadline INTO the sweep, so
#                       a hint-guided resolve could discharge inside 1ms and
#                       turn the case into c1.  Forcing every discharge
#                       attempt -EIO removes the race.  LUN DIRTY after.
#   -- re-prep --
#   c2  K1=2 K2=1       owed resolve lies -ENOENT -> terminal retract ->
#                       retire (P263+P267), no P248 -- but the bits REMAIN on
#                       disk.  LUN DIRTY after; last case for that reason.
#
# The umount SYSCALL must succeed in every case, including c3 -- P259 is a
# cluster-departure verdict, not a umount error.
#
# RULE 0 budgets: 20-create workload ~1s (30s cap incl. ssh), umount incl.
# 2000ms drain budget + release_all I/O ~4s (45s cap), rejoin mount ~5s (60s
# cap), census ssh ~2s (25s cap), churn round 45s by design (75s cap).
#
# USAGE: tests/p248_inject.sh [step...]   steps: prep c1 c4 c6 c5 c3 c2
#        no args = full sequence: prep c1 c4 c6 c5 prep c3 prep c2
#        (cluster: test1 departs/remounts per case, test2 anchors; module
#        stays loaded across cases -- knobs persist, so every case zeroes
#        all six before and after itself.)
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd -- "$SCRIPT_DIR/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
MNT=/mnt/shared
DEV="${MXFS_DEV:-/dev/mapper/mpatha}"
NONCE=$$
WANT_SV=$(modinfo "$REPO/mxfs.ko" 2>/dev/null | awk '/^srcversion/{print $2}')
cd "$REPO" || exit 2

RUN_OK=1

knobs_zero() { # node
    timeout 15 "$SSH" "$1" "
        for k in caw_inject_ra_casfail caw_inject_owed_enoent \
                 caw_inject_dow_casfail caw_inject_pubfreeze_bump \
                 caw_inject_wait_expire caw_drain_budget_ms; do
            echo 0 > /sys/module/mxfs/parameters/\$k 2>/dev/null
        done; true" >/dev/null 2>&1
}

arm() { # node knob value
    timeout 15 "$SSH" "$1" \
        "echo $3 > /sys/module/mxfs/parameters/$2" >/dev/null 2>&1
}

readknob() { # node knob -> value (empty on error)
    timeout 15 "$SSH" "$1" \
        "cat /sys/module/mxfs/parameters/$2" 2>/dev/null | tr -dc 0-9
}

mark() { # node text
    timeout 15 "$SSH" "$1" "echo '$2' > /dev/kmsg" >/dev/null 2>&1
}

window() { # node case -> the [BEGIN,END] dmesg window on stdout
    timeout 25 "$SSH" "$1" "
        f=/root/dmesg.stream
        ok=
        for t in 1 2 3; do
            [ -s \$f ] && grep -q 'P248TEST-$NONCE $2 END' \$f && { ok=1; break; }
            sleep 1
        done
        if [ -n \"\$ok\" ]; then
            sed -n '/P248TEST-$NONCE $2 BEGIN/,/P248TEST-$NONCE $2 END/p' \$f
        else
            dmesg | sed -n '/P248TEST-$NONCE $2 BEGIN/,/P248TEST-$NONCE $2 END/p'
        fi" 2>/dev/null
}

parse() { # case; stdin = window -> shell assignments on stdout
    awk -v pre="P248TEST-$NONCE $1 PREUMOUNT" '
        index($0, pre)                  {p=1}
        /P248-LREQ-LEAK-ENT/            {ent++; next}
        /P248-LREQ-LEAK entries=/       {agg++
            if (match($0, /entries=[0-9]+/))
                aggv=substr($0, RSTART+8, RLENGTH-8)
            next}
        /P263-OWED-TEARDOWN-RETIRE/     {p263++; if (!p) p263run++; next}
        /P266-RETIRE-REFUSED/           {p266++; if (!p) p266run++; next}
        /P267-RETIRE-SUM/               {p267++
            if (match($0, /retired=[0-9]+/))
                p267v=substr($0, RSTART+8, RLENGTH-8)
            next}
        /P268-RELEASEALL-IORETRY/       {p268++
            if (match($0, /n=[0-9]+/))
                p268n=substr($0, RSTART+2, RLENGTH-2)
            next}
        /P254-OWED-TEARDOWN/            {p254++
            if (match($0, /left=[0-9]+/))
                p254l=substr($0, RSTART+5, RLENGTH-5)
            next}
        /P257-RELEASEALL-RESIDUE/       {p257r++
            if (match($0, /owed=[0-9]+/))
                p257o=substr($0, RSTART+5, RLENGTH-5)
            if (match($0, /lost=[0-9]+/))
                p257lostv=substr($0, RSTART+5, RLENGTH-5)
            next}
        /P257-RELEASEALL-LOST/          {p257lost++; next}
        /P259-DEPART-UNCLEAN/           {p259++
            # one unclean departure = TWO deliberate lines: the CAW-layer
            # verdict (dlm_caw.c, "node=<id> quiesced=...") and the v5-layer
            # GOODBYE suppression (v5_mount.c).  p259 totals both (zero
            # asserts stay airtight); p259v/p259g discriminate for c3.
            if (/node=/) p259v++
            if (/suppressing the GOODBYE/) p259g++
            next}
        /P260-CAW-CTX-LEAKED/           {p260++; next}
        /P269-FROZEN-TENURE-ATTEMPTS/   {p269++; next}
        /P270-MOOT-RETRACT-REFUSED/     {p270++; next}
        /P271-OWED-DISCHARGE/           {p271++; next}
        /P272-INJECT-WAIT-EXPIRE/       {p272++; next}
        /P245-RECONCILE-EXHAUST/        {p245++; next}
        END {printf "ent=%d agg=%d aggv=%d p263=%d p263run=%d p266=%d " \
                    "p266run=%d p267=%d p267v=%d p268=%d p268n=%d p254=%d " \
                    "p254l=%d p257r=%d p257o=%d p257lostv=%d p257lost=%d " \
                    "p259=%d p259v=%d p259g=%d p260=%d p269=%d p270=%d " \
                    "p271=%d p272=%d p245=%d\n", ent, agg, \
                    aggv, p263, p263run, p266, p266run, p267, p267v, p268, \
                    p268n, p254, p254l, p257r, p257o, p257lostv, p257lost, \
                    p259, p259v, p259g, p260, p269, p270, p271, p272, p245}'
}

CASE_OK=1
chk() { # desc actual op want
    local r=1
    case "$3" in
        eq) [ "${2:-x}" -eq "$4" ] 2>/dev/null && r=0 ;;
        ge) [ "${2:-x}" -ge "$4" ] 2>/dev/null && r=0 ;;
        le) [ "${2:-x}" -le "$4" ] 2>/dev/null && r=0 ;;
    esac
    [ $r -eq 0 ] || { echo "    FAIL: $1 (got '${2:-}', want $3 $4)"
                      CASE_OK=0; RUN_OK=0; }
}

dump_probes() { # stdin = window
    grep -E 'P248TEST|P248-LREQ|P245-|P25[2-9]-|P26[0-9]-|P27[0-2]-' |
        sed 's/^/    /'
}

do_prep() {
    echo "=== prep_cluster 2/caw (force, tree srcversion $WANT_SV) ==="
    MXFS_FORCE_PREP=1 timeout 580 ./run.sh 2 caw prep_cluster 2>&1 | tail -3
    local rc=${PIPESTATUS[0]} n sv
    [ "$rc" -eq 0 ] || { echo "PREP FAILED rc=$rc"; exit 2; }
    for n in test1 test2; do
        sv=$(timeout 15 "$SSH" "$n" "cat /sys/module/mxfs/srcversion" \
             2>/dev/null | tr -d '\r\n')
        echo "  $n srcversion=$sv"
        [ "$sv" = "$WANT_SV" ] || { echo "PREP: $n srcversion MISMATCH"; exit 2; }
        knobs_zero "$n"
    done
}

remount_t1() {
    timeout 60 "$SSH" test1 "mount -t mxfs $DEV $MNT" >/dev/null 2>&1 || {
        echo "  FAIL: test1 remount"; RUN_OK=0; return 1; }
    return 0
}

run_det_case() { # c1|c4|c6|c3|c2
    local c=$1 w counts
    CASE_OK=1
    echo "=== case $c ==="
    knobs_zero test1
    mark test1 "P248TEST-$NONCE $c BEGIN"
    timeout 30 "$SSH" test1 "mkdir -p $MNT/p248_${c}_$NONCE &&
        for i in \$(seq 1 20); do echo x > $MNT/p248_${c}_$NONCE/f\$i; done &&
        sync" >/dev/null 2>&1 || {
            echo "    FAIL: workload"; RUN_OK=0; return; }
    case $c in
        c1) arm test1 caw_inject_ra_casfail 2 ;;
        c4) arm test1 caw_inject_ra_casfail 2
            arm test1 caw_inject_dow_casfail 1 ;;
        c6) arm test1 caw_inject_ra_casfail 2
            arm test1 caw_inject_pubfreeze_bump 1 ;;
        c3) arm test1 caw_inject_ra_casfail 2
            arm test1 caw_inject_dow_casfail 50
            arm test1 caw_drain_budget_ms 1 ;;
        c2) arm test1 caw_inject_ra_casfail 2
            arm test1 caw_inject_owed_enoent 1 ;;
    esac
    timeout 45 "$SSH" test1 "umount $MNT" >/dev/null 2>&1 || {
        echo "    FAIL: umount syscall"; CASE_OK=0; RUN_OK=0; }
    mark test1 "P248TEST-$NONCE $c END"
    w=$(window test1 "$c")
    echo "$w" | dump_probes
    counts=$(echo "$w" | parse "$c")
    echo "    counts: $counts"
    eval "$counts"
    # every case: no lost slots, no leaked ctx, injection fully consumed
    chk "$c P257-LOST"      "$p257lost" eq 0
    chk "$c P260-CTX-LEAK"  "$p260"     eq 0
    chk "$c K1 consumed"    "$(readknob test1 caw_inject_ra_casfail)" eq 0
    # every K1=2 case: exactly one slot went owed, one in-line retry issued
    chk "$c P257-RESIDUE"   "$p257r"    eq 1
    chk "$c residue owed"   "$p257o"    eq 1
    chk "$c residue lost"   "$p257lostv" eq 0
    chk "$c P268 lines"     "$p268"     eq 1
    chk "$c P268 n"         "$p268n"    eq 1
    case $c in
    c1)
        chk "c1 P263 retire"    "$p263" ge 1
        chk "c1 P267 line"      "$p267" eq 1
        chk "c1 P267 retired"   "$p267v" ge 1
        chk "c1 no P248-ENT"    "$ent"  eq 0
        chk "c1 no P248 agg"    "$agg"  eq 0
        chk "c1 no P266"        "$p266" eq 0
        chk "c1 no P254"        "$p254" eq 0
        chk "c1 no P259"        "$p259" eq 0
        # sess157 (D-TEARDOWN-DRAIN-MOOT-TENURED-HOLDER-LEAK): the drain must
        # DISCHARGE ON PROOF, not moot.  P271 is the positive per-mode proof
        # record; P269/P270 are frozen-world contradiction probes.
        chk "c1 P271 proven"    "$p271" ge 1
        chk "c1 no P269"        "$p269" eq 0
        chk "c1 no P270"        "$p270" eq 0
        ;;
    c4)
        chk "c4 P263 retire"    "$p263" ge 1
        chk "c4 P267 line"      "$p267" eq 1
        chk "c4 P267 retired"   "$p267v" ge 1
        chk "c4 no P248-ENT"    "$ent"  eq 0
        chk "c4 no P248 agg"    "$agg"  eq 0
        chk "c4 no P266"        "$p266" eq 0
        chk "c4 no P254"        "$p254" eq 0
        chk "c4 no P259"        "$p259" eq 0
        chk "c4 K5 consumed"    "$(readknob test1 caw_inject_dow_casfail)" eq 0
        # sess157: K5 consumed proves the drain CAS'd (the injection sits in
        # caw_drop_own_waiter's CAS); P271 proves the discharge was by proof.
        chk "c4 P271 proven"    "$p271" ge 1
        chk "c4 no P269"        "$p269" eq 0
        chk "c4 no P270"        "$p270" eq 0
        ;;
    c6)
        chk "c6 P266 refused"   "$p266" ge 1
        chk "c6 P248-ENT"       "$ent"  ge 1
        chk "c6 P248 agg"       "$agg"  eq 1
        chk "c6 P248 entries"   "$aggv" eq 1
        chk "c6 no P263"        "$p263" eq 0
        chk "c6 no P267"        "$p267" eq 0
        chk "c6 no P254"        "$p254" eq 0
        chk "c6 no P259"        "$p259" eq 0
        chk "c6 K4 consumed"    "$(readknob test1 caw_inject_pubfreeze_bump)" eq 0
        ;;
    c3)
        chk "c3 P254 line"      "$p254" eq 1
        chk "c3 P254 left"      "$p254l" ge 1
        # exactly ONE unclean departure: the CAW verdict AND its v5
        # consequence (GOODBYE suppressed) must each fire exactly once --
        # a verdict without the suppression is the fail-open hazard
        chk "c3 P259 verdict"   "$p259v" eq 1
        chk "c3 P259 goodbye"   "$p259g" eq 1
        chk "c3 P248-ENT"       "$ent"  ge 1
        chk "c3 P248 agg"       "$agg"  eq 1
        chk "c3 P248 entries"   "$aggv" eq 1
        chk "c3 no P263"        "$p263" eq 0
        chk "c3 no P267"        "$p267" eq 0
        chk "c3 no P266"        "$p266" eq 0
        echo "    c3 K5 leftover: $(readknob test1 caw_inject_dow_casfail) of 50"
        ;;
    c2)
        chk "c2 P263 retire"    "$p263" ge 1
        chk "c2 P267 line"      "$p267" eq 1
        chk "c2 P267 retired"   "$p267v" ge 1
        chk "c2 no P248-ENT"    "$ent"  eq 0
        chk "c2 no P248 agg"    "$agg"  eq 0
        chk "c2 no P266"        "$p266" eq 0
        chk "c2 no P254"        "$p254" eq 0
        chk "c2 no P259"        "$p259" eq 0
        chk "c2 K2 consumed"    "$(readknob test1 caw_inject_owed_enoent)" eq 0
        ;;
    esac
    knobs_zero test1
    case $c in c1|c4|c6) remount_t1 ;; esac   # c3/c2 leave LUN for re-prep
    [ $CASE_OK -eq 1 ] && echo "  case $c: PASS" || echo "  case $c: FAIL"
}

churn_round() { # 45s cross-node create/rm churn in one shared dir, both nodes
    local n rank
    for n in test1 test2; do
        rank=${n#test}
        ( timeout 75 "$SSH" "$n" "
            mkdir -p $MNT/p248churn 2>/dev/null
            end=\$((SECONDS+45)); i=0
            while [ \$SECONDS -lt \$end ]; do
                i=\$((i+1))
                d=$MNT/p248churn/n${rank}_\$((i % 40))
                mkdir -p \$d 2>/dev/null
                echo x > \$d/f 2>/dev/null
                rm -rf \$d 2>/dev/null
            done; true" >/dev/null 2>&1 ) &
    done
}

run_c5() {
    local round w counts consumed=
    CASE_OK=1
    echo "=== case c5 (mid-run K6-forced give-up + K5 CAS fail, sess117 guard) ==="
    # sess158: healthy 2-node churn NEVER reaches K5's site on its own --
    # mid-run owed obligations come only from divergence strips or give-up
    # cleanups, and no give-up occurs when the acquire timeout (120s) dwarfs
    # the 45s round.  K6 (caw_inject_wait_expire) deterministically expires
    # one contended wait whose own waiter bit is registered; the forced
    # give-up publishes a maximal obligation and its drop_own_waiter CAS
    # consumes the pre-armed K5 (-EIO) -> P245 obligation stands -> the
    # always-running owed worker collects MID-RUN -> the sess117 guard must
    # keep the lreq unretired (p263run=0) with no teardown leak (ent=0).
    knobs_zero test1; knobs_zero test2
    mark test1 "P248TEST-$NONCE c5 BEGIN"
    mark test2 "P248TEST-$NONCE c5 BEGIN"
    for round in 1 2 3; do
        echo "  churn round $round (45s, arm K5 then K6 at t+10)"
        churn_round
        sleep 10
        if [ "$round" -eq 1 ]; then
            arm test1 caw_inject_dow_casfail 1   # K5 armed BEFORE K6 so the
            arm test1 caw_inject_wait_expire 1   # forced give-up finds it
        fi
        wait
        if [ "$(readknob test1 caw_inject_wait_expire)" = "0" ] &&
           [ "$(readknob test1 caw_inject_dow_casfail)" = "0" ]; then
            consumed=1; break
        fi
    done
    if [ -z "$consumed" ]; then
        echo "    FAIL: K5/K6 not both consumed in 3 rounds -- case VACUOUS" \
             "(K6=$(readknob test1 caw_inject_wait_expire)" \
             "K5=$(readknob test1 caw_inject_dow_casfail))"
        CASE_OK=0; RUN_OK=0
    fi
    knobs_zero test1
    mark test1 "P248TEST-$NONCE c5 PREUMOUNT"
    mark test2 "P248TEST-$NONCE c5 PREUMOUNT"
    timeout 45 "$SSH" test1 "umount $MNT" >/dev/null 2>&1 || {
        echo "    FAIL: test1 umount"; CASE_OK=0; RUN_OK=0; }
    timeout 45 "$SSH" test2 "umount $MNT" >/dev/null 2>&1 || {
        echo "    FAIL: test2 umount"; CASE_OK=0; RUN_OK=0; }
    mark test1 "P248TEST-$NONCE c5 END"
    mark test2 "P248TEST-$NONCE c5 END"
    local n
    for n in test1 test2; do
        w=$(window "$n" c5)
        echo "  -- $n --"
        echo "$w" | dump_probes
        counts=$(echo "$w" | parse c5)
        echo "    counts: $counts"
        eval "$counts"
        if [ "$n" = test1 ]; then
            # positive anchors: the injection provably fired and the
            # obligation provably survived the failed CAS (non-vacuity)
            chk "c5 P272 fired"       "$p272" ge 1
            chk "c5 P245 obligation"  "$p245" ge 1
        fi
        chk "c5 $n mid-run P263"  "$p263run" eq 0
        chk "c5 $n mid-run P266"  "$p266run" eq 0
        chk "c5 $n no P248-ENT"   "$ent"     eq 0
        chk "c5 $n no P248 agg"   "$agg"     eq 0
        chk "c5 $n no P259"       "$p259"    eq 0
        chk "c5 $n no P260"       "$p260"    eq 0
        chk "c5 $n no P257-LOST"  "$p257lost" eq 0
    done
    [ $CASE_OK -eq 1 ] && echo "  case c5: PASS" || echo "  case c5: FAIL"
}

STEPS=("$@")
[ ${#STEPS[@]} -gt 0 ] || STEPS=(prep c1 c4 c6 c5 prep c3 prep c2)
for s in "${STEPS[@]}"; do
    case $s in
        prep)        do_prep ;;
        c1|c4|c6|c3|c2) run_det_case "$s" ;;
        c5)          run_c5 ;;
        *) echo "unknown step: $s"; exit 2 ;;
    esac
done
echo "=== p248_inject done: $([ $RUN_OK -eq 1 ] && echo ALL PASS || echo FAILURES) ==="
exit $((1 - RUN_OK))
