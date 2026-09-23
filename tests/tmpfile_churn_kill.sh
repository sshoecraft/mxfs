#!/bin/bash
# tmpfile_churn_kill.sh — crash/replay arm for the INSERT-mode iunlink item
# (ledger D-AGI-UNLINKED-CROSSNODE-RECOVERY-SHUTDOWN, "still owed for closure:
# crash/replay ... tests", sess396 design-consult ruling ccmemory
# docs/rulings/insert-mode-iunlink-item.md, seven-mode
# matrix item "crash points around dinode-repair/AGI-update/commit+replay").
#
# Every node churns O_TMPFILE create -> write -> linkat -> unlink -> close in
# its OWN directory (the two-INSERT-items-per-transaction path, stacked with
# xfs_iunlink's insert) with the platter-fossil injector armed
# (iunl_fossil_inject=INJ, inj%5 modes 0-4, re-armed by the counter as it
# drains), and the named victims are virsh-destroyed mid-churn.  The victims'
# log slices therefore end at arbitrary points inside iunlink / iunlink_remove
# / ifree transactions whose iunlink items were applied at sorted precommit,
# and the survivors must foreign-replay them.  The test then asserts:
#   - every survivor finished its ITERS iterations with errs=0 (no -117, no
#     shutdown, no hang past the recovery window),
#   - each victim's slice was replayed: "foreign replay of ... slot N ...
#     complete" present, no "... failed", P163-RECOVERY-COMPLETE >= victims,
#   - zero 'Shutting down filesystem' / 'Corruption of in-memory' / P53 /
#     P-IUNL-INSFAIL / P-AGIFC-MISMATCH on any survivor,
#   - after a clean fleet unmount, chk_mxfs -v reports no AGI-unlinked /
#     AGI-vs-btree error (the SB lazy icount/ifree lines are a separate, open
#     ledger item and are printed but not counted here — say so in the report
#     rather than hiding them).
#
# the budget rule (derived, not padded): per-node mxfs churn measured 15-20 ms/iter at
# 32/caw (sess400 E4-E10) -> ITERS=2000 ~ 30-40 s; a survivor may additionally
# stall on victim-held grants for the 32-node recovery window (~120 s HB
# timeout + fence + replay + purge, measured sess213/386).  The per-node loop
# is bounded at 2x(0.02 s x ITERS) + 120 s; overrunning it IS a FAIL line.
# the unkillable-wedge rule: every remote call bounded; per-node rc files; virsh calls bounded.
# the source-tree rule: lives in tests/.
#
# Usage: tests/tmpfile_churn_kill.sh <label> <victims: testA,testB> [inj=20] [iters=2000] [nodes=32] [--no-prep]
# Env:   TCK_OUT (evidence dir — put it under tests/evidence/, NOT the scratchpad)
#        TCK_KILL_AFTER (s after churn start before the first kill, default 4)
#        TCK_VICTIM_GAP (s between kills, default 5)
#        MXFS_MKFS_OPTS (default "-d 50G": 25 AGs, the shared-AG geometry)
#        TCK_PARAMS / TCK_TEST1_PARAMS (module params on every node / test1 only)
#        TCK_AFTER_KILL_CMD / _DELAY (clyde-side hook after the last kill; it may
#            append hostnames to $TCK_OUT/extra_victims.txt — nodes it killed)
#        TCK_EXTRA_RECOV (s added to the churn budget + recovery bound for arms
#            with a SECOND death, e.g. the prover-kill takeover arm: +70)
#        TCK_RMAN_EXPECT_TERMINAL=1 (fault arms: expect a TERMINAL FSWIDE verdict,
#            nothing replayed/purged) / TCK_RMAN_EXPECT_GUARD=1 (expect >=1
#            P-RMAN-GUARD-REFUSED from the test mutation)
# After the run the victims are restarted (virsh start) but the rig is left
# UNMOUNTED: the next run.sh/prep re-forms the cluster.

LABEL=${1:?label}; VICTIMS=${2:?victims csv}; INJ=${3:-20}; ITERS=${4:-2000}; NODES=${5:-32}
PREP=1; [ "${6:-}" = --no-prep ] && PREP=0
KILL_AFTER=${TCK_KILL_AFTER:-4}; GAP=${TCK_VICTIM_GAP:-5}
cd "$(dirname "$0")/.." || exit 2
OUT=${TCK_OUT:-$(mktemp -d)}; mkdir -p "$OUT"
SSH=tools/mxfs_sshpass.sh
MNT=${MXFS_MNT:-/mnt/shared}
export MXFS_MKFS_OPTS=${MXFS_MKFS_OPTS:--d 50G}
IFS=, read -r -a VIC <<< "$VICTIMS"
is_victim() { local v; for v in "${VIC[@]}"; do [ "$v" = "$1" ] && return 0; done; return 1; }
echo "=== tmpfile_churn_kill label=$LABEL victims=$VICTIMS inj=$INJ iters=$ITERS nodes=$NODES kill_after=${KILL_AFTER}s gap=${GAP}s out=$OUT $(date -u +%FT%TZ) ==="

PY='import os,sys,time,ctypes
d=sys.argv[1]; iters=int(sys.argv[2]); tag=sys.argv[3]
# sess480 ANCHORS.  argv[4] > 0 makes every Nth linked iteration KEEP its name
# instead of unlinking it.  Without this the churn is unreachable by name: a file
# exists as a name only between the linkat and the unlink of one loop iteration,
# so a peer trying to provoke a cluster BAST reads entries=0 every lap -- which
# is why four fault-injection matrices measured nothing.  Separate anchor files
# created before the churn would only be PROBABLY co-located; these come out of
# the churn s OWN allocation stream, so they sit in the churn s own 16 KB inode
# clusters by construction.  Each retained anchor prints its inode so the caller
# can assert co-location arithmetically instead of assuming it.  Default 0 keeps
# the ordinary crash/replay behaviour of this harness unchanged.
anchor_every=int(sys.argv[4]) if len(sys.argv)>4 else 0
libc=ctypes.CDLL(None, use_errno=True); AT_FDCWD=-100; AT_EMPTY_PATH=0x1000
os.makedirs(d, exist_ok=True)
errs=0; t0=time.time(); maxit=0.0; done=0; anchors=0
for i in range(iters):
    ti=time.time()
    try:
        fd=os.open(d, os.O_TMPFILE|os.O_RDWR, 0o644)
    except OSError as e:
        errs+=1; print("ERR open_tmpfile", e, file=sys.stderr, flush=True); continue
    try:
        os.write(fd, b"x"*4096)
        if i % 4 != 3:
            keep = anchor_every > 0 and (i % anchor_every) == 0
            name=os.path.join(d, ("%s.anchor.%d" % (tag, i)) if keep else ("%s.%d" % (tag, i)))
            if libc.linkat(fd, b"", AT_FDCWD, name.encode(), AT_EMPTY_PATH):
                e=ctypes.get_errno(); raise OSError(e, "linkat: "+os.strerror(e))
            if keep:
                anchors+=1
                print("ANCHOR ino=%d name=%s" % (os.stat(name).st_ino, name), flush=True)
            else:
                os.unlink(name)
    except OSError as e:
        errs+=1; print("ERR", e, file=sys.stderr, flush=True)
    os.close(fd)
    done+=1; maxit=max(maxit, time.time()-ti)
    if done % 100 == 0:
        print("progress done=%d t=%.2f maxit=%.3f" % (done, time.time()-t0, maxit), file=sys.stderr, flush=True)
print("wall=%.2f errs=%d done=%d maxit=%.3f anchors=%d" % (time.time()-t0, errs, done, maxit, anchors), flush=True)'
PYB=$(printf '%s' "$PY" | base64 -w0)

t0=$(date +%s)
if [ $PREP = 1 ]; then
	export D385_OUT=$OUT MXFS_KEEP_ARTIFACTS=1
	# sess409: the outer bound must EXCEED d385's inner PREP_TIMEOUT (320 s):
	# a 200 s outer bound killed d385 mid-prep (32-node power-cycle path) and
	# ORPHANED the still-running run.sh prep_cluster, which then formed the
	# cluster underneath the next lap's churn (lap1b: contaminated run).
	D385_STEP="arm_prep TREATMENT" timeout 335 tests/d385_publication_verify.sh 3 $NODES > "$OUT/prep.log" 2>&1
	rc=$?; echo "prep rc=$rc wall=$(( $(date +%s) - t0 ))s  $(grep -m1 'prep_cluster OK\|FAIL' "$OUT/prep.log" | cut -c1-120)"
	[ $rc = 0 ] || { echo "PREP FAILED — see $OUT/prep.log"; exit 3; }
fi

# sess414 (board_20260824T042006Z false release): lap-start ring hygiene for
# the --no-prep path.  arm_prep clears every ring via d385's prep; without it
# the recovery WAIT and the verdict sweep grep CUMULATIVE dmesg, so a prior
# run's "foreign replay ... complete" lines released the WAIT at +21s —
# before heartbeat expiry — and the fleet was unmounted mid-death-window
# (frc=0: a false FAIL shaped exactly like a real no-replay defect).  Clear
# every ring at lap start so every later grep is windowed to THIS lap.
# (Slot mapping below is unaffected: it already reads journald, because the
# prepped path cleared rings long before it.)
if [ $PREP = 0 ]; then
	for i in $(seq 1 $NODES); do ( timeout 15 $SSH test$i "dmesg -C" >/dev/null 2>&1 ) & done; wait
	echo "rings cleared (--no-prep lap): cumulative-grep window starts now"
fi

# knobs + loop script delivery, every node
D=$(mktemp -d)
# sess402: VICTIMS may be "auto:single" / "auto:shared" (or "auto:N" = a slot
# class by number): after prep, read every node's disklock slot (the last
# "disklock: claimed heartbeat slot N" line of this mount) and pick the first
# two nodes whose AG class matches — with 32 nodes on 25 AGs, slots 7-24 are
# SINGLE-owner AGs (AG = slot) and slots 0-6 / 25-31 share AGs 0-6 (two owners:
# slot and slot+25).  kill1 (single-owner victim, slot 13) evaluated held /
# WOULD_APPLY; kill2 (shared-AG victims, slots 30/31) evaluated not_held — the
# two arms must be chosen, not drawn.  test1 (slot 0, the usual elected
# replayer) is never a victim.
if [[ "$VICTIMS" == auto:* ]]; then
    cls=${VICTIMS#auto:}
    SM=$(mktemp -d)
    # prep clears dmesg after the mount, so the claim line is only in journald
    # (sess402: kill4/kill5 found 0 'disklock' lines in dmesg on 32/32 nodes).
    for i in $(seq 1 $NODES); do ( timeout 25 $SSH test$i "(journalctl -k -o cat --since -20min 2>/dev/null; dmesg) | grep -a 'disklock: claimed heartbeat slot' | tail -1 | grep -oE 'slot [0-9]+' | awk '{print \$2}'" 2>/dev/null | grep -av '^Unauthorized\|^Warning:\|^If you' | tr -dc 0-9 > $SM/s$i ) & done; wait
    : > "$OUT/slotmap.txt"; pick=()
    for i in $(seq 1 $NODES); do
        sl=$(cat $SM/s$i); [ -z "$sl" ] && { echo "test$i slot=?" >> "$OUT/slotmap.txt"; continue; }
        if [ "$sl" -ge 7 ] && [ "$sl" -le 24 ]; then c=single; else c=shared; fi
        echo "test$i slot=$sl ag=$(( sl % 25 )) class=$c" >> "$OUT/slotmap.txt"
        [ $i = 1 ] && continue
        # sess459: "auto:slots:A,B" = the nodes holding exactly those two
        # disklock slots (e.g. 25,26 = the sharers of AG 0 / AG 1 with slots
        # 0 / 1, whose slices run numerically ahead — the D-0517 cross-slice
        # LSN-veto reproducer needs the victim's AG blocks stamped by a peer).
        if [[ "$cls" == slots:* ]]; then
            [ ${#pick[@]} -lt 2 ] && [[ ",${cls#slots:}," == *",$sl,"* ]] && pick+=("test$i")
            continue
        fi
        [ ${#pick[@]} -lt 2 ] && { [ "$cls" = "$c" ] || [ "$cls" = "$sl" ]; } && pick+=("test$i")
    done
    [ ${#pick[@]} -eq 2 ] || { echo "FAIL: could not pick 2 victims of class '$cls' — slotmap:"; cat "$OUT/slotmap.txt"; exit 2; }
    VIC=("${pick[@]}"); VICTIMS="${pick[0]},${pick[1]}"
    echo "victims auto-selected ($cls): $(grep -E "^(${pick[0]}|${pick[1]}) " "$OUT/slotmap.txt" | tr '\n' ' ')"
fi

# TCK_PARAMS="name=val name=val": extra module params set on EVERY node after
# prep, each read back; a setter that refuses (e.g. foreign_replay_token_enforce
# fails closed on its F2 prerequisites) shows as SETFAIL and fails the run
# (sess402: the knob=1 foreign-replay capture campaign needs
# target_cache_protected=1 foreign_replay_token_enforce=1, in that order).
PARAMS_CMD=""
for kv in ${TCK_PARAMS:-}; do
    k=${kv%%=*}; v=${kv#*=}
    PARAMS_CMD="$PARAMS_CMD echo $v > /sys/module/mxfs/parameters/$k 2>/dev/null || echo SETFAIL=$k; echo $k=\$(cat /sys/module/mxfs/parameters/$k 2>/dev/null);"
done
# sess406: TCK_TEST1_PARAMS — the same, on test1 ONLY (test1 = slot 0 = the
# usual elected replayer; the rman_test_mutate one-shot knob is consumed there).
PARAMS1_CMD=""
for kv in ${TCK_TEST1_PARAMS:-}; do
    k=${kv%%=*}; v=${kv#*=}
    PARAMS1_CMD="$PARAMS1_CMD echo $v > /sys/module/mxfs/parameters/$k 2>/dev/null || echo SETFAIL=$k; echo $k=\$(cat /sys/module/mxfs/parameters/$k 2>/dev/null);"
done
for i in $(seq 1 $NODES); do P1=""; [ $i = 1 ] && P1="$PARAMS1_CMD"; ( timeout 40 $SSH test$i "echo $PYB | base64 -d > /root/tmpc_kill.py; rm -f /root/tmpc_kill.out /root/tmpc_kill.done; echo 1 > /sys/module/mxfs/parameters/iunl_fossil_fix; echo $INJ > /sys/module/mxfs/parameters/iunl_fossil_inject; $PARAMS_CMD $P1 echo ver=\$(cat /sys/module/mxfs/srcversion) fix=\$(cat /sys/module/mxfs/parameters/iunl_fossil_fix) inj=\$(cat /sys/module/mxfs/parameters/iunl_fossil_inject) m=\$(grep -c ' mxfs ' /proc/mounts)" >$D/t$i 2>/dev/null; echo $? >$D/rc$i ) & done; wait
for i in $(seq 1 $NODES); do echo "test$i rc=$(cat $D/rc$i) $(grep -av '^Unauthorized\|^Warning:\|^If you' $D/t$i | tr '\n' ' ')"; done > "$OUT/knobs.txt"
mounted=$(grep -c 'm=1' "$OUT/knobs.txt")
echo "knobs: $mounted/$NODES mounted, versions: $(grep -oE 'ver=[0-9A-F]+' "$OUT/knobs.txt" | sort | uniq -c | tr '\n' ' ')"
# sess406: a node that is not mounted churns on its LOCAL root under $MNT and
# "completes" trivially (kill6d: knobs 27/32 mounted, survivors_complete=30/30).
# Prep's contract is a 32/32 cluster; anything less is a FAIL, not a discount.
if [ "$mounted" != "$NODES" ]; then echo "FAIL: only $mounted/$NODES nodes mounted after prep — see $OUT/knobs.txt"; exit 2; fi
if [ -n "${TCK_PARAMS:-}${TCK_TEST1_PARAMS:-}" ]; then
    echo "params: $(grep -oE '(SETFAIL=[a-z_]+|[a-z_]+=[0-9]+)' "$OUT/knobs.txt" | grep -vE '^(ver|fix|inj|m)=' | sort | uniq -c | tr '\n' ' ')"
    if grep -q SETFAIL "$OUT/knobs.txt"; then echo "FAIL: TCK_PARAMS setter refused on some node(s) — see $OUT/knobs.txt"; exit 2; fi
fi

# churn: detached on every node (nohup), bounded by the derived budget
BUDGET=$(python3 -c "print(int(2*0.02*$ITERS + 120 + ${TCK_EXTRA_RECOV:-0} + 0.999))")
t1=$(date +%s)
# sess480: ANCHOR_EVERY auto-arms whenever a relgate stage is armed, because that
# is exactly the case where the peer must be able to BAST the victim's inode
# cluster and the churn's own files are otherwise nameless.  It stays 0 (off) for
# every ordinary crash/replay use of this harness, so their behaviour is unchanged.
ANCHOR_EVERY=${TCK_ANCHOR_EVERY:-0}
if [ "$ANCHOR_EVERY" = 0 ] && [[ "${TCK_PARAMS:-}" == *relgate_fault_stage=* ]]; then
    ANCHOR_EVERY=64
fi
echo "anchors: TCK_ANCHOR_EVERY=$ANCHOR_EVERY (every Nth linked churn file keeps its name; 0 = off)"
for i in $(seq 1 $NODES); do ( timeout 20 $SSH test$i "nohup sh -c 'timeout $BUDGET python3 /root/tmpc_kill.py $MNT/tmpfile_churn/test$i $ITERS test$i $ANCHOR_EVERY > /root/tmpc_kill.out 2>&1; echo rc=\$? >> /root/tmpc_kill.out; touch /root/tmpc_kill.done' >/dev/null 2>&1 &" >/dev/null 2>&1; echo $? >$D/start$i ) & done; wait
echo "churn started on $(grep -c '^0$' $D/start* )/$NODES nodes (budget ${BUDGET}s/node) at +$(( $(date +%s) - t0 ))s"

# sess461: TCK_PREKILL_GREP — a kernel-log pattern read from EACH VICTIM in
# the moment before its virsh destroy.  The nodes' journald is volatile
# (/run/log/journal; trap sess433), so anything the victim printed before the
# kill is gone with the VM — the sess448 relmark fault matrix (stages 19-21
# fire on the RELEASING node, which under a kill arm IS the victim) read
# 'P282 sum=0' fleet-wide for four arms because the only node that could have
# printed the line was the one being destroyed.  The probe also reads the
# relgate stage knob back (oneshot: armed N -> 0 after the hit).  Bounded
# (12 s); output $OUT/prekill_<victim>.txt; summary on stdout + kills.txt.
# Unset = no probe (kill timing unchanged for every other user).
PREKILL_GREP=${TCK_PREKILL_GREP:-}
if [ -z "$PREKILL_GREP" ] && [[ "${TCK_PARAMS:-}" == *relgate_fault_stage=* ]]; then
	PREKILL_GREP='P282-RELGATE-FAULT\|P-RELMARK-ICLUS-\|P-ICLUS-WEDGE\|P283-'
fi
# sess467: TCK_PREKILL_RELEASE — chain 89's probes (sess461 discriminator)
# read iclus_marked=0 iclus_failed=0 P282=0 on EVERY victim before its kill:
# the churn alone never makes the victim RELEASE its cluster grant, so
# mxfs_iclus_disk_release's marker block (where relgate stages 19-21 sit) is
# never entered before the destroy — hypothesis H1 confirmed, H2 (the hits
# died with the VM) refuted.  Force the release: a PEER reads the victim's
# churn directory and stats its live files (a PR acquire on routed inodes ->
# BAST -> the victim's cluster EX is released through the marker block), three
# laps 0.7 s apart so the transient linkat/unlink names are caught live, then
# a 2 s settle before the probe.  Adds ~5 s per victim before its kill (noted
# in kills.txt).  Auto-armed with the stage knob; TCK_PREKILL_RELEASE=0 disables.
PREKILL_RELEASE=${TCK_PREKILL_RELEASE:-}
if [ -z "$PREKILL_RELEASE" ] && [[ "${TCK_PARAMS:-}" == *relgate_fault_stage=* ]]; then
	PREKILL_RELEASE=1
fi

# kill the victims once writes are confirmed in flight
sleep "$KILL_AFTER"
for v in "${VIC[@]}"; do
	prog=$(timeout 10 $SSH "$v" "tail -1 /root/tmpc_kill.out 2>/dev/null" 2>/dev/null | grep -av '^Unauthorized\|^Warning:\|^If you' | tr -d '\r')
	if [ "$PREKILL_RELEASE" = 1 ]; then
		peer=""
		for i in $(seq 1 $NODES); do is_victim "test$i" || { peer="test$i"; break; }; done
		timeout 20 $SSH "$peer" "for k in 1 2 3; do n=\$(ls -1 $MNT/tmpfile_churn/$v/ 2>/dev/null | wc -l); s=0; for f in $MNT/tmpfile_churn/$v/*; do [ -e \"\$f\" ] && stat -c %s \"\$f\" >/dev/null 2>&1 && s=\$((s+1)); done; echo lap=\$k entries=\$n statted=\$s; sleep 0.7; done" 2>/dev/null | grep -av '^Unauthorized\|^Warning:\|^If you' > "$OUT/prekill_release_$v.txt"
		echo "PREKILL-RELEASE $v via $peer: $(tr '\n' ' ' < "$OUT/prekill_release_$v.txt")" | tee -a "$OUT/kills.txt"
		# sess480 CO-LOCATION WITNESS.  The peer's stat only provokes the
		# release we need if it lands on the SAME 16 KB inode cluster the
		# victim is churning, and "probably co-located" is exactly the kind
		# of assumption that produced four matrices of nothing.  The churn
		# now retains every Nth of its OWN files as a named anchor, so the
		# anchors are in the churn's own clusters by construction; print
		# their inodes next to a sample of the churn's, so the evidence
		# shows co-location rather than asserting it.  A run with zero
		# anchors is announced here, before the probe, not diagnosed later.
		anch=$(timeout 15 $SSH "$v" "grep -a '^ANCHOR ino=' /root/tmpc_kill.out 2>/dev/null | tail -6" 2>/dev/null | grep -av '^Unauthorized\|^Warning:\|^If you' | tr '\n' ' ')
		echo "  PREKILL-ANCHORS $v: ${anch:-<none>}" | tee -a "$OUT/kills.txt"
		if [ -z "$anch" ]; then
			echo "  PREKILL-ANCHORS $v: WARNING no named anchors — the peer had nothing to stat, so no BAST and no cluster release; the arm below will be vacuous." | tee -a "$OUT/kills.txt"
		fi
		# sess479: the peer-side ls above CANNOT work and never has.  The
		# churn is O_TMPFILE -> write -> linkat -> unlink -> close, so a
		# file carries a name only between the linkat and the unlink of one
		# loop iteration; three ls laps 0.7 s apart read entries=0 on every
		# victim of every arm in chains 85/89/100.  No PR acquire, no BAST,
		# no release, so the relgate stages inside mxfs_iclus_disk_release
		# were never reached and three matrices of "PASS" measured nothing.
		# Drive the release from the VICTIM instead, where it needs no race:
		# sync, then drop the caches, which evicts the churn inodes and runs
		# the cluster release -- and its marker block -- with the stage armed.
		timeout 30 $SSH "$v" "sync; echo 2 > /proc/sys/vm/drop_caches 2>/dev/null; echo DROPPED rc=\$?" 2>/dev/null | grep -a DROPPED | sed "s/^/  PREKILL-EVICT $v: /" | tee -a "$OUT/kills.txt"
		sleep 2
		sleep 2
	fi
	if [ -n "$PREKILL_GREP" ]; then
		timeout 12 $SSH "$v" "echo stage=\$(cat /sys/module/mxfs/parameters/relgate_fault_stage 2>/dev/null) force=\$(cat /sys/module/mxfs/parameters/relgate_fault_force 2>/dev/null) oneshot=\$(cat /sys/module/mxfs/parameters/relgate_fault_oneshot 2>/dev/null) \$(grep -a -A11 '^relmark' /sys/kernel/debug/mxfs/*/inode_authority 2>/dev/null | grep -a 'iclus_\|published' | awk '{printf \"%s=%s \", \$1, \$2}'); journalctl -k -o short-precise --since -20min --no-pager 2>/dev/null | grep -a '$PREKILL_GREP' | tail -40" 2>/dev/null | grep -av '^Unauthorized access\|^Warning: Permanently\|^If you are not' > "$OUT/prekill_$v.txt"
		prc=${PIPESTATUS[0]}
		echo "PREKILL $v rc=$prc $(head -1 "$OUT/prekill_$v.txt") P282=$(grep -ac 'P282-RELGATE-FAULT' "$OUT/prekill_$v.txt") lines=$(grep -ac . "$OUT/prekill_$v.txt")" | tee -a "$OUT/kills.txt"
	fi
	echo "KILL $v at +$(( $(date +%s) - t1 ))s into churn (victim progress: ${prog:-none}) $(date -u +%FT%T.%3NZ)" | tee -a "$OUT/kills.txt"
	timeout 60 sudo virsh -c qemu:///system destroy "$v" >> "$OUT/kills.txt" 2>&1 || echo "  WARN: virsh destroy $v rc=$?" | tee -a "$OUT/kills.txt"
	sleep "$GAP"
done

# sess405: optional post-kill hook (fault-injection arms).  TCK_AFTER_KILL_CMD
# runs ON CLYDE, TCK_AFTER_KILL_DELAY seconds after the last kill, e.g.
#   TCK_AFTER_KILL_CMD="tests/fleet_set_params.sh rman_inject=0 32" TCK_AFTER_KILL_DELAY=80
# to clear an injected prover fault once the first snapshot attempt has
# provably failed (62 s HB expiry + fence + first attempt).  Output lands in
# $OUT/afterkill.txt; the hook is waited for before the sweep.
AK_PID=""
if [ -n "${TCK_AFTER_KILL_CMD:-}" ]; then
	( sleep "${TCK_AFTER_KILL_DELAY:-80}"; echo "afterkill @+$(( $(date +%s) - t1 ))s: $TCK_AFTER_KILL_CMD"; timeout 120 bash -c "$TCK_AFTER_KILL_CMD"; echo "afterkill rc=$?" ) > "$OUT/afterkill.txt" 2>&1 &
	AK_PID=$!
	echo "afterkill hook armed: +${TCK_AFTER_KILL_DELAY:-80}s: $TCK_AFTER_KILL_CMD"
fi

# sess406: the after-kill hook may kill more nodes (the prover-kill takeover
# arm); it records them in $OUT/extra_victims.txt and they become victims for
# every assertion below (survivor counting, replay count, sweep, unmount).
load_extra_victims() {
	local v
	[ -f "$OUT/extra_victims.txt" ] || return 0
	while read -r v; do
		[ -n "$v" ] || continue
		is_victim "$v" || { VIC+=("$v"); echo "extra victim (after-kill hook): $v"; }
	done < "$OUT/extra_victims.txt"
}
# wait for every survivor's loop to finish (bounded by BUDGET from churn start)
while :; do
	left=0; now=$(date +%s)
	load_extra_victims
	for i in $(seq 1 $NODES); do
		is_victim test$i && continue
		[ -f "$D/done$i" ] && continue
		if timeout 8 $SSH test$i "test -f /root/tmpc_kill.done" >/dev/null 2>&1; then touch "$D/done$i"; else left=$((left+1)); fi
	done
	[ $left = 0 ] && break
	if [ $(( now - t1 )) -gt $(( BUDGET + 30 )) ]; then echo "WAIT EXPIRED: $left survivor loop(s) not done after $(( now - t1 ))s"; break; fi
	sleep 10
done
echo "survivor loops done after $(( $(date +%s) - t1 ))s"

# collect per-survivor churn results
for i in $(seq 1 $NODES); do is_victim test$i && continue; ( timeout 20 $SSH test$i "grep -E 'wall=|rc=|ERR' /root/tmpc_kill.out | tail -4 | tr '\n' ' '" >$D/res$i 2>/dev/null ) & done; wait
for i in $(seq 1 $NODES); do is_victim test$i && { echo "test$i VICTIM"; continue; }; echo "test$i $(grep -av '^Unauthorized\|^Warning:\|^If you' $D/res$i)"; done > "$OUT/churn.txt"
ok=$(grep -cE "done=$ITERS .*rc=0|errs=0 done=$ITERS" "$OUT/churn.txt")
echo "churn: survivors_complete=$ok/$(( NODES - ${#VIC[@]} ))  $(grep -vE "VICTIM|errs=0 done=$ITERS" "$OUT/churn.txt" | head -5 | tr '\n' ';')"

# sess402: WAIT FOR RECOVERY before sweeping/unmounting.  kill3 (inj=0) finished
# its churn in 30 s and unmounted the fleet BEFORE the victims' heartbeats
# expired (31 checks ~62 s) — no replay ever ran and the oracle then blamed
# the victims' un-replayed in-flight txns (AG 20 AGI +1).  Bound derived:
# heartbeat expiry 62 s + fence + elect + replay (<=30 s measured) = 95 s
# after the LAST kill; poll every 5 s for a terminal replay line per victim.
last_kill=$(( t1 + KILL_AFTER + (${#VIC[@]} - 1) * GAP + 5 ))
RECOV_BOUND=$(( ${TCK_RECOV_BOUND:-95} + ${TCK_EXTRA_RECOV:-0} ))
while :; do
	now=$(date +%s)
	seen=0
	load_extra_victims
	for i in $(seq 1 $NODES); do
		is_victim test$i && continue
		# sess408: under an FSWIDE terminal (0.26.4 D-FSWIDE-407 halt) the
		# remaining victims are deliberately NEVER claimed — their terminal
		# outcome is the P-RMAN-FSWIDE-HALT line (one per slot, ratelimited),
		# not a replay complete/failed line.  Count it, or every terminal arm
		# idles the full RECOV_BOUND for a replay that must not happen.
		( timeout 8 $SSH test$i "dmesg | grep -c 'foreign replay of slot .* \(complete\|failed\)\|P-RMAN-FSWIDE-HALT foreign replay slot='" 2>/dev/null | grep -av '^Unauthorized\|^Warning:\|^If you' | tail -1 > $D/fr$i ) &
	done; wait
	for i in $(seq 1 $NODES); do is_victim test$i && continue; v=$(cat $D/fr$i 2>/dev/null | tr -dc 0-9); seen=$(( seen + ${v:-0} )); done
	if [ "$seen" -ge "${#VIC[@]}" ]; then echo "WAIT recovery: $seen terminal replay line(s) for ${#VIC[@]} victim(s) at +$(( now - last_kill ))s after last kill"; break; fi
	if [ $(( now - last_kill )) -ge "$RECOV_BOUND" ]; then echo "WAIT EXPIRED: only $seen terminal replay line(s) for ${#VIC[@]} victim(s) ${RECOV_BOUND}s after the last kill"; break; fi
	sleep 5
done

# survivor dmesg sweep — recovery markers + kill-class probes
[ -n "$AK_PID" ] && { wait "$AK_PID"; echo "afterkill: $(grep -E 'afterkill|params:|FAIL|prover_kill' "$OUT/afterkill.txt" | tr '\n' ' ' | cut -c1-400)"; }
load_extra_victims
sleep 5
# sess414 fail-closed sweep (false-FAIL root, board_20260824T040959Z): five
# survivors' sweep ssh calls timed out (rc=124) under post-churn load and
# their counters were silently summed as ZERO — frc=0 while test1's ring
# carried BOTH victims' "foreign replay ... complete" lines (false FAIL);
# the same gap can equally hide a real shutdown/corruption on an unreported
# node (false PASS).  The command is hoisted so the retry pass runs the
# identical sweep; any survivor still unreported after one retry FAILS the
# lap as SWEEP-INCOMPLETE — an evidence gap is a verdict, never a zero.
TCK_SWEEP_CMD="TR=/tmp/tck_ring; dmesg > \$TR 2>/dev/null; echo rcpl=\$(grep -ac 'P163-RECOVERY-COMPLETE' \$TR) frc=\$(grep -ac 'foreign replay of .*complete' \$TR) frf=\$(grep -ac 'foreign replay of .*failed' \$TR) sd=\$(grep -ac 'Shutting down' \$TR) dc=\$(grep -ac 'Corruption of in-memory' \$TR) p53=\$(grep -ac 'P53-IUNLINK-MISMATCH' \$TR) insf=\$(grep -ac 'P-IUNL-INSFAIL' \$TR) pif=\$(grep -ac 'P-IUNL-PRECOMMIT-INSERT-FOSSIL' \$TR) fe=\$(grep -ac 'P-IUNL-FOSSIL-ENTRY' \$TR) ij=\$(grep -ac 'P-IUNL-FOSSIL-INJECT' \$TR) am=\$(grep -ac 'P-AGIFC-MISMATCH' \$TR) ar=\$(grep -ac 'P-AGIFC-RELEASE-MISMATCH' \$TR) ie=\$(grep -ac 'Internal error' \$TR) d117=\$(grep -ac 'err=-117' \$TR) p84=\$(grep -ac 'P84-UNL-RELOAD-LIVE' \$TR) adm=\$(grep -ac 'P227-FR-ENFORCE-ADMIT' \$TR) red=\$(grep -ac 'P227-FR-REDUNDANT-SKIP' \$TR) ref=\$(grep -ac 'POLICY-REFUSED' \$TR) quar=\$(grep -ac 'P240-QUAR-IMPORT' \$TR) nh=\$(grep -ac 'P-VMAN-NOTHELD' \$TR) askip=\$(grep -ac 'P227-FR-ATOMIC-SKIP' \$TR) rseal=\$(grep -ac 'P-RMAN-SEALED' \$TR) rsnap=\$(grep -ac 'P-RMAN-SNAPSHOT slot' \$TR) rload=\$(grep -ac 'P-RMAN-LOAD victim' \$TR) rinv=\$(grep -ac 'P-RMAN-INVALID' \$TR) rpost=\$(grep -ac 'P-RMAN-POSTSEAL-MUTATION' \$TR) rabort=\$(grep -ac 'P-RMAN-ABORT\\|P-RMAN-LOAD-ABORT' \$TR) rpend=\$(grep -ac 'P-RMAN-SNAPSHOT-PENDING' \$TR) rtake=\$(grep -ac 'P-RMAN-SNAPSHOT-TAKEOVER' \$TR) rlive=\$(grep -ac 'P-RMAN-LIVECHECK-ERR' \$TR) rguard=\$(grep -ac 'P-RMAN-GUARD-REFUSED' \$TR) rterm=\$(grep -ac 'P-RMAN-MUTATED-TERMINAL\\|P-RMAN-INVALID-TERMINAL' \$TR) rtm=\$(grep -ac 'P-RMAN-TEST-MUTATE' \$TR) rpv=\$(grep -ac 'P-RMAN-PREPURGE-VERIFY' \$TR) rbusy=\$(grep -ac 'P304-FENCE-PROVE-BUSY' \$TR) m=\$(grep -c ' mxfs ' /proc/mounts); grep -aE 'foreign replay of|P163-RECOVERY-COMPLETE|Shutting down|Corruption of in-memory|P53-IUNLINK-MISMATCH|P-IUNL-INSFAIL|Internal error|P273-SHADOW-EVAL|P-VMAN-NOTHELD|POLICY-REFUSED|P-RELMARK|P-RMAN-' \$TR | head -24 | cut -c1-600; grep -a -B4 -A1 'P-AGIFC-MISMATCH\\|P-AGIFC-RELEASE-MISMATCH' \$TR | head -60 | cut -c1-400"
for i in $(seq 1 $NODES); do is_victim test$i && continue; ( timeout 60 $SSH test$i "$TCK_SWEEP_CMD" >$D/s$i 2>/dev/null; echo $? >$D/src$i ) & done; wait
for i in $(seq 1 $NODES); do
    is_victim test$i && continue
    [ "$(cat $D/src$i 2>/dev/null)" = "0" ] && continue
    ( timeout 60 $SSH test$i "$TCK_SWEEP_CMD" >$D/s$i 2>/dev/null; echo $? >$D/src$i ) &
done; wait
SWEEP_MISSING=""
for i in $(seq 1 $NODES); do
    is_victim test$i && continue
    [ "$(cat $D/src$i 2>/dev/null)" = "0" ] || SWEEP_MISSING="$SWEEP_MISSING test$i"
done
# sess408: the AGIFC mismatch lines (counted as am=/ar=) are now PRINTED too
# (with 4 lines of context each, cap 60/node): base_shared on 0.26.4 had am=3
# on the replayer and chk found AG 6 AGI freecount 61 vs inobt 62, but the
# node was rebooted as a later arm's victim before anyone read its journal —
# the three lines that would have named the site were lost.  arm_prep runs
# dmesg -C, so sweep.txt is the ONLY durable capture.
for i in $(seq 1 $NODES); do is_victim test$i && continue; echo "test$i rc=$(cat $D/src$i) $(grep -av '^Unauthorized\|^Warning:\|^If you' $D/s$i | head -1)"; grep -av '^Unauthorized\|^Warning:\|^If you' $D/s$i | tail -n +2 | sed 's/^/    /'; done > "$OUT/sweep.txt"
# sess446 (board 20260829T113042Z single lap, 0.53.0): the second victim's
# (slot 24) foreign replay never started within RECOV_BOUND and the lap hit
# its bound; by the time anyone looked the nodes had been re-prepped and the
# volatile journals were gone — the sweep's counters were the only record.
# Keep every survivor's RECOVERY TRAIL (election, lease, fence, manifest,
# snapshot, replay, completion) from journald, per node, so the next such
# lap names the stage the second victim stalled at.
for i in $(seq 1 $NODES); do is_victim test$i && continue; ( timeout 40 $SSH test$i "journalctl -k -o short-precise --since -20min --no-pager 2>/dev/null | grep -a 'P238-RECOV\|P163-\|P-FRSTAB\|foreign replay\|P236-FENCE\|P-RMAN-PROTECT\|P-RMAN-SEALED\|P-RMAN-SNAPSHOT\|P304-FENCE\|P-DEAD-INC\|no longer responding\|elected\|ELECT\|P240-QUAR\|P226-\|barrier\|P-FREPLAY-\|P97-SWEEP\|P-DBG-SWEEP\|P285-F4\|P-DOMAIN-'" 2>/dev/null | grep -av '^Unauthorized\|^Warning:\|^If you' > "$OUT/recov_test$i.txt" ) & done; wait
echo "recovery trail: $(cat "$OUT"/recov_test*.txt 2>/dev/null | wc -l) lines kept in $OUT/recov_testN.txt"
sum() { grep -oE " $1=[0-9]+" "$OUT/sweep.txt" | cut -d= -f2 | awk '{s+=$1} END {print s+0}'; }
echo "sweep: rcpl=$(sum rcpl) frc=$(sum frc) frf=$(sum frf) sd=$(sum sd) dc=$(sum dc) p53=$(sum p53) insf=$(sum insf) pif=$(sum pif) fe=$(sum fe) ij=$(sum ij) am=$(sum am) ar=$(sum ar) ie=$(sum ie) d117=$(sum d117) p84=$(sum p84)"
# sess403: replay-gate disposition (REDUNDANT_CLEAN certificate A/B): ADMIT /
# redundant-skip / refusal / quarantine / not_held counts, plus the per-replay
# P273-SHADOW-EVAL summary lines (REDUNDANT_CLEAN=, relmarks=).
echo "gate:  admit=$(sum adm) redundant_skip=$(sum red) policy_refused=$(sum ref) quarantine=$(sum quar) vman_notheld=$(sum nh) atomic_skip=$(sum askip)"
# sess405 (docs/recovery-manifest.md): fence-time manifest markers — prover
# seal/snapshot, replayer load, and the three invariant breakers that FAIL.
echo "rman:  sealed=$(sum rseal) snapshot=$(sum rsnap) load=$(sum rload) invalid=$(sum rinv) postseal_mutation=$(sum rpost) abort=$(sum rabort) livecheck_err=$(sum rlive) snapshot_pending=$(sum rpend) snapshot_takeover=$(sum rtake) guard_refused=$(sum rguard) terminal=$(sum rterm) test_mutate=$(sum rtm) prepurge_verify=$(sum rpv) prove_busy=$(sum rbusy)"
grep -E 'foreign replay of' "$OUT/sweep.txt" | head -8
grep -E 'P273-SHADOW-EVAL' "$OUT/sweep.txt" | grep -oE 'victim_slot=[0-9]+ capable=[0-9].*' | cut -c1-400 | head -6
grep -E 'P-RMAN-EVAL|P-RMAN-SNAPSHOT slot|P-RMAN-SEALED' "$OUT/sweep.txt" | grep -oE 'P-RMAN-.*' | cut -c1-300 | head -8
# sess409 (D-FREPLAY-VICTIM-INODE-CORE-NOT-APPLIED-BUCKET-TO-ZERO-CORE-408):
# with instr=1 the replayer logs one P77-FRINODE verdict per foreign inode
# image (disk/log changecount, mode, gen).  Capture them (cap 4000/node) and
# summarize: apply/skip totals and the suspicious shape — an ALLOCATED image
# SKIPPED over a FREE platter core of a DIFFERENT gen (a reincarnation's
# creation judged older than the previous incarnation's freed core).  Post-fix
# that shape can still be legitimate (the dead node's old image of an
# incarnation that a peer has since freed again), so it is REPORTED; the
# decisive oracle is chk_mxfs (bucket->free core, inobt-allocated free core).
for i in $(seq 1 $NODES); do is_victim test$i && continue; ( timeout 40 $SSH test$i "dmesg | grep -a 'P77-FRINODE' | head -4000 | cut -c1-300" >$D/p77_$i 2>/dev/null ) & done; wait
: > "$OUT/p77.txt"; for i in $(seq 1 $NODES); do is_victim test$i && continue; grep -a 'P77-FRINODE' $D/p77_$i | sed "s/^/test$i /" >> "$OUT/p77.txt"; done
p77n=$(grep -c P77-FRINODE "$OUT/p77.txt"); p77a=$(grep -c 'verdict=APPLY' "$OUT/p77.txt"); p77s=$(grep -c 'verdict=SKIP' "$OUT/p77.txt")
p77x=$(grep 'verdict=SKIP' "$OUT/p77.txt" | grep 'disk_mode=0 ' | grep -v 'log_mode=0 ' | awk '{for(i=1;i<=NF;i++){if($i~/^disk_gen=/)dg=$i;if($i~/^log_gen=/)lg=$i}; if(substr(dg,10)!=substr(lg,9))print}' | wc -l)
echo "p77:   lines=$p77n apply=$p77a skip=$p77s skip_alloc_over_free_diffgen=$p77x  (instr=1 only; details $OUT/p77.txt)"
[ "$p77x" -gt 0 ] && grep 'verdict=SKIP' "$OUT/p77.txt" | grep 'disk_mode=0 ' | grep -v 'log_mode=0 ' | head -4 | cut -c1-240

# clean fleet unmount (survivors), then the platter oracle
t2=$(date +%s)
for i in $(seq 1 $NODES); do is_victim test$i && continue; ( timeout 160 $SSH test$i "timeout 150 umount $MNT; echo rc=\$? m=\$(grep -c ' mxfs ' /proc/mounts)" >$D/u$i 2>/dev/null; echo $? >$D/urc$i ) & done; wait
for i in $(seq 1 $NODES); do is_victim test$i && continue; echo "test$i ssh_rc=$(cat $D/urc$i) $(grep -av '^Unauthorized\|^Warning:\|^If you' $D/u$i | tr '\n' ' ')"; done > "$OUT/umount.txt"
echo "umount: wall=$(( $(date +%s) - t2 ))s unmounted=$(grep -c ' m=0' "$OUT/umount.txt")/$(( NODES - ${#VIC[@]} )) still_mounted=$(grep -v ' m=0' "$OUT/umount.txt" | awk '{print $1}' | tr '\n' ' ')"
HOST_IMG=$(tools/mxfs_host_image.sh) || { echo "$HOST_IMG"; exit 2; }
timeout 240 tools/chk_mxfs -v "$HOST_IMG" > "$OUT/chk.txt" 2>&1
chkrc=$?
chk_err=$(grep -c 'ERROR' "$OUT/chk.txt")
chk_sb=$(grep -c 'ERROR.*\(icount\|ifree\)' "$OUT/chk.txt")
echo "chk rc=$chkrc errors=$chk_err (of which SB lazy icount/ifree=$chk_sb)  $(grep 'ERROR' "$OUT/chk.txt" | grep -v 'icount\|ifree' | head -4 | tr '\n' ';')"

# restart the victims so the next prep finds 32 VMs
for v in "${VIC[@]}"; do timeout 60 sudo virsh -c qemu:///system start "$v" >/dev/null 2>&1; echo "restart $v rc=$?"; done | tee -a "$OUT/kills.txt"

# verdict
fail=0
[ -z "$SWEEP_MISSING" ] || { echo "FAIL: SWEEP-INCOMPLETE — no counter report from:$SWEEP_MISSING (evidence gap, fail-closed)"; fail=1; }
TERMINAL=${TCK_RMAN_EXPECT_TERMINAL:-0}
if [ "$TERMINAL" = 1 ]; then
    # sess406 (docs/recovery-manifest.md step 6, fault arms rman_inject=3 /
    # rman_test_mutate=2): the elected replayer must publish a TERMINAL FSWIDE
    # refusal (MANIFEST_INVALID / AUTHORITY_MUTATED) and NOTHING may be replayed
    # or purged.  Survivors import the verdict (P240-QUAR-IMPORT) and fail
    # acquires into the quarantined domain with -EIO — so their churn may be
    # incomplete, the victims' slices stay un-replayed and the platter oracle
    # reports them; those three are REPORTED here, not counted.  Everything else
    # (shutdown, in-core corruption, P53, guard refusals) stays a FAIL.
    [ "$(sum rterm)" -ge 1 ] || { echo "FAIL: expected a TERMINAL verdict (P-RMAN-MUTATED-TERMINAL/INVALID-TERMINAL), saw terminal=$(sum rterm)"; fail=1; }
    [ "$(sum quar)" -ge 1 ] || { echo "FAIL: no survivor imported the terminal verdict (P240-QUAR-IMPORT=$(sum quar))"; fail=1; }
    # sess407 design-consult ruling (GPT): an FSWIDE TERMINAL must stop EVERY further
    # replay on the filesystem — a second victim's intact slice completing after
    # it (mutate2 on 0.26.2: slot 12 MUTATED-TERMINAL, slot 17 complete 5 s later
    # on the same replayer) is a defect (D-FSWIDE-TERMINAL-REPLAY-CONTINUES-407),
    # not a per-victim outcome.  frc must be 0.
    [ "$(sum frc)" = 0 ] || { echo "FAIL: a victim slice was replayed to completion under a TERMINAL verdict (frc=$(sum frc)) — FSWIDE terminal did not halt replay"; fail=1; }
    echo "terminal arm: survivors_complete=$ok/$(( NODES - ${#VIC[@]} )) frc=$(sum frc) frf=$(sum frf) quar=$(sum quar) ref=$(sum ref) chk_non_sb=$(( chk_err - chk_sb )) (reported, not counted)"
else
    # sess407: -ge, not =: an after-kill extra victim (takeover arm's prover)
    # that finished its churn before it died still counts among the completes.
    [ "$ok" -ge $(( NODES - ${#VIC[@]} )) ] || { echo "FAIL: only $ok survivors completed $ITERS iterations with errs=0 (need $(( NODES - ${#VIC[@]} )))"; fail=1; }
    [ "$(sum frf)" = 0 ] || { echo "FAIL: foreign replay FAILED lines=$(sum frf)"; fail=1; }
    [ "$(sum frc)" -ge ${#VIC[@]} ] || { echo "FAIL: foreign replay complete lines=$(sum frc) < victims=${#VIC[@]}"; fail=1; }
    # sess403: a refused replay / quarantine import on any survivor is a FAIL in
    # its own right (D-402 symptom) even when every survivor's churn completed.
    for k in ref quar; do [ "$(sum $k)" = 0 ] || { echo "FAIL: $k=$(sum $k) (replay refused / victim domain quarantined)"; fail=1; }; done
    # sess405: a manifest that failed validation, a post-seal mutation, a
    # live-check failure or an attempt abort is a FAIL; every victim sealed.
    for k in rinv rpost rabort rlive rterm; do [ "$(sum $k)" = 0 ] || { echo "FAIL: $k=$(sum $k) (fence-time manifest invariant)"; fail=1; }; done
    [ "$(sum rseal)" -ge ${#VIC[@]} ] || { echo "FAIL: P-RMAN-SEALED lines=$(sum rseal) < victims=${#VIC[@]}"; fail=1; }
    [ $(( chk_err - chk_sb )) = 0 ] || { echo "FAIL: chk_mxfs non-SB errors=$(( chk_err - chk_sb ))"; fail=1; }
fi
for k in sd dc p53 insf am ar ie; do [ "$(sum $k)" = 0 ] || { echo "FAIL: $k=$(sum $k) on survivors"; fail=1; }; done
# sess405 review item 1: a guard refusal on any run is itself the defect signal
# (no live path may clear a foreign EX/PW bit) — unless this arm injected one
# (TCK_RMAN_EXPECT_GUARD=1: rman_test_mutate=1 must be refused exactly so).
if [ "${TCK_RMAN_EXPECT_GUARD:-0}" = 1 ]; then
    [ "$(sum rguard)" -ge 1 ] || { echo "FAIL: expected the guard to refuse the test mutation, saw guard_refused=$(sum rguard) test_mutate=$(sum rtm)"; fail=1; }
    [ "$(sum rtm)" -ge 1 ] || { echo "FAIL: the test mutation never ran (P-RMAN-TEST-MUTATE=$(sum rtm))"; fail=1; }
else
    [ "$(sum rguard)" = 0 ] || { echo "FAIL: guard_refused=$(sum rguard) — a live path tried to clear a protected EX/PW bit"; fail=1; }
fi
# sess406 (D-FENCE-RETRY-PROVE-BUSY-SPIN-406): with rman_inject=4 the prover is
# held 30 s and the retry worker is forced onto it; the busy guard must be hit
# (>=1) but with backoff, not once per 250 ms tick (<=10 per prover, 2 provers).
maxn() { grep -oE " $1=[0-9]+" "$OUT/sweep.txt" | cut -d= -f2 | sort -n | tail -1; }
if [ "${TCK_RMAN_EXPECT_BUSY:-0}" = 1 ]; then
    # 12 s hold, backoff 250/500/1000/2000/4000 ms -> <= 5 firings per prover
    # (a 250 ms spin would be ~48); the hold is on the heartbeat thread, so the
    # held prover must NOT itself have been fenced: exactly the victims sealed.
    [ "$(sum rbusy)" -ge 1 ] || { echo "FAIL: expected the retry worker to hit the busy prover (P304-FENCE-PROVE-BUSY=$(sum rbusy)) — the arm did not exercise the cause"; fail=1; }
    [ "$(maxn rbusy)" -le 8 ] || { echo "FAIL: P304-FENCE-PROVE-BUSY max per node=$(maxn rbusy) > 8 — the retry worker is spinning on the busy guard, not backing off"; fail=1; }
    [ "$(sum rseal)" = ${#VIC[@]} ] || { echo "FAIL: sealed=$(sum rseal) != victims=${#VIC[@]} under the prover hold — a held prover was fenced by its peers?"; fail=1; }
fi
# sess479 VACUITY GATE.  Chains 85, 89 and 100 each ran this matrix with a
# relgate stage armed, and each reported VERDICT PASS on every arm while the
# injection never fired once: every victim probe read iclus_marked=0
# iclus_unmarked=0 iclus_failed=0 P282=0, and the fleet P282 sum was 0.  Three
# runs of "evidence" that measured nothing, recorded as passes.  A PASS from an
# arm whose fault was never injected is worse than a FAIL: it is a fix-shaped
# hole in the record.  If a stage is armed, the marker block must be shown to
# have been entered; otherwise this arm is VACUOUS and says nothing.
if [[ "${TCK_PARAMS:-}" == *relgate_fault_stage=* ]]; then
    hits=0
    for v in "${VIC[@]}"; do
        p="$OUT/prekill_$v.txt"; [ -s "$p" ] || continue
        for k in iclus_marked iclus_unmarked iclus_failed; do
            n=$(grep -ao "$k=[0-9]*" "$p" | head -1 | cut -d= -f2)
            [ -n "$n" ] && [ "$n" -gt 0 ] 2>/dev/null && hits=$((hits+1))
        done
        n=$(grep -ac 'P282-RELGATE-FAULT' "$p"); [ "${n:-0}" -gt 0 ] && hits=$((hits+1))
    done
    if [ "$hits" = 0 ]; then
        echo "FAIL: VACUOUS ARM — a relgate stage was armed (${TCK_PARAMS}) but no victim probe shows the marker block was ever entered (iclus_marked/iclus_unmarked/iclus_failed all 0 and no P282-RELGATE-FAULT on every victim).  The fault was never injected, so this arm is not fault-injection evidence and must not be cited as one.  Root as of sess479: the churn's files are O_TMPFILE and are named only between linkat and unlink inside one tight loop iteration, so the TCK_PREKILL_RELEASE peer's 'ls' laps 0.7 s apart read entries=0 every time (see PREKILL-RELEASE lines) and never acquire PR on a routed inode, so the victim never releases its cluster grant.  Force the release deterministically victim-side instead of racing a name that exists for microseconds."
        fail=1
    fi
fi
if [ $fail = 0 ]; then
    if [ "$TERMINAL" = 1 ]; then echo "VERDICT PASS: terminal verdict published ($(sum rterm)) and imported ($(sum quar) survivors), nothing replayed, no kill-class probe";
    else echo "VERDICT PASS: $ok survivors complete, victims replayed ($(sum frc) complete / 0 failed), no kill-class probe, chk clean (SB lazy counters aside)"; fi
else echo "VERDICT FAIL"; fi
echo "=== done label=$LABEL total=$(( $(date +%s) - t0 ))s out=$OUT ==="
exit $fail
