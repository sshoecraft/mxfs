#!/bin/bash
# sess481 chain 128: WHERE DO THE 27 MILLISECONDS GO?
#
# The 32-node crash_consistency row is the last non-policy cell on the board.
# sess481 measured, from the shipping build's own probes, that:
#
#   - all 32/32 nodes reach PHASE=dropcaches-done; the write phase eats 85-88 s
#     of the 90 s budget and the cross-node durable verify never runs at all;
#   - 48% of a node's budget is a FAIR 32-way queue wait for the shared
#     directory's EX grant (P291-EXWIN: p50=0, p90=0, eight waits of 3.4-6.6 s
#     spaced one full rotation apart, 26-28 peers queued in each);
#   - the cluster retires 3200 creates in ~85 s = 26.6 ms per create, serialised.
#
# and then ruled, arithmetically: with creates globally serialised behind one
# exclusive grant, removing ALL handoff cost buys at most 1/(1-f) where f is the
# handoff fraction of the critical path.  Fitting the workload into 30 s needs
# 2.84x, which requires f >= 64.8%.  Measured holder-side release on that
# directory is 15-97 ms against turns of 170-320 ms -- f is 5-16%, a ceiling of
# 1.05-1.19x.  No amount of lock-handoff tuning can make this row pass.
#
# The binding term is the per-create cost that survives REMOVING the shared
# directory: the private arm costs 4.6 ms/create at 1 node and 27.8 ms/create at
# 32, with nothing shared but the mount.  So this chain does not measure the
# directory lock.  It measures where a single create's milliseconds go, in both
# arms, using the P132-CREATE decomposition that sess481 extended to file
# creates (it had been started under `is_dir` since sess132, so it had never run
# on the path that sets the ceiling).
#
# res_ms / dlk_ms / dia_ms are stamped at call boundaries inside xfs_create, so
# they are mutually exclusive by construction; other_ms is the unattributed
# remainder of pre_ms and is reported rather than hidden.
#
#   res_ms dominant  -> transaction reservation / log grant space: shared-log
#                       serialisation, the leading hypothesis for a synchronous
#                       workload.
#   dlk_ms dominant  -> the shared directory grant, i.e. the term already ruled
#                       insufficient; expect this to be large in the SHARED arm
#                       and near zero in the PRIVATE arm.
#   dia_ms dominant  -> allocation-group contention (the LUN formats to 25 AGs
#                       for 32 nodes).  The per-AG table splits it.
#   other_ms large   -> the decomposition has not found the cost yet, and that
#                       is a finding, not a null result.
#
# WHAT THIS IS NOT: it is not a fix and changes no default.  mxfs.create_cost_ms
# defaults to 0 and is armed only for the duration of a leg.
#
# derived time budgets, derived: build 600 s (measured 69-71 s for a comparable full
# build, 8x headroom because the header change rebuilds most of xfs/); prep
# 300 s (measured 88-120 s); each row 160 s = the row's UNCHANGED 90 s budget
# plus ~37 s measured harness startup.  Total ~26 min after the gate clears.
#
# This chain BUILDS the module it measures (the instrumentation is new), so it
# takes no frozen-.ko arguments; it refuses to start until the gate chain is
# DONE and the run lock is free, because a relink under another chain's preps
# splits the fleet's srcversion mid-run.
#
# Usage:  setsid nohup bash tests/sess481_chain128_create_cost.sh s481a &
set -u
cd /src/mxfs || exit 1
LABEL=${1:-s481a}
# Gate on the LAST chain in the sess480 queue.  Gating on DONE alone is not
# enough -- a leftover run from another session can still hold the run lock, and
# a build started while another chain's preps are shipping mxfs.ko over NFS
# splits the fleet's srcversion mid-run -- so rig_wait_free (which waits on the
# lock itself, and on any live make) runs after the gate, not instead of it.
GATE=${GATE:-tests/evidence/sess480_chain127_fastpoll_s480m.log}
LOG=tests/evidence/sess481_chain128_create_cost_$LABEL.log
O=tests/evidence/sess481_create_cost_$LABEL
FREEZE=tests/evidence/sess481_frozen_0650
SSH=tools/mxfs_sshpass.sh
THRESH=${THRESH:-1}          # print any create costing >= this many ms
# The SCST vdisk_fileio backing file for the shared LUN, read-only.  Reading it
# on the target host costs no rig time and cannot disturb a run; caw_slotdump
# cannot be used here because it speaks SG_IO and so needs an initiator.
LUN_IMG=$(tools/mxfs_host_image.sh) || { echo "$LUN_IMG"; exit 2; }
mkdir -p "$O"

nodes() { seq 1 32 | sed 's/^/test/'; }

# Arm the probe on every node and PROVE the arm took.  A leg whose knob did not
# land produces an empty log and an honest-looking zero; six harnesses in this
# campaign have reported PASS for work that never happened.
arm() { # <value>
    local v=$1 ok=0 bad=""
    for n in $(nodes); do
        ( $SSH "$n" "echo $v > /sys/module/mxfs/parameters/create_cost_ms 2>/dev/null;
                     cat /sys/module/mxfs/parameters/create_cost_ms 2>/dev/null" \
              > "$O/.arm.$n" 2>/dev/null ) &
    done
    wait
    for n in $(nodes); do
        if [ "$(tr -d '[:space:]' < "$O/.arm.$n" 2>/dev/null)" = "$v" ]; then
            ok=$((ok + 1))
        else
            bad="$bad $n"
        fi
    done
    echo "  arm create_cost_ms=$v: $ok/32 confirmed${bad:+ ; NOT ARMED:$bad}"
    [ "$ok" -eq 32 ]
}

{
  echo "=== sess481 chain128 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) ==="
  # Bounded: a gate chain that dies without writing DONE must not leave this
  # one waiting across sessions.  6 h comfortably covers the four queued
  # sess480 chains; past that the queue is wedged and needs a human look, not
  # another waiter.
  gate_dl=$(( $(date +%s) + 21600 ))
  while ! grep -q "^DONE" "$GATE" 2>/dev/null; do
      if [ "$(date +%s)" -ge "$gate_dl" ]; then
          echo "ABORT: gate $GATE never reached DONE within 6 h — the sess480"
          echo "       chain queue is wedged; diagnose it rather than racing it."
          echo "DONE $(date -u +%FT%TZ)"; exit 1
      fi
      sleep 30
  done
  echo "STAGE gate cleared: $GATE"
  bash tests/rig_wait_free.sh 7200 || { echo "ABORT: rig not free"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }

  # ---- build the instrumented module -------------------------------------
  t0=$(date +%s)
  timeout 600 make modules > "$O/build.log" 2>&1; brc=$?
  echo "STAGE build rc=$brc wall=$(( $(date +%s) - t0 ))s"
  if [ "$brc" -ne 0 ]; then
      tail -20 "$O/build.log"; echo "DONE $(date -u +%FT%TZ)"; exit 1
  fi
  sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  echo "STAGE identity sv=$sv"
  # The probe must actually be IN the module.  srcversion hashes sources, not
  # the linked objects, so it cannot prove this on its own.
  if ! strings -a mxfs.ko | grep -q 'dlk_ms='; then
      echo "ABORT: mxfs.ko does not contain the P132-CREATE dlk_ms field — the"
      echo "       link did not pick up the new objects. Nothing here is valid."
      echo "DONE $(date -u +%FT%TZ)"; exit 1
  fi
  echo "STAGE probe_present dlk_ms=yes"
  mkdir -p "$FREEZE" && cp mxfs.ko "$FREEZE/mxfs.ko" && echo "STAGE freeze $FREEZE sv=$sv"

  # ---- both arms ----------------------------------------------------------
  for leg in shared private; do
    echo "--- leg=$leg ---"
    timeout 300 ./run.sh 32 caw prep_cluster >/dev/null 2>&1; prc=$?
    echo "STAGE prep_$leg rc=$prc"
    if [ "$prc" -ne 0 ]; then
        echo "LEG $leg NOT RUN: prep rc=$prc — an unprepped fleet is not a result."
        continue
    fi
    # the prep reloads the module, so the knob resets to 0 here every time
    if ! arm "$THRESH"; then
        echo "LEG $leg NOT RUN: the probe is not armed on all 32 nodes."
        continue
    fi
    # harness-lint: ok - pinned BEFORE the row, compared with $post below
    pre=$(ls -dt tests/evidence/run_crash_consistency_* 2>/dev/null | head -1)
    if [ "$leg" = private ]; then
        MXFS_TEST_ENV="CC_PRIVATE=1" timeout 160 ./run.sh 32 caw crash_consistency \
            > "$O/cc_$leg.out" 2>&1
    else
        timeout 160 ./run.sh 32 caw crash_consistency > "$O/cc_$leg.out" 2>&1
    fi
    echo "STAGE cc_$leg rc=$?"
    # harness-lint: ok - compared against the $pre pinned above
    post=$(ls -dt tests/evidence/run_crash_consistency_* 2>/dev/null | head -1)
    if [ "$post" = "$pre" ] || [ -z "$post" ]; then
        echo "LEG $leg NOT SCORED: the row produced no new evidence directory"
        echo "  (still '$pre'); the previous leg's logs must not be read as this one's."
        continue
    fi
    echo "  EVIDENCE $post"
    # The row line now carries planned=/notrun=, so a budget-exhausted row says
    # how many of its assertions were never reached instead of 'failed=0'.
    grep -aE 'crash_consistency' "$O/cc_$leg.out" | grep -a 'nodes_pass' \
        | cut -c1-320 | sed "s/^/  $leg ROW: /"
    echo "  --- create-cost attribution, leg=$leg ---"
    python3 tools/p132_attribute.py "$post" 2>&1 | sed 's/^/  /'
    # Free ride on the same capture: P381-UNLK-CONTEND is always-on and now
    # carries find_ms/backoff_ms (0.65.0), which closes the unlock accounting
    # that sess481 first mis-attributed to slot I/O.
    echo "  --- contended-unlock accounting, leg=$leg (D-CAW-WIRE-UNLOCK-...) ---"
    python3 tools/caw_unlock_audit.py "$post" 2>&1 | sed 's/^/  /'
    # Structural half of the same question, taken RIGHT AFTER the row and
    # BEFORE the next leg's prep re-mkfs's the LUN and wipes the table.
    # find_slot linear-probes past tombstones, so if the probe walk is what
    # the unlock's residue is made of, displacement must be large HERE.
    # Measured on an idle table (sess481): 99 live, 0 tombstones, 100% at
    # home, 1.00 span read per lookup -- which is the null result this leg
    # exists to confirm or overturn under real churn.
    echo "  --- CAW slot-table census after leg=$leg ---"
    timeout 300 python3 tools/caw_slot_census.py "$LUN_IMG" 2>&1 | sed 's/^/  /'
    # D-DIR-INODE-DURABLE-BARRIER-FAILS-ARM-UNCLASSIFIED: the deciding
    # measurement, and it needs nothing but this build's new state=/releasing=
    # fields.  releasing=0 everywhere -> the harmless op-side best-effort miss,
    # and the record is DISPROVED as a durability defect.  ANY releasing=1 ->
    # the release-side drain gave up and handed a peer a stale dinode, which is
    # an Architectural Invariant #1 violation and critical, not major.
    echo "  --- dir-inode durable barrier, arm split, leg=$leg ---"
    python3 - "$post" <<'PYIN' 2>&1 | sed 's/^/  /'
import glob, gzip, os, re, sys, collections
d = sys.argv[1]
c = collections.Counter(); samples = []
for f in sorted(glob.glob(os.path.join(d, "kernlog_*.gz"))):
    try:
        with gzip.open(f, "rt", errors="replace") as fh:
            for ln in fh:
                if "DURABLE-FAIL" not in ln:
                    continue
                tag = "P13" if "P13-SFPARENT" in ln else (
                      "P68" if "P68-DIRINODE" in ln else "other")
                m = re.search(r"releasing=(\d+)", ln)
                arm = m.group(1) if m else "UNFIELDED"
                c[(tag, arm)] += 1
                if len(samples) < 4:
                    samples.append(ln.strip()[:190])
    except OSError:
        pass
if not c:
    print("no DURABLE-FAIL events in this row -- a zero here is a real zero "
          "only if the probes are present in the running build; both are "
          "always-on and ratelimited, so this count is a floor.")
else:
    for (tag, arm), n in sorted(c.items()):
        print("%s releasing=%s : %d" % (tag, arm, n))
    if any(a == "UNFIELDED" for (_, a) in c):
        print("UNFIELDED means the fleet is NOT running 0.65.0 -- the arm "
              "cannot be decided from this row.")
    elif any(a == "1" for (_, a) in c):
        print("VERDICT: release-side give-up OBSERVED -- Architectural "
              "Invariant #1 violated on the handoff path. Raise the record to "
              "critical.")
    else:
        print("VERDICT: every failure is op-side (releasing=0), the arm the "
              "design documents as harmless. Candidate DISPROVED for the "
              "durability claim -- state that, do not silently drop it.")
    for s in samples:
        print("  sample: %s" % s)
PYIN
    echo "$post" > "$O/evidence_$leg.path"
  done

  arm 0 >/dev/null 2>&1 || true
  echo "--- unlock accounting, shared vs private ---"
  if [ -s "$O/evidence_shared.path" ] && [ -s "$O/evidence_private.path" ]; then
      python3 tools/caw_unlock_audit.py --compare "$(cat "$O/evidence_shared.path")" \
          -- "$(cat "$O/evidence_private.path")" 2>&1 | sed 's/^/  /'
  else
      echo "  NOT COMPARED: one or both legs did not produce evidence."
  fi
  echo "--- reading ---"
  echo "  Compare dlk_ms between the arms: it is the shared-directory queue wait"
  echo "  and should collapse in the private arm.  Whatever is LEFT in the"
  echo "  private arm's total_ms is the term that sets the ceiling, because it"
  echo "  survives removing the shared directory entirely.  If that residue is"
  echo "  res_ms, the shared log is the root; if dia_ms, allocation-group"
  echo "  contention is (check the per-AG table for whether collided-AG nodes"
  echo "  differ from exclusive-AG ones); if other_ms, the decomposition needs"
  echo "  another boundary and this run says exactly where to put it."
  timeout 300 ./run.sh 32 caw prep_cluster >/dev/null 2>&1; echo "STAGE prep_final rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
