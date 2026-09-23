#!/bin/bash
# tests/pr_retirement_probe.sh — after the target has lost a node's I_T nexus,
# can a write it already ACCEPTED from that nexus still land?
#
# WHY THIS EXISTS.  Every fence kind this tree mints proves ADMISSION: the dead
# incarnation cannot obtain permission to write again (its registration is gone
# and a Write Exclusive form is held by somebody else).  None of them witnesses
# RETIREMENT: that the target has finished with the commands it already took
# from that nexus.  A certificate authorises foreign-slice replay, so a command
# accepted from the old nexus that executes AFTER the certificate lands under
# the replay — an unordered logical write into metadata the replay is
# rewriting.  The design-consult ruling is banked in
# docs/rulings/fence-ambiguous-drain-and-proof-resume.md; the ledger record is
# D-BOOT-SUCCESSION-CERTIFIES-FROM-IDENTITY-AND-ADMISSION-WITH-NO-TASK-
# RETIREMENT-WITNESS.
#
# WHY IT IS NOT tests/fence_inflight/inflight_ab.sh.  That harness holds the
# victim's write in the target's task set with dm-delay under the target's
# backing store and times the PR completion from an ftrace probe INSIDE the
# target.  Both require owning the target.  The shipping LUN is an appliance
# (data/rigs.json), so neither is available and the measurement has to be made
# entirely from the initiators.
#
# THE MEASUREMENT, AND WHY IT NEEDS NO CROSS-HOST CLOCK.  V writes a rising
# 64-bit counter into each of NSLOT distinct blocks, O_DIRECT, one thread per
# slot, continuously.  W reads that whole window O_DIRECT in a tight loop and
# records a row every time ANY counter changes.  V is then destroyed — a power
# cut, not a shutdown, so whatever V had submitted is in the target's queue with
# nobody to answer to.  W keeps reading.
#
#   the counters stop advancing  ==  V died (W sees this in its OWN data)
#   any change after a quiescent gap  ==  a write accepted from the dead nexus
#                                         executed after the nexus was gone
#
# So the verdict is read off one node's own timeline.  clyde's destroy timestamp
# is recorded as context, never as the discriminator: a skew between two guests
# cannot move the verdict.
#
# WHAT A PASS DOES AND DOES NOT ESTABLISH.  A clean run says: on THIS target,
# THIS firmware, THIS session topology, no write accepted from a nexus that was
# power-cut was observed to land after the nexus stopped.  Per the ruling that
# may be used as a qualified target contract and may NEVER be promoted into a
# promise about arbitrary SPC targets; re-run it when the target, its firmware
# or the session topology changes, exactly as data/rigs.json's
# pr_registration_on_session_loss declaration requires.
#
# THE SCRATCH WINDOW IS DESTRUCTIVE.  Unlike tests/pr_preempt_sark0_probe.sh,
# which writes a block back with its own bytes, this one has to change content
# to carry a counter.  It writes the last 256 KiB of the LUN and re-formats with
# tools/mkfs_mxfs in the tail, so the filesystem the next lap preps is a fresh
# one and never a torn one.  Both nodes must be unmounted with the module out.
#
# Budget (derived): device resolution and PR setup ~20 + writer warmup and the
# advance control 20 + the destroy 5 + the observation OBS_S (150, which covers
# the ~34 s registration purge this target is declared to do plus a wide margin)
# + V's boot ~90 + re-format ~30 ~= 315 s.  Caller bound 400 s.
#
# Usage: tests/pr_retirement_probe.sh <label> [W=test1] [V=test2]
# Env:   OBS_S (150), NSLOT (32), QUIET_S (3), MXFS_NODE_LIST
# Exit 0 PASS, 1 FAIL, 2 ABORT/INFRA, 3 VACUOUS.
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
W=${2:-${MXFS_NODE_LIST%%,*}}
V=${3:-${MXFS_NODE_LIST##*,}}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
SSH=tools/mxfs_sshpass.sh
OBS_S=${OBS_S:-150}
NSLOT=${NSLOT:-32}
QUIET_S=${QUIET_S:-3}
KW=0xfeed0a01
KV=0xfeed0a02
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_prret_$LABEL
mkdir -p "$OUT"
fails=0
. "$(dirname "$0")/lib/rig.sh"
VIRSH="timeout 30 virsh -c qemu:///system"
say() { echo "[$(date -u +%H:%M:%SZ)] $*"; }
# rig.sh supplies ck/measure/capture_require/rsx/mxfs_dev_*; these two are the
# harness's own and are NOT in the library, so they are defined here rather
# than inherited by accident.
field() { grep -ao "^$2=[^ ]*" "$1" | head -1 | cut -d= -f2; }
keys_into() {
    measure "$1" 25 "$2" 'PR generation=' "$3 on $1" \
        "sg_persist -i -k \$(readlink -f $DEV) 2>&1 | tail -8"
}
s0=$(date +%s)
el() { echo $(( $(date +%s) - s0 )); }
DESTROYED=0
prret_cleanup() {
    [ "$DESTROYED" = 1 ] && { echo "CLEANUP: restarting $V"; $VIRSH start "$V" > /dev/null 2>&1; }
    return 0
}
trap prret_cleanup EXIT

say "=== pr_retirement_probe label=$LABEL W(observer)=$W V(victim)=$V nslot=$NSLOT obs=${OBS_S}s ==="

# ---- 1. both nodes idle at the SCSI layer.  A mounted node would have the
# module writing to the same LUN, and this probe's whole signal is "nothing
# else is writing", so a mount here is an ABORT and not a warning.
for n in "$W" "$V"; do
    measure "$n" 25 "$OUT/idle_$n.txt" '^IDLE_DONE=1$' "the idle check on $n" \
        "echo MXFS_MOUNTS=\$(grep -c ' mxfs ' /proc/mounts); echo MXFS_MOD=\$(lsmod | grep -c '^mxfs '); echo IDLE_DONE=1"
    ck "$n has no mxfs mount" "$(field "$OUT/idle_$n.txt" MXFS_MOUNTS)" 0
    ck "$n has the module out" "$(field "$OUT/idle_$n.txt" MXFS_MOD)" 0
done
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=notidle wall=$(el)s evidence=$OUT"; exit 2; }

# the LUN by its declared identity on BOTH nodes, and the same format
# generation on each — a probe that measured two different devices would be
# well-formed and meaningless
mxfs_dev_same "$W" "$V"
DEV=$MXFS_DEV_RESOLVED
say "dev=$DEV wwid=$MXFS_DEV_WWID fsid=$MXFS_DEV_FSID (declared identity, same on both nodes)"

# ---- 2. PR entry state.  With no module loaded the target may still hold keys
# from an earlier lap, so start from a known table: W registers, clears
# everything else, re-registers and takes the all-registrants Write Exclusive
# this build establishes; V registers under it.  CLEAR is safe here precisely
# because nothing is mounted.
measure "$W" 40 "$OUT/w_setup.txt" '^SETUP_DONE=[0-9]+$' "W's PR setup" \
    "R=\$(readlink -f $DEV); \
     sg_persist --out --register-ignore --param-sark=$KW \$R > /dev/null 2>&1; \
     sg_persist --out --clear --param-rk=$KW \$R 2>&1 | tail -6; echo CLEAR_RC=\${PIPESTATUS[0]}; \
     sg_persist --out --register-ignore --param-sark=$KW \$R 2>&1 | tail -2; echo REG_RC=\${PIPESTATUS[0]}; \
     sg_persist --out --reserve --param-rk=$KW --prout-type=7 \$R 2>&1 | tail -2; echo RESV_RC=\${PIPESTATUS[0]}; \
     echo SETUP_DONE=1"
# REGISTER with a zero reservation key is a RESERVATION CONFLICT on a nexus
# that is already registered, and these nodes keep an MXFS key across an
# unclean departure by design (P302-PR-KEY-RETAINED-FENCE-TARGET), so the
# setup uses REGISTER AND IGNORE EXISTING KEY throughout and then CLEARs.
ck "W cleared the table it found" "$(field "$OUT/w_setup.txt" CLEAR_RC)" 0
ck "W registered its key" "$(field "$OUT/w_setup.txt" REG_RC)" 0
ck "W took the all-registrants Write Exclusive" "$(field "$OUT/w_setup.txt" RESV_RC)" 0
# W's CLEAR raises a unit attention on every other nexus (registrations
# preempted).  The next command from V eats it as a CHECK CONDITION, so a
# PERSISTENT RESERVE OUT issued straight after the clear fails once and
# succeeds on the retry — measured s75s, where V's register returned 6
# (illegal request) and the identical command by hand returned 0.  Absorb the
# attention with TEST UNIT READY first, keep the sense text in the capture,
# and retry once so a single expected attention cannot abort the lap.
measure "$V" 40 "$OUT/v_setup.txt" '^VREG_DONE=[0-9]+$' "V's registration" \
    "R=\$(readlink -f $DEV); for i in 1 2 3; do sg_turs \$R > /dev/null 2>&1; done; \
     sg_persist --out --register-ignore --param-sark=$KV \$R 2>&1 | tail -6; VR=\${PIPESTATUS[0]}; \
     if [ \$VR != 0 ]; then echo VREG_RETRY_AFTER=\$VR; sg_persist --out --register-ignore --param-sark=$KV \$R 2>&1 | tail -6; VR=\${PIPESTATUS[0]}; fi; \
     echo VREG_RC=\$VR; echo VREG_DONE=1"
ck "V registered under the reservation" "$(field "$OUT/v_setup.txt" VREG_RC)" 0
keys_into "$W" "$OUT/K0.txt" "READ KEYS after setup"
ck "both keys are registered before the writer starts" \
   "$(grep -ac '^    0x' "$OUT/K0.txt")" 2
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=prsetup wall=$(el)s evidence=$OUT"; exit 2; }

# ---- 3. the writer and the reader.  The window is the LAST NSLOT*4096 bytes
# of the LUN, so a partial write cannot land on the envelope or the superblock
# region while the probe is running; the tail re-formats regardless.
# O_DIRECT needs the transfer BUFFER to be block-aligned, not just the offset.
# A Python bytes/bytearray is whatever pymalloc hands out — writing from one
# gets EINVAL, which this probe would have read as "the write was refused".
# mmap(-1, n) is page-aligned by construction, so every transfer below goes
# through an mmap buffer and os.preadv/os.pwritev, never os.pread/os.pwrite.
WRITER=$(base64 -w0 <<'PY'
import mmap, os, struct, sys, threading, time
dev, nslot, span = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
fd0 = os.open(dev, os.O_RDONLY)
base = (os.lseek(fd0, 0, os.SEEK_END) - span) & ~4095
os.close(fd0)
def run(i):
    fd = os.open(dev, os.O_WRONLY | os.O_DIRECT)
    buf = mmap.mmap(-1, 4096)
    buf[0:8] = b'PRRETIRE'
    buf[8:16] = struct.pack('>Q', i)
    n = 0
    while True:
        n += 1
        buf[16:24] = struct.pack('>Q', n)
        try:
            os.pwritev(fd, [buf], base + i * 4096)
        except OSError as e:
            print("WRITE_ERR slot=%d n=%d errno=%d" % (i, n, e.errno), flush=True)
            time.sleep(0.05)
for i in range(nslot):
    threading.Thread(target=run, args=(i,), daemon=True).start()
print("WRITER_BASE=%d nslot=%d" % (base, nslot), flush=True)
while True:
    time.sleep(60)
PY
)
READER=$(base64 -w0 <<'PY'
import mmap, os, struct, sys, time
dev, nslot, span, secs = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4])
fd = os.open(dev, os.O_RDONLY | os.O_DIRECT)
base = (os.lseek(fd, 0, os.SEEK_END) - span) & ~4095
buf = mmap.mmap(-1, span)
# While the writer is alive the window changes on almost every read, so rows
# are rate-limited to one per MIN_DT.  That never hides the row this probe is
# about: a change that follows a quiescent gap is by definition more than
# MIN_DT after the previous row, so it is emitted the moment it is seen.
MIN_DT = 0.05
prev, t0, rows, last = None, time.monotonic(), 0, -1.0
print("READER_BASE=%d nslot=%d min_dt=%.3f" % (base, nslot, MIN_DT), flush=True)
while time.monotonic() - t0 < secs:
    try:
        got = os.preadv(fd, [buf], base)
    except OSError as e:
        print("READ_ERR t=%.3f errno=%d" % (time.monotonic() - t0, e.errno), flush=True)
        time.sleep(0.05); continue
    if got != span:
        print("READ_SHORT t=%.3f got=%d want=%d" % (time.monotonic() - t0, got, span), flush=True)
        time.sleep(0.05); continue
    v = []
    for i in range(nslot):
        off = i * 4096
        v.append(struct.unpack('>Q', buf[off + 16:off + 24])[0]
                 if buf[off:off + 8] == b'PRRETIRE' else -1)
    now = time.monotonic() - t0
    if v != prev and now - last >= MIN_DT:
        rows += 1
        print("CHANGE t=%.3f sum=%d max=%d v=%s" %
              (now, sum(x for x in v if x > 0), max(v),
               ','.join(str(x) for x in v)), flush=True)
        prev, last = v, now
print("READER_DONE rows=%d wall=%.1f" % (rows, time.monotonic() - t0), flush=True)
PY
)
SPAN=$(( NSLOT * 4096 ))
say "starting V's writer ($NSLOT O_DIRECT threads into the last $SPAN bytes) at +$(el)s"
measure "$V" 30 "$OUT/v_writer_start.txt" '^WSTART_DONE=1$' "V's writer launch" \
    "R=\$(readlink -f $DEV); echo $WRITER | base64 -d > /run/prret_writer.py; \
     nohup python3 /run/prret_writer.py \$R $NSLOT $SPAN > /run/prret_writer.log 2>&1 & \
     sleep 3; echo WLOG=\$(head -1 /run/prret_writer.log); echo WSTART_DONE=1"
say "$(grep -a '^WLOG=' "$OUT/v_writer_start.txt" | head -1)"

# ---- 4. the reader runs for the warmup + the destroy + the observation, in
# ONE process, so the whole timeline is one monotonic clock on one node.
READ_S=$(( OBS_S + 30 ))
say "starting W's reader for ${READ_S}s at +$(el)s"
timeout $(( READ_S + 60 )) $SSH "$W" \
    "R=\$(readlink -f $DEV); echo $READER | base64 -d > /run/prret_reader.py; \
     python3 /run/prret_reader.py \$R $NSLOT $SPAN $READ_S" > "$OUT/w_reader.txt" 2>&1 &
RPID=$!
sleep 20
# the positive control: the writer must actually be reaching the platter, or
# the whole observation is about a device nothing was writing
ADV=$(grep -ac '^CHANGE ' "$OUT/w_reader.txt" 2>/dev/null || echo 0)
if [ "$ADV" -lt 3 ]; then
    kill $RPID 2>/dev/null
    echo "  FAIL <the observer saw $ADV change(s) in 20 s while the writer was alive: nothing was reaching the platter>"
    echo "RESULT: VACUOUS label=$LABEL stage=nowrites wall=$(el)s evidence=$OUT"; exit 3
fi
say "the writer is reaching the platter ($ADV change rows in 20 s) — cutting $V's power at +$(el)s"

# ---- 5. the power cut.  destroy, not shutdown: a clean shutdown would let V's
# own stack finish or cancel its outstanding writes, which is the opposite of
# the state under test.
T_DESTROY=$(date -u +%FT%T.%NZ)
$VIRSH destroy "$V" > /dev/null 2>&1
DESTROYED=1
say "$V destroyed at $T_DESTROY (+$(el)s) — observing for ${OBS_S}s"
# W's registration table across the purge: context for the row, never the
# discriminator.  This target is DECLARED to purge a lost session's
# registration (data/rigs.json pr_registration_on_session_loss); when that
# happens is recorded so a late landing can be placed before or after it.
( for i in 1 2 3 4 5 6 7 8 9 10; do
      sleep 15
      echo "PURGEPOLL i=$i t=$(date -u +%FT%T.%NZ) keys=$(timeout 20 $SSH "$W" "sg_persist -i -k \$(readlink -f $DEV) 2>/dev/null | grep -ac '^    0x'" 2>/dev/null | tr -d '\r' | tail -1)"
  done ) > "$OUT/w_purge.txt" 2>&1 &
PPID_POLL=$!
wait $RPID
wait $PPID_POLL 2>/dev/null
say "observation complete at +$(el)s"

# ---- 6. the verdict, read off W's own monotonic timeline.
grep -a '^CHANGE \|^READER_DONE\|^READ_ERR\|^READER_BASE' "$OUT/w_reader.txt" > "$OUT/w_changes.txt"
capture_require "$OUT/w_changes.txt" '^READER_DONE ' "W's observation of the scratch window"
python3 - "$OUT/w_changes.txt" "$QUIET_S" > "$OUT/verdict.txt" <<'PY'
import sys
rows, endw = [], None
for line in open(sys.argv[1]):
    if line.startswith('CHANGE '):
        f = dict(p.split('=', 1) for p in line.split()[1:] if '=' in p)
        rows.append((float(f['t']), int(f['max']), int(f['sum'])))
    elif line.startswith('READER_DONE'):
        f = dict(p.split('=', 1) for p in line.split()[1:] if '=' in p)
        endw = float(f['wall'])
quiet = float(sys.argv[2])
if len(rows) < 3 or endw is None:
    print("VERDICT=VACUOUS rows=%d end=%s" % (len(rows), endw)); raise SystemExit
# Where the writer stopped is the first row followed by a gap of >= quiet —
# and the gap may run to the END OF THE OBSERVATION rather than to another
# row, which is exactly what a clean run looks like: the victim dies, the
# window settles, and nothing is ever recorded again.  Treating only
# row-to-row gaps as quiescence reports that clean run as "never went quiet".
stop_i = None
for i in range(len(rows)):
    nxt = rows[i + 1][0] if i + 1 < len(rows) else endw
    if nxt - rows[i][0] >= quiet:
        stop_i = i
        break
if stop_i is None:
    print("VERDICT=QUIESCED_NEVER last_t=%.3f end=%.3f rows=%d" %
          (rows[-1][0], endw, len(rows)))
    raise SystemExit
late = rows[stop_i + 1:]
print("STOP_T=%.3f STOP_MAX=%d PRE_ROWS=%d OBS_END=%.3f QUIET_TAIL=%.3f" %
      (rows[stop_i][0], rows[stop_i][1], stop_i + 1, endw,
       (rows[stop_i + 1][0] if late else endw) - rows[stop_i][0]))
print("LATE_ROWS=%d" % len(late))
for t, mx, sm in late[:10]:
    print("LATE t=%.3f gap=%.3f max=%d sum=%d" % (t, t - rows[stop_i][0], mx, sm))
print("VERDICT=%s" % ("RETIRED" if not late else "LATE_WRITE_LANDED"))
PY
sed 's/^/    /' "$OUT/verdict.txt"
VERDICT=$(grep -ao '^VERDICT=[A-Z_]*' "$OUT/verdict.txt" | head -1 | cut -d= -f2)
case "$VERDICT" in
    RETIRED)
        echo "  PASS no write accepted from the power-cut nexus landed after it stopped (quiescent gap >= ${QUIET_S}s, then no change for the rest of the observation)" ;;
    LATE_WRITE_LANDED)
        echo "  FAIL a write accepted from the power-cut nexus LANDED after the nexus stopped — admission is not retirement, and a certificate taken from the victim's absence authorises replay over a store another initiator can still modify"
        fails=$((fails+1)) ;;
    QUIESCED_NEVER)
        echo "  FAIL <the scratch window never went quiet: the observation cannot separate V's death from its writes>"; fails=$((fails+1)) ;;
    *)
        echo "ABORT: the observation produced no verdict (got=[${VERDICT:-none}])"
        echo "RESULT: ABORT label=$LABEL stage=noverdict wall=$(el)s evidence=$OUT"; exit 2 ;;
esac
echo "--- the registration table across the observation (context, not the discriminator):"
sed 's/^/    /' "$OUT/w_purge.txt"

# ---- 7. tail: give the LUN back a clean filesystem, and V its power.
$VIRSH start "$V" > /dev/null 2>&1
DESTROYED=0
measure "$W" 90 "$OUT/w_mkfs.txt" '^MKFS_RC=[0-9]+$' "the re-format that undoes the scratch writes" \
    "R=\$(readlink -f $DEV); sg_persist --out --release --param-rk=$KW --prout-type=7 \$R > /dev/null 2>&1; \
     sg_persist --out --register --param-rk=$KW --param-sark=0 \$R > /dev/null 2>&1; \
     yes | timeout 60 /src/mxfs/tools/mkfs_mxfs -f \$R > /run/prret_mkfs.log 2>&1; echo MKFS_RC=\$?; tail -2 /run/prret_mkfs.log"
ck "the LUN carries a fresh filesystem again" "$(field "$OUT/w_mkfs.txt" MKFS_RC)" 0

echo "RESULT: $( [ $fails = 0 ] && echo PASS || echo FAIL ) label=$LABEL fails=$fails verdict=$VERDICT wall=$(el)s evidence=$OUT"
[ $fails = 0 ]
