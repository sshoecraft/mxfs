#!/bin/bash
# d0959_first_join_peermod.sh — when a mount that has never had a peer holds
# objects DIRTY at NL at the moment its first peer joins, and the newcomer
# modifies those same objects BEFORE the incumbent touches them again, does
# either side's change get lost?
#
# D-0959.  tests/d0959_first_join_drain.sh (s583o/p/q) and the first two laps
# of this harness (s584a/b, three objects) measured nothing, for one reason:
# the incumbent's add loop touched every object again AFTER the membership
# flip (a full `dmesg` per check cost over a second; then the first post-flip
# add blocked ~0.7 s on the settle window and re-acquired all three objects
# under real grants).  Its own re-acquire is what saved every image: the
# reload's 3-way merge for a shortform directory, and a fresh log of the
# whole in-core dir block for a block-format one.  The shape the record
# names needs objects the incumbent does NOT touch after the flip.
#
# So the incumbent spreads its adds round-robin over 3*K objects (K
# block-format directories past shortform, K shortform directories, K
# regular files), one object per iteration, and checks for the join after
# EVERY add through a persistent /dev/kmsg reader (milliseconds, not a
# second).  At most the last few iterations run after the flip, so all but a
# few objects are left exactly as they were: modified within the last
# fraction of a second before the flip, dirty in the AIL if xfsaild had not
# reached them yet, and never touched again by the incumbent until the
# newcomer has read them cold, modified each one and synced.
#
# Measurements, all per object, computed on clyde from the count dumps:
#   B_COLD_BEFORE  what the newcomer read cold right after joining -- an
#                  object showing fewer incumbent entries than the loop made
#                  is one whose dirty image was still undrained at the flip
#   A_COLD         the durable truth after both nodes leave and A remounts:
#                  every incumbent entry and the newcomer's one add per
#                  object must be there
# The last 3 iterations' objects may have been touched after the flip and
# are reported separately, never counted as evidence either way.
#
# derived budget: two unmounts and four mounts at ~5 s each on this rig,
# 3*K object creations (K*120 + K*3 creates, K files) at ~3 ms each (~12 s
# for K=32), an add loop that runs for the ~10 s of B's mount, B's 3*K
# modifications, three syncs and four count sweeps.  ~75 s of work; the
# whole run is bounded at 200 s and every ssh step at the number beside it.
#
# Usage: tests/d0959_first_join_peermod.sh <label> [K]
set -u
LABEL=${1:?label}
K=${2:-32}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
A=${MXFS_NODE_LIST%%,*}
B=${MXFS_NODE_LIST##*,}
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "${MXFS_NODE_LIST%%,*}"; DEV=$MXFS_DEV_RESOLVED
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0959peermod_$LABEL
mkdir -p "$OUT"
filt() { grep -av '^Unauthorized\|^Warning:\|^If you\|^$'; }
# rs: tests/lib/rig.sh (sourced above) provides the same helper; a local copy would shadow it
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
echo "=== d0959_first_join_peermod label=$LABEL K=$K sv=$SV $(date -u +%FT%TZ) ==="

fails=0
for n in $A $B; do
    st=$(rs 25 "$n" "echo sv=\$(cat /sys/module/mxfs/srcversion 2>/dev/null) mnt=\$(grep -c ' $MNT mxfs ' /proc/mounts)" | tr -d '\n')
    echo "  INFO $n $st"
    [ "$st" = "sv=$SV mnt=1" ] || { echo "  FAIL $n precondition (want sv=$SV mnt=1)"; fails=$((fails+1)); }
done
[ $fails = 0 ] || { echo "RESULT: FAIL label=$LABEL precondition fails=$fails"; exit 2; }

D=$MNT/d0959pm_$LABEL
NBD=120
KM=$((K-1))
t0=$(date +%s)
echo "  LEAVE B=$(rs 120 "$B" "umount $MNT; echo rc=\$?" | tr '\n' ' ') A=$(rs 120 "$A" "umount $MNT; echo rc=\$?" | tr '\n' ' ')"
amt=$(rs 120 "$A" "mount -t mxfs $DEV $MNT; echo A_SOLO_MOUNT_RC=\$?; sleep 2; dmesg | grep -a 'MXFS-MEMBERSHIP' | tail -1 | grep -ao 'active_count=[0-9]*'")
echo "  SOLO $(echo "$amt" | tr '\n' ' ')"
case "$amt" in *A_SOLO_MOUNT_RC=0*) ;; *) echo "RESULT: FAIL label=$LABEL $A could not mount alone: $amt"; exit 2 ;; esac

# The objects, created and made durable while alone.  A block dir's 120
# names of 28 characters cannot fit a shortform fork (and overflow one 4 KiB
# block), so it is data+leaf format on the platter before the dirty phase.
pre=$(rs 120 "$A" "mkdir -p $D; for k in \$(seq 0 $KM); do mkdir $D/bd\$k $D/sd\$k; for i in \$(seq 1 $NBD); do : > $D/bd\$k/blockdir_entry_number_\$i; done; : > $D/sd\$k/x1; : > $D/sd\$k/x2; : > $D/sd\$k/x3; echo A-init > $D/f\$k; done; sync -f $MNT; sleep 2; echo PRE objects=\$(ls $D | wc -l) bd0=\$(ls $D/bd0 | wc -l) sd0=\$(ls $D/sd0 | wc -l) f0=\$(wc -l < $D/f0) bd0_ino=\$(stat -c %i $D/bd0) sd0_ino=\$(stat -c %i $D/sd0) f0_ino=\$(stat -c %i $D/f0)")
echo "  $(echo "$pre" | tr '\n' ' ')"
case "$pre" in *"objects=$((3*K))"*) ;; *) echo "RESULT: FAIL label=$LABEL object creation: $pre"; exit 2 ;; esac

# The dirty phase.  Iteration i touches kind i%3 (0 bd, 1 sd, 2 f) of object
# (i/3)%K: one name in a block dir, one name in a shortform dir, one line in
# a file.  The write-side probes (dirwr, iwr) are on for the window so the
# kernel log carries every directory-block and inode-cluster write with its
# timestamp against the membership line.  The join detector is a persistent
# /dev/kmsg reader: the loop notes the file offset once the join mark has
# arrived and then greps only the bytes after it, after every add.
JOINMK="D0959PM-JOINMARK-$LABEL-$$"
rs 30 "$A" "cat /sys/module/mxfs/parameters/dirwr > /tmp/d0959pm_dirwr.sav; cat /sys/module/mxfs/parameters/iwr > /tmp/d0959pm_iwr.sav; echo 1 > /sys/module/mxfs/parameters/dirwr; echo 1 > /sys/module/mxfs/parameters/iwr; rm -f /tmp/d0959pm_loop.txt /tmp/d0959pm_kmsg.txt; nohup bash -c 'cat /dev/kmsg > /tmp/d0959pm_kmsg.txt 2>/dev/null & KR=\$!; sleep 0.5; echo $JOINMK > /dev/kmsg; for w in \$(seq 1 50); do grep -aq $JOINMK /tmp/d0959pm_kmsg.txt && break; sleep 0.1; done; OFF=\$(wc -c < /tmp/d0959pm_kmsg.txt); echo READER_READY off=\$OFF wait=\$w; i=0; while [ \$i -lt 60000 ]; do i=\$((i+1)); c=\$((i % 3)); k=\$(((i / 3) % $K)); case \$c in 0) : > $D/bd\$k/y\$i ;; 1) : > $D/sd\$k/z\$i ;; 2) echo A-\$i >> $D/f\$k ;; esac; if tail -c +\$OFF /tmp/d0959pm_kmsg.txt | grep -aq \"active_count=2\"; then echo JOIN_SEEN_AT_ADD=\$i; break; fi; done; echo LOOP_DONE adds=\$i; echo LOOPEND-$JOINMK > /dev/kmsg; sleep 0.2; kill \$KR' > /tmp/d0959pm_loop.txt 2>&1 &
sleep 2; cat /tmp/d0959pm_loop.txt | tr '\n' ' '; echo LOOP_STARTED adds_so_far=\$(ls $D/bd0 $D/bd1 | grep -c '^y')" | tr '\n' ' '
echo

# One count sweep, run on whichever node: 'kind k total Acount Bcount'.
COUNT="for k in \$(seq 0 $KM); do echo bd \$k \$(ls $D/bd\$k 2>/dev/null | wc -l) \$(ls $D/bd\$k 2>/dev/null | grep -c '^y') \$(ls $D/bd\$k 2>/dev/null | grep -c '^b[0-9]'); echo sd \$k \$(ls $D/sd\$k 2>/dev/null | wc -l) \$(ls $D/sd\$k 2>/dev/null | grep -c '^z') \$(ls $D/sd\$k 2>/dev/null | grep -c '^w[0-9]'); echo f \$k \$(wc -l < $D/f\$k 2>/dev/null) \$(grep -c '^A-[0-9]' $D/f\$k 2>/dev/null) \$(grep -c '^B-[0-9]' $D/f\$k 2>/dev/null); done"

# The first join.  B mounts (its own kernel log marked first, so its side of
# the transition can be windowed later), reads every object cold, modifies
# each one, and syncs -- all before A touches them.
BJOINMK="D0959PM-BJOINMARK-$LABEL-$$"
bmt=$(rs 180 "$B" "echo $BJOINMK > /dev/kmsg; mount -t mxfs $DEV $MNT; echo B_JOIN_MOUNT_RC=\$?; sleep 1; echo B_COLD_BEFORE_BEGIN; $COUNT; echo B_COLD_BEFORE_END; for k in \$(seq 0 $KM); do : > $D/bd\$k/b1; : > $D/sd\$k/w1; echo B-1 >> $D/f\$k; done; echo B_MOD_RC=\$?; sync -f $MNT; echo B_SYNC_RC=\$?; echo B_AFTER_BEGIN; $COUNT; echo B_AFTER_END")
echo "$bmt" > "$OUT/B_join.txt"
echo "  JOIN $(echo "$bmt" | grep -a 'RC=' | tr '\n' ' ')"
case "$bmt" in *B_JOIN_MOUNT_RC=0*) ;; *) echo "RESULT: FAIL label=$LABEL $B could not join: $bmt"; exit 2 ;; esac

# A's loop must have ended on the flip; read only its report, not the tree.
conv=$(rs 90 "$A" "for i in \$(seq 1 60); do grep -aq LOOP_DONE /tmp/d0959pm_loop.txt 2>/dev/null && { echo LOOP_ENDED_AT=\$i; break; }; sleep 1; done; cat /tmp/d0959pm_loop.txt | tr '\n' ' '; echo; echo A_VIEW=\$(dmesg | grep -a 'MXFS-MEMBERSHIP' | tail -1 | grep -ao 'active_count=[0-9]*')")
echo "  CONVERGE $(echo "$conv" | tr '\n' ' ')"
case "$conv" in *JOIN_SEEN_AT_ADD=*) ;; *) echo "RESULT: FAIL label=$LABEL $A's add loop never saw active_count=2 after the join: $conv"; exit 2 ;; esac
NADDS=$(echo "$conv" | sed -n 's/.*LOOP_DONE adds=\([0-9]*\).*/\1/p' | head -1); NADDS=${NADDS:-0}

# A now flushes what it held dirty at the flip; its log is windowed from the
# join mark (the membership line, every write the probes saw, the refusal /
# poison / revert counters), then A's warm view.
fl=$(rs 120 "$A" "sync -f $MNT; echo SYNC_RC=\$?; sleep 3; dmesg | sed -n '/$JOINMK/,\$p' > /tmp/d0959pm_win.txt; cat /tmp/d0959pm_dirwr.sav > /sys/module/mxfs/parameters/dirwr; cat /tmp/d0959pm_iwr.sav > /sys/module/mxfs/parameters/iwr; echo MARK=\$(grep -ac '$JOINMK' /tmp/d0959pm_win.txt) MEMB=\$(grep -a 'MXFS-MEMBERSHIP' /tmp/d0959pm_win.txt | head -1 | cut -c1-16) LOOPEND=\$(grep -a 'LOOPEND-' /tmp/d0959pm_win.txt | head -1 | cut -c1-16) JOINFREEZE=\$(grep -a 'P-JOIN-FREEZE ' /tmp/d0959pm_win.txt | head -1 | cut -c1-16) JOININST=\$(grep -a 'P-JOIN-INSTALLED' /tmp/d0959pm_win.txt | head -1 | grep -ao 'attempts=[0-9]* ms=[0-9]*' | tr ' ' ',') INVALDONE=\$(grep -ac 'cached-view invalidation complete' /tmp/d0959pm_win.txt) INVALSTUCK=\$(grep -ac 'P232-INVAL-STUCK\|P-JOIN-FREEZE-INVAL-INCOMPLETE\|P-JOIN-PREPARE-RETRY' /tmp/d0959pm_win.txt) GATEWAIT=\$(grep -a 'P-D7-SETTLEGATE' /tmp/d0959pm_win.txt | head -1 | grep -ao 'waited=[0-9]*ms confirmed=[0-9]*' | tr ' ' ',') GATEREFUSED=\$(grep -ac 'P-D7-SETTLEGATE.*REFUSED' /tmp/d0959pm_win.txt) NLDIRSKIP=\$(grep -ac 'P56-NL-LOGGED-DIR-SKIP' /tmp/d0959pm_win.txt) DIRWRITE=\$(grep -ac 'P56-DIRWRITE' /tmp/d0959pm_win.txt) NLINKREV=\$(grep -ac 'P186-NLINK-REVERT' /tmp/d0959pm_win.txt) POISON=\$(grep -ac 'P34H-INCARN-POISON' /tmp/d0959pm_win.txt) SHUT=\$(grep -ac 'Shutting down filesystem\|P-WITHDRAW ' /tmp/d0959pm_win.txt) P218=\$(grep -ac 'P218-CLUSTER-AUTHORITY' /tmp/d0959pm_win.txt) RELMERGE=\$(grep -ac 'P56-RELOAD-MERGE' /tmp/d0959pm_win.txt) IDENT=\$(grep -ac 'P-RELOAD-IDENTICAL' /tmp/d0959pm_win.txt) P3W=\$(grep -ac 'P3W-DIRWR' /tmp/d0959pm_win.txt) WOULDSKIP=\$(grep -a 'P16-DIRBLK-SUBMIT' /tmp/d0959pm_win.txt | grep -ac 'would_skip=1') BEHIND=\$(grep -ac 'P191-POSTRELOAD-BEHIND' /tmp/d0959pm_win.txt) LINES=\$(wc -l < /tmp/d0959pm_win.txt); echo A_WARM_BEGIN; $COUNT; echo A_WARM_END")
echo "$fl" > "$OUT/A_flush.txt"
echo "  FLUSH $(echo "$fl" | grep -a 'SYNC_RC=\|MARK=' | tr '\n' ' ')"
rs 60 "$A" "cat /tmp/d0959pm_win.txt" > "$OUT/A_window.txt"
# B's side of the transition: its own prepare, its view, and how long its
# first grant waited for A's post-install beacon (the admission barrier).
bj=$(rs 60 "$B" "dmesg | sed -n '/$BJOINMK/,\$p' > /tmp/d0959pm_bwin.txt; echo B_JOINFREEZE=\$(grep -ac 'P-JOIN-FREEZE \|P-JOIN-INSTALLED' /tmp/d0959pm_bwin.txt) B_MEMB=\$(grep -a 'MXFS-MEMBERSHIP' /tmp/d0959pm_bwin.txt | head -1 | cut -c1-16) B_GATEWAIT=\$(grep -a 'P-D7-SETTLEGATE' /tmp/d0959pm_bwin.txt | head -1 | grep -ao 'mode=[0-9]* since_change=[0-9]*ms.*waited=[0-9]*ms confirmed=[0-9]*' | tr ' ' ',') B_GATES=\$(grep -ac 'P-D7-SETTLEGATE' /tmp/d0959pm_bwin.txt) B_GATEREFUSED=\$(grep -ac 'P-D7-SETTLEGATE.*REFUSED' /tmp/d0959pm_bwin.txt) B_SHUT=\$(grep -ac 'Shutting down filesystem\|P-WITHDRAW ' /tmp/d0959pm_bwin.txt) B_LINES=\$(wc -l < /tmp/d0959pm_bwin.txt)")
echo "  BJOIN $(echo "$bj" | tr '\n' ' ')"
rs 60 "$B" "cat /tmp/d0959pm_bwin.txt" > "$OUT/B_window.txt"

# What B sees now that both have flushed, then the durable truth: both
# leave, A comes back cold, and B comes back cold too.
bw=$(rs 60 "$B" "echo B_WARM_BEGIN; $COUNT; echo B_WARM_END")
echo "$bw" > "$OUT/B_warm.txt"
lv=$(rs 120 "$B" "umount $MNT; echo B_UMOUNT_RC=\$?")
lv2=$(rs 120 "$A" "umount $MNT; echo A_UMOUNT_RC=\$?; mount -t mxfs $DEV $MNT; echo A_REMOUNT_RC=\$?; echo A_COLD_BEGIN; $COUNT; echo A_COLD_END")
echo "$lv2" > "$OUT/A_cold.txt"
echo "  DURABLE $(echo "$lv" "$lv2" | grep -a 'RC=' | tr '\n' ' ')"
rb=$(rs 180 "$B" "mount -t mxfs $DEV $MNT; echo B_REMOUNT_RC=\$?; echo B_COLD_BEGIN; $COUNT; echo B_COLD_END")
echo "$rb" > "$OUT/B_cold.txt"
echo "  RESTORE $(echo "$rb" | grep -a 'RC=' | tr '\n' ' ')"
wall=$(( $(date +%s) - t0 ))

# The verdict, per object, from the count dumps.
python3 - "$OUT" "$K" "$NBD" "$NADDS" "$LABEL" "$SV" "$wall" <<'PY'
import sys, re
out, K, NBD, n, label, sv, wall = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), sys.argv[5], sys.argv[6], sys.argv[7]

def sweep(path, tag):
    txt = open(path, errors="replace").read()
    m = re.search(tag + r"_BEGIN\n(.*?)\n" + tag + r"_END", txt, re.S)
    d = {}
    if not m:
        return d
    for line in m.group(1).splitlines():
        p = line.split()
        if len(p) == 5 and p[0] in ("bd", "sd", "f"):
            try:
                d[(p[0], int(p[1]))] = tuple(int(x) for x in p[2:])
            except ValueError:
                pass
    return d

exp = {}
for i in range(1, n + 1):
    key = (("bd", "sd", "f")[i % 3], (i // 3) % K)
    exp[key] = exp.get(key, 0) + 1
late = set()
for i in range(max(1, n - 2), n + 1):
    late.add((("bd", "sd", "f")[i % 3], (i // 3) % K))

cold_b = sweep(out + "/B_join.txt", "B_COLD_BEFORE")
after_b = sweep(out + "/B_join.txt", "B_AFTER")
warm_a = sweep(out + "/A_flush.txt", "A_WARM")
warm_b = sweep(out + "/B_warm.txt", "B_WARM")
cold_a = sweep(out + "/A_cold.txt", "A_COLD")
cold_b2 = sweep(out + "/B_cold.txt", "B_COLD")

objs = [(k, j) for k in ("bd", "sd", "f") for j in range(K)]
if len(cold_a) != len(objs) or len(cold_b) != len(objs):
    print("D0959-PEERMOD label=%s sv=%s adds=%d wall=%ss evidence=%s" % (label, sv, n, wall, out))
    print("  READ: INFRA — count sweeps incomplete (B_COLD_BEFORE %d, A_COLD %d of %d objects)" % (len(cold_b), len(cold_a), len(objs)))
    sys.exit(0)

stale_at_join = []     # B read fewer incumbent entries than the loop made
lost_a = []            # incumbent entries missing from the durable truth
lost_b = []            # the newcomer's one add missing from the durable truth
late_notes = []
for o in objs:
    e = exp.get(o, 0)
    cb = cold_b[o]
    ca = cold_a[o]
    if cb[1] < e:
        stale_at_join.append((o, cb[1], e))
    note = None
    if ca[1] != e:
        note = "A:%d/%d" % (ca[1], e)
    if ca[2] != 1:
        note = (note + " " if note else "") + "B:%d/1" % ca[2]
    if note:
        if o in late:
            late_notes.append("%s%d[%s]" % (o[0], o[1], note))
        elif ca[1] != e and ca[2] != 1:
            lost_a.append("%s%d[%s]" % (o[0], o[1], note))
        elif ca[1] != e:
            lost_a.append("%s%d[%s]" % (o[0], o[1], note))
        else:
            lost_b.append("%s%d[%s]" % (o[0], o[1], note))
touched = sum(1 for o in objs if exp.get(o, 0) > 0)
flush = open(out + "/A_flush.txt", errors="replace").read()
def field(name, default=""):
    m = re.search(r"\b" + name + r"=(\S*)", flush)
    return m.group(1) if m else default
shut = int(field("SHUT", "0") or 0)
joininst = field("JOININST")          # attempts=N,ms=M when the freeze-ordered transition ran on A
invalstuck = int(field("INVALSTUCK", "0") or 0)
gatewait = field("GATEWAIT")
print("D0959-PEERMOD label=%s sv=%s adds=%d objects=%d touched=%d stale_at_join=%d lost_A=%d lost_B=%d late_objs=%d shut=%d join=%s inval_retries=%d gate=%s wall=%ss evidence=%s"
      % (label, sv, n, len(objs), touched, len(stale_at_join), len(lost_a), len(lost_b), len(late), shut, joininst or "-", invalstuck, gatewait or "-", wall, out))
if stale_at_join:
    print("  STALE_AT_JOIN (object, B saw, loop made): " + " ".join("%s%d:%d/%d" % (o[0], o[1], s, e) for o, s, e in stale_at_join[:24]) + (" ..." if len(stale_at_join) > 24 else ""))
if late_notes:
    print("  LATE (touched in the last 3 iterations, not evidence): " + " ".join(late_notes))
if n == 0:
    print("  READ: VACUOUS — the add loop made no modification before the flip")
elif shut:
    print("  READ: SHUTDOWN — the incumbent's filesystem shut down across the join (SHUT=%d); A-entries missing on %d objects, B-adds missing on %d objects" % (shut, len(lost_a), len(lost_b)))
elif lost_a or lost_b:
    print("  READ: LOST — A-entries missing on %d objects [%s] B-adds missing on %d objects [%s] — after both nodes left, a fresh mount is missing changes one side made; the incumbent's dirty NL images and the newcomer's first grant were not ordered"
          % (len(lost_a), " ".join(lost_a[:16]), len(lost_b), " ".join(lost_b[:16])))
elif joininst and not stale_at_join:
    print("  READ: NOT REPRODUCED — the incumbent's freeze-ordered transition (%s) landed its state before the newcomer was admitted: B read every object complete cold and every entry of both sides survived a cold remount" % joininst)
elif not stale_at_join:
    print("  READ: NOT REPRODUCED, WEAK — nothing survived dirty into the join (B read every object complete cold) and no freeze-ordered transition ran on A; the AIL had landed everything before B's first read")
else:
    print("  READ: NOT REPRODUCED — %d objects were read stale by B at the join, yet every entry of both sides survived a cold remount (read the A_window for how the dirty images were landed)" % len(stale_at_join))
PY
[ "$wall" -gt 150 ] && echo "  the budget rule: wall ${wall}s exceeds the 150 s derived bound"
exit 0
