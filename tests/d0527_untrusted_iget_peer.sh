#!/bin/bash
# tests/d0527_untrusted_iget_peer.sh <creator-node> <peer-node> [label]
#
# D-0527 (sess470): every XFS_IGET_UNTRUSTED iget on MXFS answers its
# "is this number allocated?" question from xfs_imap_lookup, which reads the
# AGI + inobt through xfs_ialloc_read_agi(pag, NULL, ...) WITHOUT the AG DLM
# lock — i.e. from whatever image this node last cached.  A peer's allocation
# of the number is invisible there until this node next takes that AG.
# The dir-sharding module hit it first (D-0526: -EINVAL for every peer op);
# this harness measures the same gap through the NFS/handle path
# (xfs_nfs_get_inode -> XFS_IGET_UNTRUSTED), which needs no sharding at all.
#
# Shape (instrumentation, not a fix):
#   1. creator C makes a directory + one WARM file w; peer P opens w by
#      handle -> P has now read C's AG's AGI/inobt into its cache (the
#      lookup is UNTRUSTED, so it walks the inobt).
#   2. C creates N more files (N=200 > 3 inode chunks of 64) so the inobt
#      C's AG changes on the platter; C mints a handle for the LAST file.
#   3. P opens that handle R times over ~10 s.  Then P looks the file up BY
#      PATH (a trusted iget: must succeed), then opens the handle again.
#   4. P's dmesg is swept for the 0.64.12 probes P-IMAP-UNTRUSTED-FREE /
#      -NOREC and P-IGET-ENOENT.
# RESULT PASS   = every handle open on P succeeded (gap not observed).
# RESULT FAIL   = any handle open of a C-created file failed on P
#                 (errno + the probe lines attribute it).  That is the
#                 defect; the path lookup succeeding alongside proves the
#                 file exists and only the untrusted route refuses it.
# RESULT INFRA  = the warm handle (step 1) failed, or a node is unmounted.
# budget: whole harness < 60 s (creates ~1 s, handle opens ~10 s).
set -u
cd /src/mxfs || exit 1
C=${1:?creator node}; P=${2:?peer node}; LABEL=${3:-d0527}
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
TS=$(date -u +%Y%m%dT%H%M%SZ)
OUT=tests/evidence/${TS}_d0527_${LABEL}
mkdir -p "$OUT"
PROBE=/src/mxfs/tools/handle_probe
[ -x "$PROBE" ] || cc -O2 -static -o "$PROBE" tools/handle_probe.c || { echo "RESULT INFRA d0527: handle_probe did not compile"; exit 3; }
r() { timeout 40 $SSH "$1" "$2" 2>/dev/null | grep -av '^Unauthorized\|^If you\|^$'; }
say() { echo "[d0527] $*"; }
D=$MNT/d0527_$TS

for n in $C $P; do
  m=$(r $n "grep -c ' $MNT mxfs ' /proc/mounts; cat /sys/module/mxfs/srcversion" | tr '\n' ' ')
  echo "$n: $m" | tee "$OUT/pre_$n.txt"
  case "$m" in 1\ *) ;; *) echo "RESULT INFRA d0527: $n not mounted ($m)"; exit 3;; esac
done
# sess473: the mark is the peer's UPTIME (seconds), and the probe sweep below
# keeps only ring lines stamped at or after it.  The old sweep was the whole
# ring: chain 110 s472k counted 5 NOREC lines stamped 862-870 s on test4
# (15:42Z, the previous run on 0.64.12) against a 16:34Z run and reported
# 'untrusted_norec=5' for a lap that produced none.
MARK=$(r $P "cut -d' ' -f1 /proc/uptime")
r $P "dmesg | tail -1 | cut -c1-40; echo mark_uptime=$MARK; cat /sys/module/mxfs/parameters/untrusted_imap_aglock_n 2>/dev/null" > "$OUT/p_dmesg_mark.txt"
AGL0=$(sed -n '3p' "$OUT/p_dmesg_mark.txt")

# 1. warm: C creates, P opens by handle (loads C's AG inobt on P)
say "warm file on $C, handle open on $P"
W=$(r $C "mkdir -p $D && echo warm > $D/w && stat -c %i $D/w && $PROBE encode $D/w")
echo "$W" > "$OUT/warm_encode.txt"
WINO=$(echo "$W" | sed -n 1p); WH=$(echo "$W" | sed -n 2p)
WO=$(r $P "$PROBE open $MNT $WH 1 0"); echo "$WO" > "$OUT/warm_open.txt"
say "warm ino=$WINO on $P: $WO"
case "$WO" in attempt=1\ rc=0*) ;; *) echo "RESULT INFRA d0527: warm handle open failed on $P: $WO"; exit 3;; esac

# 2. C allocates 200 more inodes in its AG, handle for the last one
T0=$(date +%s)
E=$(r $C "for i in \$(seq 1 200); do echo x > $D/f\$i; done; stat -c '%i' $D/f200; $PROBE encode $D/f200")
echo "$E" > "$OUT/last_encode.txt"
LINO=$(echo "$E" | sed -n 1p); LH=$(echo "$E" | sed -n 2p)
say "200 creates on $C wall=$(( $(date +%s) - T0 ))s last ino=$LINO"

# 3. P: handle opens over ~10 s, then a path lookup, then the handle again
T0=$(date +%s%N)
O1=$(r $P "$PROBE open $MNT $LH 5 2000"); echo "$O1" > "$OUT/peer_open_before_path.txt"
# budget: 5 attempts with 2000 ms sleeps between = 8 s of sleep; the cold
# handle open itself (one AG bracket + one cluster read) must be < 300 ms,
# so the whole call is bounded at 8 s + 5 x 300 ms + ssh.
say "peer cold handle opens wall=$(( ($(date +%s%N) - T0) / 1000000 )) ms (includes 8000 ms of harness sleep)"
echo "$O1" | sed 's/^/  /'
PL=$(r $P "stat -c '%i %h %s' $D/f200 2>&1; echo path_rc=\$?"); echo "$PL" > "$OUT/peer_path_lookup.txt"
say "path lookup on $P: $(echo "$PL" | tr '\n' ' ')"
O2=$(r $P "$PROBE open $MNT $LH 3 1000"); echo "$O2" > "$OUT/peer_open_after_path.txt"
echo "$O2" | sed 's/^/  /'
# the creator itself must decode its own handle
O3=$(r $C "$PROBE open $MNT $LH 1 0"); echo "$O3" > "$OUT/creator_open.txt"
say "creator's own handle open: $O3"

# 4. probes
# only ring lines stamped at/after the mark (uptime seconds) count
r $P "dmesg | sed -n 's/^\[ *\([0-9.]*\)\] \(.*\)/\1 \2/p' | awk -v m=$MARK '\$1+0 >= m+0' | grep -a 'P-IMAP-UNTRUSTED\|P-IGET-ENOENT\|P4ST-ENOENT' | tail -20" > "$OUT/peer_probes.txt"
AGL1=$(r $P "cat /sys/module/mxfs/parameters/untrusted_imap_aglock_n 2>/dev/null")
nfree=$(grep -ac P-IMAP-UNTRUSTED-FREE "$OUT/peer_probes.txt"); nnorec=$(grep -ac P-IMAP-UNTRUSTED-NOREC "$OUT/peer_probes.txt")
say "peer probe lines (post-mark $MARK s): untrusted_free=$nfree untrusted_norec=$nnorec iget_enoent=$(grep -ac P-IGET-ENOENT "$OUT/peer_probes.txt") aglock_fail=$(grep -ac P-IMAP-UNTRUSTED-AGLOCK-FAIL "$OUT/peer_probes.txt") aglock_n=${AGL0:-?}->${AGL1:-?}"
head -5 "$OUT/peer_probes.txt" | cut -c1-200

fails=$(grep -ac 'rc=-1' "$OUT/peer_open_before_path.txt" "$OUT/peer_open_after_path.txt" | awk -F: '{s+=$2} END {print s+0}')
pathok=$(grep -ac 'path_rc=0' "$OUT/peer_path_lookup.txt")
r $C "rm -rf $D" > /dev/null
if [ "$fails" -gt 0 ]; then
  echo "RESULT FAIL d0527: $fails of 8 handle opens of a $C-created file failed on $P (path lookup ok=$pathok); first: $(grep -a 'rc=-1' "$OUT/peer_open_before_path.txt" "$OUT/peer_open_after_path.txt" | head -1 | cut -d: -f2-) out=$OUT"
  exit 1
fi
# sess473: the ledger's verification condition is opens 8/8 AND zero
# untrusted-free/norec probe lines on the serving node for THIS lap AND the
# AG bracket engaging (counter advancing) — a PASS on the opens alone is
# not the fix being exercised.
if [ "$nfree" != 0 ] || [ "$nnorec" != 0 ]; then
  echo "RESULT FAIL d0527: 8/8 opens succeeded but the serving node still read the inobt unlocked: untrusted_free=$nfree untrusted_norec=$nnorec (post-mark) out=$OUT"
  exit 1
fi
if [ -z "${AGL0:-}" ] || [ -z "${AGL1:-}" ] || [ "$AGL1" -le "$AGL0" ]; then
  echo "RESULT VACUOUS d0527: 8/8 opens succeeded but untrusted_imap_aglock_n did not advance (${AGL0:-?}->${AGL1:-?}): the AG bracket was not exercised out=$OUT"
  exit 1
fi
echo "RESULT PASS d0527: 8/8 handle opens of a $C-created file succeeded on $P (path lookup ok=$pathok) probes free=0 norec=0 aglock_n=$AGL0->$AGL1 out=$OUT"
exit 0
