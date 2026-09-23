#!/bin/bash
# d0535_xattr_reuse.sh [victim] [peer] [tries]
#
# D-0535 generic (non-dirshard) reproducer: a node's cached in-core shell of
# an inode that carried an attr fork is reused for a CREATE after a PEER
# freed the number.  mxfs_dlm_reset_inode_for_create (the P-CR63 path) used
# xfs_idestroy_fork on i_af, which leaves if_bytes behind; the new
# incarnation's first xattr set grew the shortform fork from that phantom
# length and the next flush failed xfs_attr_shortform_verify -> shutdown
# (chain 115 s473b, 0.64.22, the sharded parent's locator).  0.64.23 zaps the
# fork (xfs_ifork_zap_attr) and prints P-RESET-STALE-AF with the inherited
# state.
#
#   victim V: creates f, sets user.d0535 (V's shell now has a shortform attr
#             fork), records ino I, drops its reference (nothing keeps the
#             shell busy; it stays cached, not reclaimed)
#   peer   P: rm f  (P's inactivation frees I; V's xfs_ifree never runs)
#   victim V: creates g_1..g_N in the same directory until one lands on I
#             (dialloc picks the lowest free number in V's own AG); sets
#             user.d0535 on it; sync x2 (AIL push flushes the dinode through
#             the verifier)
# Verdict: reuse reached (some g_k got ino I) — else VACUOUS; on the fixed
# build P-RESET-STALE-AF >= 1 with af_bytes>0 on V and zero
# 'xfs_attr_shortform_verify' / 'Shutting down' on V; on 0.64.22 the same lap
# shuts V down.
# budget: every step is a handful of creates/xattr ops (< 1 s native); the
# whole script < 60 s including 4 ssh calls.  Exit 0 PASS, 1 FAIL, 2 INFRA/VACUOUS.
set -u
V=${1:-test1}; P=${2:-test2}; N=${3:-64}
MNT=/mnt/shared
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH=$REPO/tools/mxfs_sshpass.sh
TS=$(date -u +%Y%m%dT%H%M%SZ)
OUT=$REPO/tests/evidence/${TS}_d0535_xattr_reuse
mkdir -p "$OUT"
D=$MNT/.d0535_$TS
say() { echo "[d0535] $*"; }
r() { local n="$1"; shift; timeout 60 "$SSH" "$n" "$@" 2>&1 | grep -av '^Unauthorized access\|^If you are not\|^Warning: Permanently\|^$'; }
echo "=== d0535_xattr_reuse victim=$V peer=$P tries=$N @ $TS out=$OUT ==="
for n in $V $P; do
    m=$(r $n "grep -c ' $MNT mxfs ' /proc/mounts; cat /sys/module/mxfs/srcversion" | tr '\n' ' ')
    echo "$n: $m" | tee "$OUT/pre_$n.txt"
    case "$m" in 1\ *) ;; *) say "INFRA: $MNT not mounted on $n ($m)"; echo "RESULT INFRA d0535"; exit 2;; esac
done
MARK=$(r $V "cut -d' ' -f1 /proc/uptime")
# 1. victim creates f with an xattr, notes I
I=$(r $V "mkdir -p $D && echo seed > $D/f && setfattr -n user.d0535 -v phantom32 $D/f && sync && stat -c %i $D/f")
case "$I" in ''|*[!0-9]*) say "INFRA: victim create/setfattr failed: $I"; echo "RESULT INFRA d0535"; exit 2;; esac
say "victim f ino=$I (attr fork in V's cache)"
# 2. peer removes it (the free happens on P; V keeps its shell)
# sess474 (chain 115 s473c, both pairs VACUOUS): the peer's inactivation
# DEFERs (P128-INACT-DEFER keeps its EX grant cached on I) and the victim's
# dialloc then SKIPS I — the inobt record showed I free (pre mask bit set) and
# the allocation took I+1 (P150-ALLOC-FIN off=5 for I=132).  Make the peer
# release first: drop_caches evicts the corpse (P141-UNLK-EXCLR on P).
o=$(r $P "ls -l $D/f > /dev/null && getfattr -n user.d0535 $D/f > /dev/null 2>&1; rm -f $D/f; sync; sleep 2; echo 2 > /proc/sys/vm/drop_caches; sleep 3; echo rm_ok; dmesg | grep -ac 'P141-UNLK-EXCLR ino=$I '")
echo "$o" | grep -q rm_ok || { say "INFRA: peer rm failed: $o"; echo "RESULT INFRA d0535"; exit 2; }
say "peer rm+evict: P141-UNLK-EXCLR ino=$I lines on $P = $(echo "$o" | tail -1)"
# 3. victim creates until the number comes back, then sets the xattr and flushes
o=$(r $V "hit=; inos=; for k in \$(seq 1 $N); do : > $D/g_\$k; i=\$(stat -c %i $D/g_\$k); inos=\"\$inos \$i\"; if [ \$i = $I ]; then hit=g_\$k; break; fi; done; echo hit=\$hit; echo inos=\$inos; if [ -n \"\$hit\" ]; then setfattr -n user.d0535 -v phantom32again $D/\$hit; echo setfattr_rc=\$?; sync; sleep 1; sync; sleep 2; getfattr -n user.d0535 --only-values $D/\$hit; echo; echo getfattr_rc=\$?; fi; echo mounted=\$(grep -c ' $MNT mxfs ' /proc/mounts)")
echo "$o" > "$OUT/reuse_$V.txt"; echo "$o" | sed 's/^/  /'
hit=$(echo "$o" | grep -ao '^hit=.*' | cut -d= -f2)
# 4. evidence
r $V "dmesg | sed -n 's/^\[ *\([0-9.]*\)\] \(.*\)/\1 \2/p' | awk -v m=$MARK '\$1+0 >= m+0' | grep -a 'P-RESET-STALE-AF\|P-CR63\|P9-NLEDGE reset4create\|shortform_verify\|Shutting down\|Corruption\|P-SESSION-POISON\|Metadata corruption' | head -40" > "$OUT/dmesg_$V.txt"
stale=$(grep -ac 'P-RESET-STALE-AF' "$OUT/dmesg_$V.txt"); reset=$(grep -ac 'P-CR63-SHELL\|reset4create' "$OUT/dmesg_$V.txt")
verify=$(grep -ac 'shortform_verify' "$OUT/dmesg_$V.txt"); shut=$(grep -ac 'Shutting down\|P-SESSION-POISON' "$OUT/dmesg_$V.txt")
say "victim probes (post-mark): reset4create/P-CR63=$reset P-RESET-STALE-AF=$stale shortform_verify=$verify shutdown=$shut"
head -6 "$OUT/dmesg_$V.txt" | cut -c1-220
r $V "rm -rf $D 2>/dev/null; true" > /dev/null
# sess474: the victim's shell must still be CACHED for the shape (a cache-miss
# create has no inherited fork): P-CR63-SHELL ino=0x<I hex> names the cache hit.
shell=$(grep -ac "P-CR63-SHELL ino=0x$(printf %x "$I") " "$OUT/dmesg_$V.txt")
if [ -z "$hit" ]; then echo "RESULT VACUOUS d0535: ino $I was not reused within $N creates on $V (got: $(echo "$o" | grep -ao '^inos=.*' | cut -c6-80)) shell_hit=$shell out=$OUT"; exit 2; fi
if [ "$verify" != 0 ] || [ "$shut" != 0 ]; then echo "RESULT FAIL d0535: reuse of ino $I as $hit -> shortform_verify=$verify shutdown=$shut (the phantom attr fork) out=$OUT"; exit 1; fi
if [ "$reset" = 0 ]; then echo "RESULT VACUOUS d0535: ino $I reused as $hit but no reset4create/P-CR63 on $V (the shell was not cache-hit; reclaimed?) out=$OUT"; exit 2; fi
if [ "$stale" = 0 ]; then echo "RESULT FAIL d0535: reset ran ($reset) but P-RESET-STALE-AF=0 — the inherited fork state was not seen (build < 0.64.23, or the shell had no fork) out=$OUT"; exit 1; fi
echo "RESULT PASS d0535: ino $I reused as $hit, P-RESET-STALE-AF=$stale (inherited attr fork zapped), verify=0 shutdown=0 out=$OUT"
exit 0
