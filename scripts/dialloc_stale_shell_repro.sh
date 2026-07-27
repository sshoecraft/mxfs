#!/bin/bash
# dialloc_stale_shell_repro.sh — DETERMINISTIC repro for the stale dead-shell
# dialloc corruption (pve1 ino-489 "-117 Free inode not marked free" shutdown,
# dossier tests/logs/pve1_agi_wedge_20260721_035122Z, autopsy probe P-CR63).
#
# THE DEFECT (xfs_iget_cache_hit hole): an IRECLAIMABLE dead shell with stale
# nonzero i_mode — formed when a PEER frees an inode this node has cached, so
# local xfs_ifree (the only thing that zeroes in-core i_mode) never runs and
# the sess47 anti-double-free guard (INACT-SKIP-STALE) parks the shell as-is.
# A later local create diallocs the same ino (free is cluster-authoritative
# under the AG DLM); iget(XFS_IGET_CREATE) cache-HITS the dead shell; the MXFS
# CREATE rescue branch excludes IRECLAIMABLE; xfs_iget_check_free_state sees
# mode!=0 -> -EFSCORRUPTED -> dirty xfs_trans_cancel -> forced shutdown.
#
# WHY fd-choreography: the incident state needs in-core nlink==0 ADOPTED from
# the peer's unlink BEFORE the peer's ifree destages (iput_final evicts
# nlink==0 inodes immediately — no LRU — which is what parks the dead shell).
# Every racy variant (concurrent rm, drop_caches) either misses the adopt
# window or reclaims the shells entirely.  Holding fds on both nodes pins each
# phase open so the window is forced, not raced:
#
#   P1  n1: create f0..fN, sync                       (n1-affine inos, cached)
#   P2  n1+n2: hold O_RDONLY fds on f1..fN            (pin both nodes' i_count)
#   P3  n2: rm f1..fN                                 (unlink only: nlink=0 on
#                                                      disk at BAST-flush; n2's
#                                                      ifree DEFERRED by its fds)
#   P4  n1: fstat+pread+flistxattr each fd            (ILOCK -> slow DLM acquire
#                                                      -> reload -> ADOPT
#                                                      nlink=0, mode kept —
#                                                      P9-NLEDGE from_disk 1->0)
#   P5  n2: close fds                                 (sync-inactive runs the
#                                                      REAL ifree: disk mode=0)
#   P6  n1: close fds                                 (iput_final nlink==0 ->
#                                                      immediate evict ->
#                                                      sess47 disk-free skip ->
#                                                      INACT-SKIP-STALE -> dead
#                                                      shells park IRECLAIMABLE)
#   P7  n1: rm f0 (blocking AG difree pulls the AG DLM back — dialloc pass 1
#       is TRYLOCK and skips peer-held AGs) + create burst g1..gN
#       -> dialloc reuses the freed inos -> cache-HIT on dead shells
#       -> pre-fix: P-CR63-DEADSHELL + "not marked free" -117 + shutdown
#       -> post-fix: rescued, creates succeed, no shutdown
#
# Exit 42 = corruption reproduced (expected pre-fix); 0 = clean (post-fix);
# 2 = environment/choreography failure.
set -u
N1=${N1:-test1}
N2=${N2:-test2}
PASS=${MXFS_PASS:-/tmp/.mxfs_pass}
SSH=${MXFS_SSH:-/src/mxfs/tools/mxfs_sshpass.sh}
MNT=${MXFS_MOUNT:-/mnt/shared}
NF=${1:-32}
DIR="$MNT/.sshell_$(date +%s)"
SIG='not marked free|P-CR63-DEADSHELL|P-CR63-IGRAB-FAIL|Corruption of in-memory|Internal error xfs_trans_cancel|Shutting down filesystem'

say() { echo "[sshell $(date +%H:%M:%S)] $*"; }
sq() { "$SSH" "$1" "$PASS" "$2" 2>/dev/null | grep -v -i 'unauthorized\|disconnect immediately' | grep -v '^[[:space:]]*$'; }

waitflag() { # node flagfile timeout_s — ONE ssh session, remote-side poll
  if ! "$SSH" "$1" "$PASS" "n=\$(( $3 * 2 )); for i in \$(seq 1 \$n); do test -f $2 && exit 0; sleep 0.5; done; exit 1" >/dev/null 2>&1; then
    say "TIMEOUT waiting for $2 on $1"; return 1
  fi
  return 0
}

HOLDER='import os,sys,time
d=sys.argv[1]; n=int(sys.argv[2]); do_ilock=int(sys.argv[3])
fds=[]
for i in range(1,n+1):
    try: fds.append(os.open(f"{d}/f{i}",os.O_RDONLY))
    except OSError: pass
open("/run/sshell_open","w").write(str(len(fds)))
deadline=time.time()+600
def waitf(p):
    while not os.path.exists(p):
        if time.time()>deadline: sys.exit(3)
        time.sleep(0.05)
if do_ilock:
    waitf("/run/sshell_go")
    a=0
    for fd in fds:
        try:
            os.fstat(fd); os.pread(fd,1,0)
            try: os.listxattr(fd)
            except OSError: pass
            a+=1
        except OSError: pass
    open("/run/sshell_statted","w").write(str(a))
waitf("/run/sshell_close")
for fd in fds:
    try: os.close(fd)
    except OSError: pass
open("/run/sshell_closed","w").close()'

for NODE in "$N1" "$N2"; do
  if ! "$SSH" "$NODE" "$PASS" "grep -q ' $MNT ' /proc/mounts" >/dev/null 2>&1; then
    say "FATAL: $NODE has no mount at $MNT — prep the cluster first (run.sh)"
    exit 2
  fi
  "$SSH" "$NODE" "$PASS" "pkill -9 -f 'sshell_holder[.]py' 2>/dev/null; rm -f /run/sshell_*; true" >/dev/null 2>&1
  "$SSH" "$NODE" "$PASS" "cat > /run/sshell_holder.py" <<<"$HOLDER" >/dev/null 2>&1
done
V1=$(sq "$N1" "cat /sys/module/mxfs/srcversion" | tr -d '[:space:]')
V2=$(sq "$N2" "cat /sys/module/mxfs/srcversion" | tr -d '[:space:]')
say "srcversion n1=$V1 n2=$V2 nfiles=$NF dir=$DIR"

MARK="SSHELL_$(date +%s%N)"
for NODE in "$N1" "$N2"; do
  "$SSH" "$NODE" "$PASS" "echo $MARK > /dev/kmsg" >/dev/null 2>&1
done

say "P1: n1 creates f0..f$NF + sync"
INOS_A=$(sq "$N1" "mkdir -p $DIR && cd $DIR && for i in \$(seq 0 $NF); do echo x > f\$i; done && sync && for i in \$(seq 1 $NF); do stat -c %i f\$i; done" | grep -E '^[0-9]+$' | sort -n | uniq)
[ -n "$INOS_A" ] || { say "FATAL: n1 create failed"; exit 2; }
say "  n1 inos: $(echo "$INOS_A" | head -1)..$(echo "$INOS_A" | tail -1) (n=$(echo "$INOS_A" | wc -l))"

say "P2: holders open fds on both nodes"
"$SSH" "$N1" "$PASS" "cd /run && setsid nohup python3 /run/sshell_holder.py $DIR $NF 1 >/run/sshell_holder.log 2>&1 </dev/null & exit 0" >/dev/null 2>&1
"$SSH" "$N2" "$PASS" "cd /run && setsid nohup python3 /run/sshell_holder.py $DIR $NF 0 >/run/sshell_holder.log 2>&1 </dev/null & exit 0" >/dev/null 2>&1
waitflag "$N1" /run/sshell_open 30 || exit 2
waitflag "$N2" /run/sshell_open 30 || exit 2
say "  open counts: n1=$(sq "$N1" 'cat /run/sshell_open') n2=$(sq "$N2" 'cat /run/sshell_open')"

say "P3: n2 rm f1..f$NF (unlink only; ifree deferred by n2's fds)"
sq "$N2" "cd $DIR && for i in \$(seq 1 $NF); do rm -f f\$i; done && echo n2-unlinked"

say "P4: n1 fd-ops adopt nlink=0 (ILOCK slow acquire + reload)"
"$SSH" "$N1" "$PASS" "touch /run/sshell_go" >/dev/null 2>&1
waitflag "$N1" /run/sshell_statted 180 || exit 2
say "  n1 statted: $(sq "$N1" 'cat /run/sshell_statted') fds"

say "P5: n2 closes fds (real ifree runs now)"
"$SSH" "$N2" "$PASS" "touch /run/sshell_close" >/dev/null 2>&1
waitflag "$N2" /run/sshell_closed 240 || exit 2
sq "$N2" "sync; echo n2-ifreed"

say "P6: n1 closes fds (nlink==0 -> immediate evict -> dead shells park)"
"$SSH" "$N1" "$PASS" "touch /run/sshell_close" >/dev/null 2>&1
waitflag "$N1" /run/sshell_closed 240 || exit 2

say "P7: n1 rm f0 (AG reclaim) + create burst (dialloc reuse of dead-shell inos)"
"$SSH" "$N1" "$PASS" "cd $DIR && rm -f f0; ok=0; fail=0; for i in \$(seq 1 $NF); do if echo y > g\$i 2>/dev/null; then ok=\$((ok+1)); else fail=\$((fail+1)); fi; done; echo CREATES ok=\$ok fail=\$fail; stat -c %i g* 2>/dev/null" > /tmp/sshell_n1.out 2>&1
grep 'CREATES' /tmp/sshell_n1.out || say "WARN: create burst produced no status (node shut down?)"
INOS_B=$(grep -E '^[0-9]+$' /tmp/sshell_n1.out | sort -n)
OVER=$(comm -12 <(echo "$INOS_A") <(echo "$INOS_B") | wc -l)
say "ino reuse overlap: $OVER of $NF"

sleep 2
RC=0
for NODE in "$N1" "$N2"; do
  DM=$("$SSH" "$NODE" "$PASS" "dmesg 2>/dev/null | awk -v m=$MARK 'f{print} \$0~m{f=1}'" 2>/dev/null | grep -v 'Permanently added')
  say "$NODE: P9-NLEDGE-adopts=$(echo "$DM" | grep -c 'P9-NLEDGE from_disk') INACT-SKIP-STALE=$(echo "$DM" | grep -c 'INACT-SKIP-STALE') P-CR63-SHELL=$(echo "$DM" | grep -c 'P-CR63-SHELL') P-CR63-DEADSHELL=$(echo "$DM" | grep -c 'P-CR63-DEADSHELL')"
  HITS=$(echo "$DM" | grep -E "$SIG" || true)
  if [ -n "$HITS" ]; then
    say "=== $NODE ESCALATION ==="
    echo "$HITS" | head -12
    RC=42
  fi
done

if [ "$RC" = "42" ]; then
  say "REPRODUCED: stale dead-shell dialloc corruption (exit 42)"
else
  say "clean run — no corruption signature (exit 0)"
  sq "$N1" "rm -rf $DIR" || true
fi
exit $RC
