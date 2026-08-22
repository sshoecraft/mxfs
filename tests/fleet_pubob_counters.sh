#!/bin/bash
# sess389: one-pass per-node dmesg counter sweep for the publication-durability
# gate probes (P55B/P245-RELOG/P177-KEPT-AHEAD/P88/P87/P119-unlink/etc).
# Usage: tests/fleet_pubob_counters.sh [N=32]   — prints fleet sums (n:nodes>0)
# One dmesg read per node (a 24-grep sweep at 1.1s/grep x32 parallel blew a
# 40s cap on a 110k-line ring; this is ~2s/node).
N=${1:-32}
cd "$(dirname "$0")/.." || exit 1
D=$(mktemp -d)
for i in $(seq 1 "$N"); do
  ( timeout 60 tools/mxfs_sshpass.sh test$i "dmesg | awk '
/Shutting down filesystem/{s++} /P-NOINO-RELFENCE-WEDGE/{w++} /P-IUNL-LOGSAME/{ls++}
/P55B-PUBOB-PR-FLUSH/{p55b++} /P245-RELOG ino/{relog++} /P245-RELOG-FAIL/{relogf++}
/P245-CLEAN-MISMATCH/{cm++} /P177-KEPT-AHEAD/{ka++} /P177-PUBOB-SUPERSEDED/{sup++}
/P177-OBLIGATION-DROPPED/{p177++}
/P119-NONEX-FLUSH-SKIP/ && /incore_nlink=0 disk_nlink=[1-9]/{p119pub++}
/P88-PUBOB-UNREPAIRED/{p88u++} /P88-PUBOB-REPAIRED/{p88r++} /P88-PUBOB-NOSHELL/{p88ns++}
/P87-PUBLISH-DEFER-EXHAUSTED/{p87x++} /P87-PUBLISH-REPAIRED/{p87rep++} /P87-REPAIR-FAIL/{p87f++}
/torn-live-no-local-unlink/{tl++} /P88-PUBOB-RECLAIM-REFUSED/{rr++}
/P86-AGI-UNLINKED-PUBLISH /{p86s++} /P86-AGI-UNLINKED-BADHEAD/{p86b++}
/P245-REL-OBLIGATION-CONVERT/{p245++} /P382-RELDEFER-RELOAD/{p382++} /P-INODE-WEDGE/{wedge++}
/P-IUNL-FOSSIL-RESET/{fr++} /P82-ADD-FAIL/{af++} /P217-RENAME-FAILSITE/{rf++}
/P86-AGI-PUBLISH-TOTALS/{tot=\$0}
END{printf \"s=%d w=%d ls=%d p55b=%d relog=%d relogf=%d cm=%d ka=%d sup=%d p177=%d p119pub=%d p88u=%d p88r=%d p88ns=%d p87x=%d p87rep=%d p87f=%d tl=%d rr=%d p86s=%d p86b=%d p245=%d p382=%d wedge=%d fr=%d af=%d rf=%d\n\", s,w,ls,p55b,relog,relogf,cm,ka,sup,p177,p119pub,p88u,p88r,p88ns,p87x,p87rep,p87f,tl,rr,p86s,p86b,p245,p382,wedge,fr,af,rf; if (tot!=\"\") print \"TOT \" tot}'; echo m=\$(grep -c mxfs /proc/mounts) r=\$(timeout 5 ls /mnt/shared >/dev/null 2>&1 && echo 1 || echo 0)" >"$D/t$i" 2>/dev/null; echo $? >"$D/rc$i" ) &
done
wait 2>/dev/null
echo "responders: $(find "$D" -name 't*' -size +0 | wc -l)/$N rc!=0: $(grep -L '^0$' "$D"/rc* 2>/dev/null | wc -l)"
cat "$D"/t* | grep -v "^TOT" | grep -oE '[a-z0-9]+=[0-9]+' | awk -F= '{s[$1]+=$2;if($2>0)n[$1]++} END{for(k in s)printf "%s=%d(n:%d) ",k,s[k],n[k];print""}'
echo "P86 totals summed: $(cat "$D"/t* | grep '^TOT' | grep -oE '(heads|joint_ok|REPAIRED|SPLIT|BADHEAD)=[0-9]+' | awk -F= '{s[$1]+=$2} END{for(k in s)printf "%s=%d ",k,s[k]}')"
echo "dir: $D"
