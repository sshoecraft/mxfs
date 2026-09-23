#!/bin/bash
# sess465 (D-0524): one-pass per-node dmesg counter sweep for the FREE
# obligation state machine after the entry-authoritative rewrite (0.63.1).
# Usage: tests/d0524_freeob_sweep.sh [N=8]
# Prints one line per node and a fleet-sum line.  Counters:
#   stale     P-FREEOB-FLUSH-STALE       a cluster-buffer write completion whose
#                                        token no longer matched the entry — the
#                                        D-0524 interleaving WAS exercised and
#                                        was ignored (the fix engaging)
#   pcomm     P-FREEOB-PENDING-COMMITTED gate self-heal: FREE_PENDING with the
#                                        ifree committed (must be 0 with the fix;
#                                        >0 = a transition was still lost)
#   pend      P-FREEOB-PENDING           gate deferral (uncommitted pending —
#                                        should be unreachable)
#   pfatal    P-FREEOB-PENDING-FATAL     orphan / cross-tenure pending
#   refused   P-FREEOB-REFUSED           fail-closed shutdown at the gate
#   proto     P-FREEOB-COMMIT-PROTOCOL   tenure skew / bad kind at commit
#   created   P-FREEOB-COMMIT-CREATED    commit found no entry
#   nopend    P-FREEOB-COMMIT-NOPENDING  commit found UNLINK (pending never ran)
#   busy      P-FREEOB-TOKEN-BUSY        unconsumed token overwritten
#   aborted   P-FREEOB-ABORTED           ifree cancelled, predecessor restored
#   anomaly   P-FREEOB-PENDING-ANOMALY   ifree began on an actionable FREE
#   p55c      P55C-FREE-FLUSH            free image written by xfsaild (healthy)
#   pub       P-FREEOB-PUBLISHED         free image written at the gate (healthy)
#   unpub     P-FREEOB-UNPUBLISHED       free image not home after the flush
#   noshell   P-FREEOB-NOSHELL
#   foreign   P-FREEOB-FOREIGN
#   disch     P-FREEOB-FREE-DISCHARGED-BY FREE ended by P55C/recovery/reload proof
#   shut      'Shutting down filesystem'
#   poison    P-SESSION-POISON
#   rr        P88-PUBOB-RECLAIM-REFUSED
N=${1:-8}
cd "$(dirname "$0")/.." || exit 1
D=$(mktemp -d)
for i in $(seq 1 "$N"); do
  ( timeout 60 tools/mxfs_sshpass.sh test$i "dmesg | awk '
/P-FREEOB-FLUSH-STALE/{stale++} /P-FREEOB-PENDING-COMMITTED/{pcomm++}
/P-FREEOB-PENDING ag=/{pend++} /P-FREEOB-PENDING-FATAL/{pfatal++}
/P-FREEOB-REFUSED/{refused++} /P-FREEOB-COMMIT-PROTOCOL/{proto++}
/P-FREEOB-COMMIT-CREATED/{created++} /P-FREEOB-COMMIT-NOPENDING/{nopend++}
/P-FREEOB-TOKEN-BUSY/{busy++} /P-FREEOB-ABORTED/{aborted++}
/P-FREEOB-PENDING-ANOMALY/{anomaly++} /P55C-FREE-FLUSH/{p55c++}
/P-FREEOB-PUBLISHED/{pub++} /P-FREEOB-UNPUBLISHED/{unpub++}
/P-FREEOB-NOSHELL/{noshell++} /P-FREEOB-FOREIGN/{foreign++}
/P-FREEOB-FREE-DISCHARGED-BY/{disch++} /Shutting down filesystem/{shut++}
/P-SESSION-POISON/{poison++} /P88-PUBOB-RECLAIM-REFUSED/{rr++}
END{printf \"stale=%d pcomm=%d pend=%d pfatal=%d refused=%d proto=%d created=%d nopend=%d busy=%d aborted=%d anomaly=%d p55c=%d pub=%d unpub=%d noshell=%d foreign=%d disch=%d shut=%d poison=%d rr=%d\n\",stale,pcomm,pend,pfatal,refused,proto,created,nopend,busy,aborted,anomaly,p55c,pub,unpub,noshell,foreign,disch,shut,poison,rr}'" \
      > "$D/t$i" 2>/dev/null; echo $? > "$D/rc$i" ) &
done
wait 2>/dev/null
for i in $(seq 1 "$N"); do
  printf 'test%-3s rc=%s %s\n' "$i" "$(cat "$D/rc$i" 2>/dev/null)" "$(cat "$D/t$i" 2>/dev/null)"
done
echo "responders: $(cat "$D"/t* 2>/dev/null | grep -c stale=)/$N"
echo "FLEET $(cat "$D"/t* 2>/dev/null | grep -oE '[a-z0-9]+=[0-9]+' | awk -F= '{s[$1]+=$2;if($2>0)n[$1]++} END{for(k in s)printf "%s=%d(n:%d) ",k,s[k],n[k];print""}')"
echo "dir: $D"
