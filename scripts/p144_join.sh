#!/bin/bash
# p144_join.sh <logdir> <daddr> [maxlines]
# Cross-node join of P144 WR/RD lines for one btree buffer daddr.
# Merges live_test1.log + live_test2.log by realns and, for every RD,
# reports whether its crc matches the most recent prior WR (either node).
# Verdict per RD:
#   FRESH  - crc == last WR crc (reader saw the newest write)
#   STALE  - crc == an OLDER WR crc from the history (reader got old data)
#   UNKNOWN- crc matches no WR seen so far (pre-capture image or torn)
# Also flags WR-after-foreign-RD inversions (writer-late candidates).
LOGD=${1:?logdir}; DADDR=${2:?daddr}; MAX=${3:-4000}
for n in 1 2; do
    grep -h "P144-" "$LOGD/live_test$n.log" 2>/dev/null | \
    awk -v node="test$n" -v d="$DADDR" '
    {
        rw=""; crc=""; realns=""; agno=""; daddr=""; comm=""; lsn="";
        for (i=1;i<=NF;i++) {
            if ($i ~ /^P144-(RD|WR)$/) { rw=$i; bt=$(i+1); }
            else if ($i ~ /^agno=/)   { agno=substr($i,6); }
            else if ($i ~ /^daddr=/)  { daddr=substr($i,7); }
            else if ($i ~ /^crc=/)    { crc=substr($i,5); }
            else if ($i ~ /^lsn=/)    { lsn=substr($i,5); }
            else if ($i ~ /^comm=/)   { comm=substr($i,6); }
            else if ($i ~ /^realns=/) { realns=substr($i,8); }
        }
        if (daddr==d && rw!="") printf "%s %s %s %s %s %s %s %s\n", realns, node, rw, bt, agno, crc, lsn, comm;
    }'
done | sort -n | tail -n "$MAX" | awk '
{
    realns=$1; node=$2; rw=$3; bt=$4; agno=$5; crc=$6; lsn=$7; comm=$8;
    t = realns/1e9;
    if (rw=="P144-WR") {
        seen[crc]=NR; lastwr_crc=crc; lastwr_node=node; lastwr_t=t;
        printf "%.6f %-5s WR  crc=%s lsn=%s comm=%s\n", t, node, crc, lsn, comm;
    } else {
        verdict="UNKNOWN";
        if (crc==lastwr_crc) verdict="FRESH";
        else if (crc in seen) verdict="STALE(older-wr)";
        marker=""; if (node!=lastwr_node && lastwr_crc!="") marker=" xnode";
        printf "%.6f %-5s RD  crc=%s lsn=%s comm=%s -> %s%s (lastWR %s@%.6f crc=%s)\n", \
            t, node, crc, lsn, comm, verdict, marker, lastwr_node, lastwr_t, lastwr_crc;
        if (verdict!="FRESH") bad++;
        rd++;
    }
}
END { printf "== daddr summary: RDs=%d nonfresh=%d\n", rd, bad; }'
