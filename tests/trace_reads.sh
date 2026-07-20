#!/bin/bash
# trace_reads.sh — capture block-layer READ sectors on this node for a bounded
# window and histogram them by AG + within-AG offset, to identify which shared
# buffer the 32-node dlm_scaling op-loop re-reads ~18x/op (RULE 4).
#
# Run ON a node while a 32-node workload is active. Maps device sector ->
# FS 4K block -> (AG, within-AG block). AG-header reads land at within-AG
# block 0..3 (AGF/AGI/AGFL/AGFL). Inode/dir buffers land deeper.
#
# Usage: trace_reads.sh <seconds> <agblocks>
set -u
SECS="${1:-4}"
AGBLK="${2:-261653}"          # agblocks from chk_mxfs (50GB LUN default)
T=/sys/kernel/debug/tracing
dm=$(ls -l /dev/mapper/mpatha 2>/dev/null | grep -oE 'dm-[0-9]+')

echo 0 > "$T/tracing_on" 2>/dev/null
echo > "$T/trace" 2>/dev/null
# reads only (rwbs starts with R)
echo 'rwbs ~ "R*"' > "$T/events/block/block_rq_issue/filter" 2>/dev/null
echo 1 > "$T/events/block/block_rq_issue/enable" 2>/dev/null
echo 1 > "$T/tracing_on" 2>/dev/null
sleep "$SECS"
echo 0 > "$T/tracing_on" 2>/dev/null
echo 0 > "$T/events/block/block_rq_issue/enable" 2>/dev/null

# Parse: line ends "... <sector> + <nsect> [comm]". Grab the sector (field before '+').
awk -v agblk="$AGBLK" '
  /block_rq_issue/ {
    for (i=1;i<=NF;i++) if ($i=="+") { sec=$(i-1); break }
    if (sec=="") next
    blk=int(sec/8); ag=int(blk/agblk); off=blk%agblk
    tot++
    agc[ag]++
    if (off<=3) hdr++; else deep++
    seccnt[sec]++
    sec=""
  }
  END{
    printf "TRACE reads=%d  ag_header(off0-3)=%d  deeper=%d\n", tot, hdr, deep
    print "-- top 8 AGs by read count --"
    n=0; for (a in agc) arr[n++]=a
    # simple selection of top few
    for (k=0;k<8;k++){ best=-1; bi=-1; for (a in agc){ if (agc[a]>best){best=agc[a]; bi=a} } if (bi<0)break; printf "   AG %-4s reads=%d\n", bi, best; delete agc[bi] }
    print "-- top 8 individual sectors --"
    for (k=0;k<8;k++){ best=-1; bs=-1; for (s in seccnt){ if (seccnt[s]>best){best=seccnt[s]; bs=s} } if (bs<0)break; b=int(bs/8); printf "   sector %-12s fsblk=%-10d AG=%-3d off=%-7d reads=%d\n", bs, b, int(b/agblk), b%agblk, best; delete seccnt[bs] }
  }' "$T/trace"
echo > "$T/trace" 2>/dev/null
