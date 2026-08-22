#!/bin/bash
# lba_probe.sh — run ON a node.  Times direct SCSI READ(16)+FUA to two LBAs,
# alternating, for a fixed duration.  Reports worst and mean per LBA.
#
# sess379 (D-HOT-SLOT-CAW-SERIALIZES-LUN-PER-LBA-379): the RULE-5 review
# rejected a stat()-based control as inconclusive, because two stat calls can
# differ in whether they issue a SCSI command AT ALL.  This issues the command
# itself, with the same opcode and FUA bit MXFS uses for a slot read, so a
# fast COLD result during a storm is direct evidence that the LUN is answering
# while the HOT LBA is not.
#
# Usage: lba_probe.sh <dev> <hot_lba> <cold_lba> <seconds>
set -u
DEV="${1:?dev}"; HOT="${2:?hot lba}"; COLD="${3:?cold lba}"; SECS="${4:-90}"

cdb() {   # emit the 16 CDB bytes for READ(16)+FUA of one 512B block at $1
    local l=$1
    printf '88 08'
    for s in 56 48 40 32 24 16 8 0; do printf ' %02x' $(( (l >> s) & 0xff )); done
    printf ' 00 00 00 01 00 00'
}
HOTC=$(cdb "$HOT"); COLDC=$(cdb "$COLD")

hw=0; cw=0; hn=0; cn=0; ht=0; ct=0; herr=0; cerr=0
end=$(( $(date +%s) + SECS ))
while [ "$(date +%s)" -lt "$end" ]; do
    a=$(date +%s%N); timeout 200 sg_raw -r 512 "$DEV" $HOTC >/dev/null 2>&1 || herr=$((herr+1)); b=$(date +%s%N)
    d=$(( (b-a)/1000000 )); hn=$((hn+1)); ht=$((ht+d)); [ "$d" -gt "$hw" ] && hw=$d
    a=$(date +%s%N); timeout 200 sg_raw -r 512 "$DEV" $COLDC >/dev/null 2>&1 || cerr=$((cerr+1)); b=$(date +%s%N)
    d=$(( (b-a)/1000000 )); cn=$((cn+1)); ct=$((ct+d)); [ "$d" -gt "$cw" ] && cw=$d
done
echo "LBAPROBE hot_lba=$HOT hot_n=$hn hot_worst_ms=$hw hot_mean_ms=$(( ht / (hn>0?hn:1) )) hot_err=$herr | cold_lba=$COLD cold_n=$cn cold_worst_ms=$cw cold_mean_ms=$(( ct / (cn>0?cn:1) )) cold_err=$cerr"
