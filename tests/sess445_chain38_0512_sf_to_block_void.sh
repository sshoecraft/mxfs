#!/bin/bash
# sess445 chain 38 (0.52.0): D-DIR-SF-TO-BLOCK-RETYPE-VOIDS-AUTHORITY-TOKEN-
# SLICE-REFUSED-0512 — instrument step 2 (measure the producer, not the corpse).
# Chain 35 point 13 refused victim slot 24 on ONE class=NONE/INCOMPLETE image
# (AG 24 agbno 9, 4 KiB) inside the create transaction that also carved the
# node's inode chunk.  Code reading: xfs_dir2_sf_to_block -> xfs_dir3_data_init
# (set_type DIR_DATA + log = the authority CAPTURE instant) then
# xfs_dir3_block_init re-types the same buffer DIR_BLOCK -> serialize-time
# blftchg void.  0.52.0 prints P-AUTHCAP-VOID why=... blft_cap= blft_now= on
# the producer.  This lap creates 4 files/node into ONE fresh directory from
# 32 live nodes (sf->block AND block->leaf conversions) and greps the LIVE
# fleet — no node is destroyed, so the producer's line survives.
#   prediction: exactly one why=blftchg line fleet-wide per conversion with
#   blft_cap=DIR_DATA and blft_now=DIR_BLOCK (sf->block), plus the block->leaf
#   / leaf->block shapes if they void too; a nocap line or a different pair
#   REFUTES the reading.
# budget: prep 79-120 s (measured); handoff_anatomy 32x4 creates ~10 s burst +
# ~60 s harvest (32-node journalctl pulls) -> bound 240; fleet grep 32 x ssh
# ~20 s -> bound 90.
cd /src/mxfs || exit 1
while ! grep -q "^DONE" tests/evidence/sess444_chain37_0511_icreate_refuse_negative2_s444f.log 2>/dev/null; do sleep 30; done
LABEL=${1:-s445a}
LOG=tests/evidence/sess445_chain38_0512_sf_to_block_void_$LABEL.log
EV=tests/evidence/sess445_chain38_0512_sf_to_block_void_$LABEL
mkdir -p "$EV"
SSH=tools/mxfs_sshpass.sh
PASS=$(tools/mxfs_secrets.sh passfile 2>/dev/null)
{
  echo "=== sess445 chain38 start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') VERSION=$(cat VERSION) ==="
  if ! grep -q 'P-AUTHCAP-VOID' pal/linux/xfs_buf_item.c; then echo "ABORT: tree lacks the P-AUTHCAP-VOID probe"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  if ! strings mxfs.ko | grep -q 'P-AUTHCAP-VOID'; then echo "ABORT: mxfs.ko lacks the P-AUTHCAP-VOID probe (chain 36 did not build 0.52.0?)"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep rc=$prc"
  if [ "$prc" -ne 0 ]; then echo "ABORT: prep failed"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  STAMP=@$(date +%s)
  T0=$(date +%s); timeout 240 tests/handoff_anatomy.sh $LABEL 32 4 keep 50; echo "STAGE burst rc=$? wall=$(( $(date +%s) - T0 ))s"
  # fleet grep of the LIVE nodes' kernel logs since the burst (journalctl, never a bounded dmesg sweep)
  for i in $(seq 1 32); do
    ( timeout 40 "$SSH" "test$i" "$PASS" "journalctl -k --since '$STAMP' --no-pager 2>/dev/null | grep -a 'P-AUTHCAP-VOID\|P228-TOKCLASS' ; echo RC=\$?" 2>/dev/null | grep -av '^Unauthorized\|^Warning\|^If you' > "$EV/test$i.void" ) &
  done; wait
  echo "--- P-AUTHCAP-VOID lines fleet-wide: $(cat "$EV"/test*.void | grep -ac 'P-AUTHCAP-VOID') (why=blftchg $(cat "$EV"/test*.void | grep -ac 'why=blftchg'), why=nocap $(cat "$EV"/test*.void | grep -ac 'why=nocap'))"
  grep -aH 'P-AUTHCAP-VOID' "$EV"/test*.void | cut -c1-300 | head -40
  echo "--- P228-TOKCLASS (incomplete= is the producer's aggregate counter):"
  grep -ah 'P228-TOKCLASS' "$EV"/test*.void | tail -3 | cut -c1-200
  echo "VERDICT: void_lines=$(cat "$EV"/test*.void | grep -ac 'P-AUTHCAP-VOID') blftchg=$(cat "$EV"/test*.void | grep -ac 'why=blftchg') nocap=$(cat "$EV"/test*.void | grep -ac 'why=nocap')"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
