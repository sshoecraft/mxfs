#!/bin/bash
# iunl_soak_sweep.sh <mark> [nnodes]
#
# Per-cycle fleet sweep for the P53/iunlink-store soak (sess48).  Counts
# only dmesg lines AFTER the given MXFS-SOAK-MARK (nodes are not rebooted
# between preps, so raw dmesg greps count prior builds — the sess48
# attribution lesson).  One awk pass per node (a 6-grep variant blew the
# time budget on long dmesg buffers).  Prints per-node anomalies and a
# fleet summary; exits nonzero on any shutdown/P53/FOSSILWR/unreachable.
#
# Signals swept:
#   Shutting down          — fatal (any = FAIL)
#   P53-IUNLINK-MISMATCH   — fossil reached a reader (any = FAIL)
#   P-IUNLSTORE-OVERLAY    — store corrected an install (informational)
#   P-IUNLSTORE-WRSITE     — write-side overlay corrected outgoing
#                            payload (should be ZERO once install site 5
#                            covers the clmerge reverter; nonzero = an
#                            un-hooked in-core reverter still exists)
#   P-IUNLSTORE-FOSSILWR   — completed SAME-GEN write lacked the
#                            committed value (regression alarm; FAIL)
#   P-IUNL-DISCRIM         — A/B specimen fired (informational)
cd "$(dirname "$0")/.." || exit 2
MARK=${1:?usage: iunl_soak_sweep.sh <mark> [nnodes]}
N=${2:-32}
bad=0; ov=0; ws=0; fw=0; dc=0; rl=0; gp=0; lk=0
for i in $(seq 1 "$N"); do
	R=$(timeout 25 tools/mxfs_sshpass.sh "test$i" "dmesg | tail -n 200000 | awk '
		/MXFS-SOAK-MARK $MARK/ {s=1; S=P=O=W=F=D=L=G=K=0; next}
		!s {next}
		/Shutting down/ {S++}
		/P53-IUNLINK-MISMATCH/ {P++}
		/P-IUNLSTORE-OVERLAY/ {O++}
		/P-IUNLSTORE-WRSITE/ {W++}
		/P-IUNLSTORE-FOSSILWR/ {F++}
		/P-IUNL-DISCRIM/ {D++}
		/P-IUNLSTORE-RELLEAK/ {L++}
		/P-IUNLSTORE-AGPURGE/ {G++}
		/P-IUNLSTORE-LIVESKEW/ {K++}
		END {if (!s) print \"NOMARK\"; else print S, P, O, W, F, D, L, G, K}'" 2>/dev/null)
	if [ -z "$R" ]; then echo "test$i UNREACHABLE"; bad=1; continue; fi
	if [ "$R" = NOMARK ]; then echo "test$i NOMARK"; bad=1; continue; fi
	read -r S P O W F D L G K <<<"$R"
	if [ "${S:-1}" != 0 ] || [ "${P:-1}" != 0 ] || [ "${F:-1}" != 0 ]; then
		echo "test$i shut=$S p53=$P ov=$O ws=$W fw=$F dc=$D rl=$L gp=$G lk=$K"
		bad=1
	elif [ "${W:-0}" != 0 ] || [ "${O:-0}" != 0 ] || [ "${L:-0}" != 0 ] ||
	     [ "${K:-0}" != 0 ]; then
		echo "test$i (info) ov=$O ws=$W dc=$D rl=$L gp=$G lk=$K"
	fi
	ov=$((ov+O)); ws=$((ws+W)); fw=$((fw+F)); dc=$((dc+D))
	rl=$((rl+L)); gp=$((gp+G)); lk=$((lk+K))
done
echo "SWEEP $MARK: bad=$bad overlays=$ov wrsite=$ws fossilwr=$fw discrim=$dc relleak=$rl agpurge=$gp liveskew=$lk"
exit "$bad"
