#!/bin/bash
# ag_handoff_lap_sweep.sh — one d385 TREATMENT lap at the current rig geometry
# plus the AG-handoff latch counter sweep (sess392, D-RSYNC-LAP-PACE-AG-SHARING-388).
#
# usage: D385_OUT=<dir> tests/ag_handoff_lap_sweep.sh <lap_n> [label]
#
# Runs `arm_lap TREATMENT <lap_n>` (CHUNK_TIMEOUT 330 / outer cap 340 s — the
# measured 25-AG lap walls are 167-332 s; never widen), prints the row verdicts,
# then sweeps all 32 nodes for: wedge/shutdown/P275 watchdog counts, the latch
# event counts (P12-LATCH / LATCHED-ENTER / bail2-holders armed), the DLM stats
# 'handoff:' line summed over nodes, the per-node b2c (BAST->COMMIT) p50/p90/max
# and the 0.22.2 split (r2e = rx->worker enter, e2a = enter->armed,
# a2c = armed->COMMIT) tails, and the per-node rsync walls of the lap's
# rsync_paired run.  Per-node evidence files stay in a mktemp dir (printed).
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO"
LAP="${1:?lap number}"
LABEL="${2:-lap}"
: "${D385_OUT:?set D385_OUT}"
SSH=tools/mxfs_sshpass.sh
N="${N:-32}"

t0=$(date +%s)
CHUNK_TIMEOUT="${CHUNK_TIMEOUT:-330}" D385_STEP="arm_lap TREATMENT $LAP" \
    timeout 340 tests/d385_publication_verify.sh 3 "$N" >/dev/null 2>&1
echo "$LABEL lap $LAP wall=$(( $(date +%s)-t0 ))s"
grep -E "  (PASS|FAIL)  |marker stale|ERROR|pre-assert" "$D385_OUT/lap.TREATMENT.$LAP.log" | cut -c1-220

D=$(mktemp -d)
echo "evidence dir: $D"
set +m
for i in $(seq 1 "$N"); do
    (
        timeout 60 "$SSH" "test$i" "echo m=\$(grep -c ' mxfs ' /proc/mounts) sd=\$(dmesg | grep -c 'Shutting down') w=\$(dmesg | grep -c RELFENCE-WEDGE) cv=\$(dmesg | grep -c P-NOINO-CONVOY) td=\$(dmesg | grep -c P-AGTRY-DEMOTING) lat=\$(dmesg | grep -c P12-LATCH) le=\$(dmesg | grep -c LATCHED-ENTER) lp2=\$(dmesg | grep -c LATCHED-PHASE2) b2h=\$(dmesg | grep -c 'bail2-holders') pla=\$(dmesg | grep -c POSTLATCH) uwd=\$(dmesg | grep -c UNLOCK-WHILE-DEMOTING) dwl=\$(dmesg | grep -c DEMOTE-WAIT-LONG) p275=\$(dmesg | grep -c P275-AG-STUCK) p67=\$(dmesg | grep -c P67-AG-BAST-STALL) p86s=\$(dmesg | grep -c 'P86-AGI-UNLINKED-PUBLISH ') p87t=\$(dmesg | grep -c P87-TARGET-TIMEOUT) dc=\$(dmesg | grep -c 'P217-RENAME-DIRTYCANCEL\\|Corruption of in-memory') warn=\$(dmesg | grep -c 'WARNING:') ro=\$(dmesg | grep -c 'P12-READOPT ag'); dmesg | grep 'handoff: n=' | tail -1 | grep -oE 'handoff: n=.*stale_hint=[0-9]+'; dmesg | grep 'resv: try=' | tail -1 | grep -oE 'resv: try=.*grow=[0-9]+'; dmesg | grep -oE 'P12-HANDOFF ag=[0-9]+ b2c_ms=[0-9]+' | awk -F'b2c_ms=' '{print \$2}' | sort -n | awk '{a[NR]=\$1} END{if(NR>0) print \"b2c n=\"NR\" p50=\"a[int(NR*0.5)+1]\" p90=\"a[int(NR*0.9)+1]\" max=\"a[NR]}'; for k in q wq r2e e2a a2c; do dmesg | grep -oE \"P12-HANDOFF.* \$k=[0-9]+\" | grep -oE \"\$k=[0-9]+\$\" | cut -d= -f2 | sort -n | awk -v k=\$k '{a[NR]=\$1} END{if(NR>0) print k\" n=\"NR\" p50=\"a[int(NR*0.5)+1]\" p90=\"a[int(NR*0.9)+1]\" max=\"a[NR]}'; done" >"$D/t$i" 2>/dev/null
        echo $? >"$D/rc$i"
    ) &
done
wait 2>/dev/null
echo "rc!=0: $(grep -L '^0$' "$D"/rc* | wc -l)"
echo "--- per-counter: total(nodes>0)"
head -qn1 "$D"/t* | grep -av '^Unauthorized\|^Warning:\|^If you' | tr ' ' '\n' | awk -F= 'NF==2{s[$1]+=$2; if($2>0)n[$1]++} END{for(k in s) printf "%s=%d(n:%d) ",k,s[k],n[k]; print ""}'
echo "--- handoff stats (sum over nodes of last line):"
grep -h 'handoff: n=' "$D"/t* | tr ' ' '\n' | awk -F= 'NF==2{s[$1]+=$2} END{for(k in s) printf "%s=%d ",k,s[k]; print ""}'
echo "--- resv stats (sum over nodes of last line; probe_max = max):"
grep -h 'resv: try=' "$D"/t* | tr ' ' '\n' | awk -F= 'NF==2{ if($1=="probe_max_us"){if($2>m)m=$2} else s[$1]+=$2} END{for(k in s) printf "%s=%d ",k,s[k]; printf "probe_max_us=%d\n", m}'
echo "--- RESV probes per node (busy/exhaust/swept/sweep-retry):"
for i in $(seq 1 "$N"); do printf "test%s %s\n" "$i" "$(sed -n '2p' "$D/t$i" 2>/dev/null | head -c 0)$(timeout 20 "$SSH" "test$i" "echo busy=\$(dmesg | grep -c P-DIALLOC-RESV-BUSY) exh=\$(dmesg | grep -c P-DIALLOC-RESV-EXHAUST) swept=\$(dmesg | grep -c P-DIALLOC-RESV-SWEPT) sweep=\$(dmesg | grep -c P-DIALLOC-SWEEP-RETRY) err=\$(dmesg | grep -c P-DIALLOC-RESV-ERR)" 2>/dev/null | grep -av '^Unauthorized\|^Warning:\|^If you')"; done | grep -vE 'busy=0 exh=0 swept=0 sweep=0 err=0$' | head -16
echo "--- b2c per node (worst 10):"
for i in $(seq 1 "$N"); do printf "test%s: %s\n" "$i" "$(grep 'b2c n=' "$D/t$i")"; done | grep -v ': $' | sort -t= -k5 -n | tail -10
echo "--- split tails per node (worst 6 by max, per component):"
for k in q wq r2e e2a a2c; do
    for i in $(seq 1 "$N"); do printf "test%s: %s\n" "$i" "$(grep "^$k n=" "$D/t$i")"; done | grep -v ': $' | sort -t= -k5 -n | tail -6
done
R=$(ls -td /tmp/run_rsync_paired_* 2>/dev/null | head -1)
echo "--- rsync walls ($R):"
for i in $(seq 1 "$N"); do printf "test%s %s\n" "$i" "$(grep -h 'RSYNC: node' "$R/test$i.raw" 2>/dev/null | head -1 | grep -oE 'elapsed=[0-9.]+s rc=[0-9-]+')"; done | sort -t= -k2 -n | awk '{printf "%s ", $0; if(NR%4==0) print ""} END{print ""}'
