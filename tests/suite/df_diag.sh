#!/bin/bash
# df_diag — dlm_fairness clone that, on a non-empty drain, characterizes the
# leftover dirent: re-reads after a short delay (self-heal => stale read),
# re-reads after dropping caches, and stats each leftover (inode + size).
# Used to classify the `df shared dir drained got=N` residual.
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"

R="$RANK"; T="$NODES"
D="$MNT/.df_diag"
mkdir -p "$D" 2>/dev/null

ROUNDS=50

ck "df barrier ready" coord_barrier "df_ready"

done_rounds=0
for r in $(seq 1 "$ROUNDS"); do
    f="$D/n${R}_r${r}"
    echo "$r" > "$f" || break
    mv "$f" "$f.done" || break
    rm -f "$f.done" || break
    done_rounds=$r
done
sync

ckeq "df node${R} completed all rounds" "$ROUNDS" "$done_rounds"

ck "df barrier done" coord_barrier "df_done"

if [ "$R" = 1 ]; then
    n1=$(ls "$D" 2>/dev/null | wc -l | tr -d ' ')
    if [ "$n1" != 0 ]; then
        lo1=$(ls "$D" 2>/dev/null | tr '\n' ',')
        echo "DIAG: immediate got=$n1 leftover=[$lo1]" >&2
        for f in $(ls "$D" 2>/dev/null); do
            echo "DIAG-STAT $f -> $(stat -c 'ino=%i size=%s' "$D/$f" 2>&1)" >&2
        done
        # self-heal probe: re-read a few times with small delays
        for k in 1 2 3 4 5; do
            sleep 0.4
            nk=$(ls "$D" 2>/dev/null | wc -l | tr -d ' ')
            echo "DIAG: reread#$k got=$nk leftover=[$(ls "$D" 2>/dev/null | tr '\n' ',')]" >&2
            [ "$nk" = 0 ] && break
        done
        # cache-drop probe (forces re-read of dir from disk/peer)
        echo 3 > /proc/sys/vm/drop_caches 2>/dev/null
        sleep 0.3
        nd=$(ls "$D" 2>/dev/null | wc -l | tr -d ' ')
        echo "DIAG: after_drop_caches got=$nd leftover=[$(ls "$D" 2>/dev/null | tr '\n' ',')]" >&2
        nfinal="$nd"
    else
        nfinal=0
    fi
    ckeq "df shared dir drained" "0" "$nfinal"
fi

ck "df barrier verify" coord_barrier "df_verify"

coord_done "$([ "$FAIL_N" -eq 0 ] && echo PASS || echo FAIL)"
finish
