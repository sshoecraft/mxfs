#!/bin/bash
# fio_vs_xfs_baseline — native-XFS fio throughput vs MXFS on the SAME LUN.
# Benchmark (reformats device). Stores the XFS baseline at .xfs_fio_baseline.json.
# Leaves MXFS mounted.
#
# sess16(a9a03929): single-shot write legs were a HOST-cache coin flip exactly
# like single_node_paired's were (seqW swung 46%..210% across runs on one
# build — clyde's disk.img writeback state differs per leg).  Same medicine as
# the sess15 paired rewrite: 4 position-balanced rounds (XM MX MX XM), each
# round scores its own internal mxfs/xfs ratio for the two WRITE workloads
# (time_based so both legs do identical wall-clock of I/O), trimmed mean
# (drop best+worst) per workload.  Reads stay single-shot informational —
# they are served from clyde's host page cache by design (see below).
SUITE_TEST_NAME=fio_vs_xfs_baseline
NODES="${MXFS_NODES:-1}"
DEV="${MXFS_DEV:-/dev/sda}"; MNT="${MXFS_MOUNT:-/mnt/shared}"
MODULE="${MXFS_MODULE:-/src/mxfs/mxfs.ko}"; MKFS="${MKFS_MXFS:-/src/mxfs/tools/mkfs_mxfs}"
SIZE="${FIO_SIZE:-256m}"; MIN_PCT="${FIO_MIN_PCT:-70}"
WSECS="${FIO_WRITE_SECS:-6}"       # per-workload time_based seconds (write rounds)
emit(){ echo "RESULT: $1 | test=$SUITE_TEST_NAME | nodes=$NODES | measured=$2 | reason=${3:-}"; }
fio_one(){ local d="$1" n="$2" rw="$3" bs="$4" extra="$5" j="/tmp/fvx.$$.$n.json"
  sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null
  fio --name="$n" --filename="$d/$n.dat" --rw="$rw" --bs="$bs" --size="$SIZE" \
      --ioengine=libaio --direct=1 --iodepth=32 $extra --output-format=json > "$j" 2>/dev/null
  python3 -c "import json;b=json.load(open('$j'))['jobs'][0];print(int((b['read']['bw_bytes']+b['write']['bw_bytes'])/1048576),int(round(b['read']['iops']+b['write']['iops'])))" 2>/dev/null || echo "0 0"
  rm -f "$j"; }
# One WRITE pass: time_based seqW bw + randW iops (identical wall both legs).
runW(){ local d="$1/.fiobench"; mkdir -p "$d"; local a sw rw
  a=$(fio_one "$d" sw write 1M "--time_based --runtime=$WSECS");     sw=${a%% *}
  a=$(fio_one "$d" rw randwrite 4k "--time_based --runtime=$WSECS"); rw=${a##* }
  echo "$sw $rw"; }
# One READ pass (informational): lay out files then read them.
runR(){ local d="$1/.fiobench"; mkdir -p "$d"; local a sr rr
  fio_one "$d" sr write 1M "" >/dev/null   # layout
  fio_one "$d" rr write 1M "" >/dev/null   # layout
  a=$(fio_one "$d" sr read 1M "");     sr=${a%% *}
  a=$(fio_one "$d" rr randread 4k ""); rr=${a##* }
  echo "$sr $rr"; }
pct(){ { [ "${2:-0}" -gt 0 ] 2>/dev/null && echo $(( $1*100/$2 )); } || echo 0; }
tmean(){ # trimmed mean of 4 values: drop min+max, average middle two
  local s; s=$(printf '%s\n' "$@" | sort -n | sed -n '2p;3p')
  echo $(( ( $(echo "$s" | head -1) + $(echo "$s" | tail -1) ) / 2 )); }

xfs_up(){ mountpoint -q "$MNT" && umount "$MNT"
  lsmod | grep -q '^mxfs' && rmmod mxfs 2>/dev/null
  mkfs.xfs -f "$DEV" >/dev/null 2>&1 || return 1
  mount "$DEV" "$MNT"; }
mxfs_up(){ mountpoint -q "$MNT" && umount "$MNT"
  modprobe libcrc32c 2>/dev/null || true
  lsmod | grep -q '^mxfs' || insmod "$MODULE" force_transport=1 || return 1
  "$MKFS" -f "$DEV" >/dev/null 2>&1 || return 1
  mount -t mxfs "$DEV" "$MNT"; }

# ---- write rounds: position-balanced XM MX MX XM, per-round internal ratio ----
xsw_a=(); xrw_a=(); msw_a=(); mrw_a=(); rsw=(); rrw=()
for round in 1 2 3 4; do
    case $round in
      1|4) xfs_up  || { emit FAIL "xfs-r$round" "xfs leg failed"; exit 1; }
           read xsw xrw < <(runW "$MNT")
           mxfs_up || { emit FAIL "mxfs-r$round" "mxfs leg failed"; exit 1; }
           read msw mrw < <(runW "$MNT") ;;
      2|3) mxfs_up || { emit FAIL "mxfs-r$round" "mxfs leg failed"; exit 1; }
           read msw mrw < <(runW "$MNT")
           xfs_up  || { emit FAIL "xfs-r$round" "xfs leg failed"; exit 1; }
           read xsw xrw < <(runW "$MNT") ;;
    esac
    xsw_a+=("$xsw"); xrw_a+=("$xrw"); msw_a+=("$msw"); mrw_a+=("$mrw")
    rsw+=( "$(pct "$msw" "$xsw")" ); rrw+=( "$(pct "$mrw" "$xrw")" )
done
psw=$(tmean "${rsw[@]}"); prw=$(tmean "${rrw[@]}")

# ---- read pass (informational, single-shot on each FS once) ----
# CACHE METHODOLOGY: this LUN is target fileio over a host file (disk.img), so
# reads are served from clyde's HOST page cache — a guest cannot drop it, so
# seqR/randR are cache-bound and swing run-to-run. WRITES gate PASS; reads are
# reported informationally.
xfs_up || { emit FAIL xfs-readpass "xfs leg failed"; exit 1; }
read xsr xrr < <(runR "$MNT")
mxfs_up || { emit FAIL mxfs-readpass "mxfs leg failed"; exit 1; }
read msr mrr < <(runR "$MNT")
psr=$(pct "$msr" "$xsr"); prr=$(pct "$mrr" "$xrr")

# representative absolute numbers for bench.json = round-2 values. Do NOT
# also write these to $BASE (.xfs_fio_baseline.json): that file is owned
# exclusively by fio_perf.sh's own xfs-mode capture (2-pass, steady-state,
# see tests/suite/fio_perf.sh), which is far more reliable than a single
# round here -- this test's own round-to-round ratios (see psw/prw below)
# are known to swing wildly (95%-1892% observed 2026-07-14) precisely
# because single-shot legs on this host are noisy; writing that noise into
# the SHARED baseline file corrupted fio_perf_vs_xfs.sh's comparison for
# every other test/condition until this was found and fixed.
xsw=${xsw_a[1]}; xrw=${xrw_a[1]}; msw=${msw_a[1]}; mrw=${mrw_a[1]}

worst_w=$(printf '%s\n' "$psw" "$prw" | sort -n | head -1)
measured="seqW=${msw}/${xsw}MiB rounds=$(IFS=,; echo "${rsw[*]}")→${psw}% randW=${mrw}/${xrw}iops rounds=$(IFS=,; echo "${rrw[*]}")→${prw}% worst_write=${worst_w}% [reads cache-bound: seqR ${psr}% randR ${prr}%]"

# Append XFS baseline + mxfs numbers + ratios to bench.json (perf history).
BENCH="${MXFS_BENCH:-/src/mxfs/bench.json}"; DLM="${MXFS_DLM:-tcp}"
[ -s "$BENCH" ] || echo '{}' > "$BENCH" 2>/dev/null
btmp=$(mktemp 2>/dev/null) && jq \
  --arg l "fio_vs_xfs_${NODES}n_${DLM}_$(date +%s)" --arg ts "$(date -u +%FT%TZ)" \
  --argjson n "$NODES" --arg d "$DLM" --arg sz "$SIZE" \
  --argjson xsw "${xsw:-0}" --argjson xsr "${xsr:-0}" --argjson xrw "${xrw:-0}" --argjson xrr "${xrr:-0}" \
  --argjson msw "${msw:-0}" --argjson msr "${msr:-0}" --argjson mrw "${mrw:-0}" --argjson mrr "${mrr:-0}" \
  --argjson psw "${psw:-0}" --argjson psr "${psr:-0}" --argjson prw "${prw:-0}" --argjson prr "${prr:-0}" \
  '.[$l] = {ts:$ts, test:"fio_vs_xfs_baseline", nodes:$n, dlm:$d, size:$sz,
            xfs:{seq_write_1m:{bw_mib:$xsw}, seq_read_1m:{bw_mib:$xsr}, rand_write_4k:{iops:$xrw}, rand_read_4k:{iops:$xrr}},
            mxfs:{seq_write_1m:{bw_mib:$msw}, seq_read_1m:{bw_mib:$msr}, rand_write_4k:{iops:$mrw}, rand_read_4k:{iops:$mrr}},
            ratio_pct:{seqW:$psw, seqR:$psr, randW:$prw, randR:$prr}}' \
  "$BENCH" > "$btmp" 2>/dev/null && mv "$btmp" "$BENCH" 2>/dev/null

{ [ "${worst_w:-0}" -ge "$MIN_PCT" ]; } && emit PASS "$measured" || emit FAIL "$measured" "mxfs write worst ${worst_w}% < ${MIN_PCT}% of XFS"
