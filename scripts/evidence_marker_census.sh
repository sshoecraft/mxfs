#!/bin/bash
# Marker census over per-run evidence kernel logs.
#   usage: evidence_marker_census.sh <since-mtime> <markers-file> [parallelism]
# Streams every kernlog_*.gz / *.dmesg* / dmesg_test*.txt exactly once
# (zcat -f handles gz and plain text), prefilters with a single fixed-string
# Aho-Corasick grep, then attributes each surviving line to every marker it
# contains.  Nothing is decompressed to disk.
# Emits TSV on stdout:
#   C <dir> <file> <marker> <line-count>
#   X <marker> <file> <line trimmed to 300 chars>     (up to 3 per marker/file)
#   F <file>                                          (one per file scanned)
set -u
ROOT=/src/mxfs/tests/evidence
SINCE=${1:?since}
MARKERS=${2:?markers file}
PAR=${3:-8}

export MARKERS

scan_one() {
  f=$1
  d=$(dirname "$f")
  printf 'F\t%s\n' "$f"
  zcat -f -- "$f" 2>/dev/null \
    | LC_ALL=C grep -F -f "$MARKERS" 2>/dev/null \
    | LC_ALL=C awk -v D="$d" -v F="$f" -v MF="$MARKERS" '
        BEGIN { n=0; while ((getline m < MF) > 0) if (length(m)) { M[++n]=m; c[m]=0; ex[m]=0 } }
        {
          for (i=1;i<=n;i++) {
            m=M[i]
            if (index($0,m)) {
              c[m]++
              if (ex[m]<3) { ex[m]++; printf "X\t%s\t%s\t%s\n", m, F, substr($0,1,300) }
            }
          }
        }
        END { for (i=1;i<=n;i++) if (c[M[i]]>0) printf "C\t%s\t%s\t%s\t%d\n", D, F, M[i], c[M[i]] }
      '
}
export -f scan_one

find "$ROOT" -maxdepth 1 -newermt "$SINCE" -type d ! -path "$ROOT" -print0 \
  | xargs -0 -I{} find {} -maxdepth 1 -type f \
      \( -name 'kernlog_*.gz' -o -name '*.dmesg*' -o -name 'dmesg_test*.txt' \) -print0 \
  | xargs -0 -P "$PAR" -I{} bash -c 'scan_one "$@"' _ {}
