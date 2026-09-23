#!/usr/bin/env python3
"""
p13_release_shape.py — correlate P-ICD-TENURE-REFUSE / P13-SFPARENT-DURABLE-FAIL
events against the surrounding P70-BP/P15/P146-RELDUR/P51-REL/P-RELFLUSH-NOTENURE/
marker/P56-RELOAD-MERGE/P-RELOAD-IDENTICAL/P-SFDIR-REVERT lines, for the same ino,
in each gzip kernel log independently.

One streaming decompress + full in-memory line list per file (files are ~a few
tens of MB decompressed; parallelised with multiprocessing so each worker holds
one file at a time). Correlation is done with per-ino sorted line-index lists and
bisect, not a second file pass.

Usage:
    python3 tools/p13_release_shape.py --files <filelist> [--workers 8] \
        [--out <json>] [--root <evidence-dir>]

Invocation used for the report:
    \
    python3 /src/mxfs/tools/p13_release_shape.py \
        --files /tmp/claude-1000/-src-mxfs/403a35fc-7d8a-418a-9fe8-c0325ef3506e/scratchpad/tmp.ErpmTpbJre/files \
        --workers 8 \
        --out /tmp/claude-1000/-src-mxfs/403a35fc-7d8a-418a-9fe8-c0325ef3506e/scratchpad/p13/results.json
"""
import argparse
import bisect
import gzip
import json
import re
import sys
from multiprocessing import Pool

EVENT_RE = re.compile(r'\b(P-ICD-TENURE-REFUSE|P13-SFPARENT-DURABLE-FAIL)\b.*?\bino=(\d+)')
INO_RE = re.compile(r'\bino=(\d+)\b')

P70_RE = re.compile(r'P70-BP ino=(\d+) ENTRY')
ORPH_RE = re.compile(r'P15-ORPH-PROCEED ino=(\d+)')
RELDUR_RE = re.compile(r'P146-RELDUR ino=(\d+)')
REL_RE = re.compile(r'P51-REL ino=(\d+)')
NOTENURE_RE = re.compile(r'P-RELFLUSH-NOTENURE ino=(\d+)')
MERGE_RE = re.compile(r'P56-RELOAD-MERGE ino=(\d+)')
IDENTICAL_RE = re.compile(r'P-RELOAD-IDENTICAL ino=(\d+)')
REVERT_RE = re.compile(r'P-SFDIR-REVERT ino=(\d+)')

MARKER_PATTERNS = {
    'P228-RELBAR': re.compile(r'P228-RELBAR.*?ino=(\d+)'),
    'P220-UNLOCK-LEDGER-OPEN': re.compile(r'P220-UNLOCK-LEDGER-OPEN.*?ino=(\d+)'),
    'P188-REL-OBLIGATION-AT-UNLOCK': re.compile(r'P188-REL-OBLIGATION-AT-UNLOCK.*?ino=(\d+)'),
    'P146V': re.compile(r'P146V\S*.*?ino=(\d+)'),
    'P9-ICD-FAIL': re.compile(r'P9-ICD-FAIL.*?ino=(\d+)'),
}

FIELD_RE = lambda name: re.compile(r'\b' + re.escape(name) + r'=(\S+)')

P70_FIELDS = ['mode', 'state', 'qsrc', 'held_ms']
RELDUR_FIELDS = ['in_ail', 'pin', 'ili_fields', 'wrote', 'rerr', 'flushed']
REL_FIELDS = ['held_mode', 'sf', 'clean_skip', 'drain_ms']
MERGE_FIELDS = ['post_cnt', 'disk_cnt', 'ours_cnt', 'resurrect']
REVERT_FIELDS = ['incore_cnt', 'disk_cnt', 'fua_cnt']

WIN_P70 = 400
WIN_ORPH = 60
WIN_RELDUR = 200
WIN_NOTENURE = 30
WIN_MARKER = 200
WIN_RELOAD = 5000


def extract_fields(line, names):
    out = {}
    for n in names:
        m = FIELD_RE(n).search(line)
        out[n] = m.group(1) if m else None
    return out


def nearest_preceding(idx_list, event_idx, window):
    """idx_list sorted ascending. Return nearest idx < event_idx with
    event_idx - idx <= window, or None."""
    pos = bisect.bisect_left(idx_list, event_idx)
    if pos == 0:
        return None
    cand = idx_list[pos - 1]
    if event_idx - cand <= window:
        return cand
    return None


def any_preceding_in_window(idx_list, event_idx, window):
    pos = bisect.bisect_left(idx_list, event_idx)
    if pos == 0:
        return False
    cand = idx_list[pos - 1]
    return (event_idx - cand) <= window and cand >= (event_idx - window)


def nearest_following(idx_list, event_idx, window):
    pos = bisect.bisect_right(idx_list, event_idx)
    if pos >= len(idx_list):
        return None
    cand = idx_list[pos]
    if window is None or (cand - event_idx) <= window:
        return cand
    return None


def any_following_in_window(idx_list, event_idx, window):
    pos = bisect.bisect_right(idx_list, event_idx)
    if pos >= len(idx_list):
        return False
    cand = idx_list[pos]
    return (cand - event_idx) <= window


def process_file(relpath):
    """Runs in a worker. Reads relpath (relative to cwd, which is set to the
    evidence root by the parent before Pool creation — each worker inherits
    cwd via fork). Returns a dict: file, n_lines, events (list), error."""
    try:
        lines = []
        with gzip.open(relpath, 'rt', errors='replace') as fh:
            for line in fh:
                lines.append(line.rstrip('\n'))
    except Exception as e:
        return {'file': relpath, 'error': f'{type(e).__name__}: {e}', 'events': []}

    n_lines = len(lines)

    # Per-ino index lists, built in a single forward pass.
    p70 = {}
    orph = {}
    reldur = {}
    rel = {}
    notenure = {}
    merge = {}
    identical = {}
    revert = {}
    markers = {name: {} for name in MARKER_PATTERNS}
    events = []  # (line_idx, tag, ino)

    for i, line in enumerate(lines):
        if 'mxfs:' not in line:
            continue
        m = P70_RE.search(line)
        if m:
            p70.setdefault(m.group(1), []).append(i)
            continue
        m = ORPH_RE.search(line)
        if m:
            orph.setdefault(m.group(1), []).append(i)
            continue
        m = RELDUR_RE.search(line)
        if m:
            reldur.setdefault(m.group(1), []).append(i)
            continue
        m = REL_RE.search(line)
        if m:
            rel.setdefault(m.group(1), []).append(i)
            continue
        m = NOTENURE_RE.search(line)
        if m:
            notenure.setdefault(m.group(1), []).append(i)
            continue
        m = MERGE_RE.search(line)
        if m:
            merge.setdefault(m.group(1), []).append(i)
            continue
        m = IDENTICAL_RE.search(line)
        if m:
            identical.setdefault(m.group(1), []).append(i)
            continue
        m = REVERT_RE.search(line)
        if m:
            revert.setdefault(m.group(1), []).append(i)
            continue
        for name, pat in MARKER_PATTERNS.items():
            m = pat.search(line)
            if m:
                markers[name].setdefault(m.group(1), []).append(i)
        em = EVENT_RE.search(line)
        if em:
            events.append((i, em.group(1), em.group(2)))

    out_events = []
    for idx, tag, ino in events:
        rec = {'line': idx + 1, 'tag': tag, 'ino': ino, 'raw': lines[idx][:300]}

        # (1) nearest preceding P70-BP ENTRY within 400 lines
        plist = p70.get(ino, [])
        pidx = nearest_preceding(plist, idx, WIN_P70)
        if pidx is not None:
            f = extract_fields(lines[pidx], P70_FIELDS)
            rec['p70_entry'] = {'line': pidx + 1, 'dist': idx - pidx, **f}
        else:
            rec['p70_entry'] = None

        # (2) P15-ORPH-PROCEED within 60 lines before
        olist = orph.get(ino, [])
        rec['orph_proceed'] = any_preceding_in_window(olist, idx, WIN_ORPH)

        # (3) nearest following P146-RELDUR within 200 lines
        rlist = reldur.get(ino, [])
        ridx = nearest_following(rlist, idx, WIN_RELDUR)
        if ridx is not None:
            f = extract_fields(lines[ridx], RELDUR_FIELDS)
            rec['reldur'] = {'line': ridx + 1, 'dist': ridx - idx, **f}
        else:
            rec['reldur'] = None

        # (4) nearest following P51-REL (no stated window -> unbounded, rest of file)
        rellist = rel.get(ino, [])
        relidx = nearest_following(rellist, idx, None)
        if relidx is not None:
            f = extract_fields(lines[relidx], REL_FIELDS)
            rec['rel'] = {'line': relidx + 1, 'dist': relidx - idx, **f}
        else:
            rec['rel'] = None

        # (5) P-RELFLUSH-NOTENURE within 30 lines after
        nlist = notenure.get(ino, [])
        rec['relflush_notenure'] = any_following_in_window(nlist, idx, WIN_NOTENURE)

        # (6) marker presence within 200 lines after
        seen_markers = []
        for name in MARKER_PATTERNS:
            mlist = markers[name].get(ino, [])
            if any_following_in_window(mlist, idx, WIN_MARKER):
                seen_markers.append(name)
        rec['markers_seen'] = seen_markers

        # (7) nearest following (5000 lines) among MERGE / IDENTICAL / REVERT
        candidates = []
        for kind, table in (('MERGE', merge), ('IDENTICAL', identical), ('REVERT', revert)):
            lst = table.get(ino, [])
            fidx = nearest_following(lst, idx, WIN_RELOAD)
            if fidx is not None:
                candidates.append((fidx, kind))
        if candidates:
            candidates.sort()
            fidx, kind = candidates[0]
            f = {}
            if kind == 'MERGE':
                f = extract_fields(lines[fidx], MERGE_FIELDS)
            elif kind == 'REVERT':
                f = extract_fields(lines[fidx], REVERT_FIELDS)
            rec['reload'] = {'kind': kind, 'line': fidx + 1, 'dist': fidx - idx,
                              'raw': lines[fidx][:300], **f}
        else:
            rec['reload'] = None

        out_events.append(rec)

    return {'file': relpath, 'n_lines': n_lines, 'events': out_events}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--files', required=True, help='file listing relative paths, one per line')
    ap.add_argument('--workers', type=int, default=8)
    ap.add_argument('--out', required=True, help='output JSON path')
    args = ap.parse_args()

    with open(args.files) as fh:
        paths = [l.strip() for l in fh if l.strip()]

    results = []
    errors = []
    with Pool(args.workers) as pool:
        for res in pool.imap_unordered(process_file, paths, chunksize=4):
            if 'error' in res and res['error']:
                errors.append(res)
            results.append(res)

    with open(args.out, 'w') as fh:
        json.dump({'files_listed': len(paths), 'results': results, 'errors': errors}, fh)

    total_events = sum(len(r.get('events', [])) for r in results)
    sys.stderr.write(f'files_listed={len(paths)} files_processed={len(results)} '
                      f'errors={len(errors)} total_events={total_events}\n')


if __name__ == '__main__':
    main()
