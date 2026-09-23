#!/usr/bin/env python3
"""
ccloop_refusal_audit.py — inventory every API-safeguard refusal across this
project's Claude Code transcripts.

Answers: when did they happen, in what category, on what CLI/model, how big was
the context at the time, and what changed on the days the rate moved.

Rows it looks for (all written by the CLI itself):
  * {"type":"system","subtype":"model_refusal_fallback"}      -> silently absorbed
  * {"type":"system","subtype":"model_refusal_no_fallback"}   -> fatal API error
  * assistant content block {"type":"fallback","from":..,"to":..}
  * assistant isApiErrorMessage rows whose text mentions "safeguards flagged"
"""
import json, os, sys, glob, collections, datetime, re

PROJ = os.path.expanduser('~/.claude/projects/-src-mxfs')

def ts(s):
    if not s: return None
    try: return datetime.datetime.fromisoformat(s.replace('Z','+00:00'))
    except Exception: return None

events = []
files = sorted(glob.glob(os.path.join(PROJ, '*.jsonl')))
scanned = 0
for fp in files:
    sid = os.path.basename(fp)[:-6]
    last_usage = None
    last_ver = None
    last_model = None
    try:
        fh = open(fp, 'r', errors='replace')
    except Exception:
        continue
    scanned += 1
    for line in fh:
        if 'refusal' not in line and 'safeguards flagged' not in line and '"usage"' not in line:
            continue
        try: d = json.loads(line)
        except Exception: continue
        if d.get('version'): last_ver = d['version']
        msg = d.get('message') or {}
        if isinstance(msg, dict):
            if msg.get('model'): last_model = msg['model']
            u = msg.get('usage')
            if isinstance(u, dict):
                last_usage = (u.get('input_tokens',0) or 0) + (u.get('cache_read_input_tokens',0) or 0) + (u.get('cache_creation_input_tokens',0) or 0)
        kind = None
        cat = d.get('apiRefusalCategory')
        req = d.get('requestId') or d.get('requestID')
        if d.get('type') == 'system' and 'refusal' in str(d.get('subtype','')):
            kind = d['subtype']
        elif d.get('type') == 'assistant':
            c = msg.get('content')
            if isinstance(c, list):
                for b in c:
                    if isinstance(b, dict) and b.get('type') == 'fallback':
                        kind = 'fallback_block:%s->%s' % (b.get('from'), b.get('to'))
                if kind is None and d.get('isApiErrorMessage'):
                    txt = json.dumps(c)
                    if 'safeguards flagged' in txt:
                        kind = 'api_error_text'
                        m = re.search(r'Details: `\[(\w+)\]`', txt)
                        if m and not cat: cat = m.group(1)
                        m = re.search(r'(req_[A-Za-z0-9]+)', txt)
                        if m and not req: req = m.group(1)
        if kind:
            events.append(dict(t=d.get('timestamp'), sid=sid, kind=kind, cat=cat or '?',
                               req=req or '?', ver=last_ver, model=last_model, ctx=last_usage))
    fh.close()

events.sort(key=lambda e: e['t'] or '')
print("transcripts scanned: %d   refusal-related events: %d" % (scanned, len(events)))
print()
print("=== per UTC day ===")
byday = collections.OrderedDict()
for e in events:
    t = ts(e['t'])
    if not t: continue
    k = t.strftime('%Y-%m-%d')
    byday.setdefault(k, collections.Counter())[e['kind'].split(':')[0]] += 1
for k, c in byday.items():
    print("  %s  %s" % (k, dict(c)))
print()
print("=== category totals ===")
print("  ", dict(collections.Counter(e['cat'] for e in events)))
print()
print("=== last 40 events (UTC) ===")
for e in events[-40:]:
    t = ts(e['t'])
    print("  %s %-26s cat=%-18s ctx=%-9s ver=%-8s sess=%s %s" % (
        t.strftime('%m-%d %H:%M:%S') if t else '?', e['kind'][:26], e['cat'],
        e['ctx'], e['ver'], e['sid'][:8], e['req'][:24]))
