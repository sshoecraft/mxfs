import re, glob, statistics as st, sys

D = "/src/mxfs/tests/evidence/sess436_chain2_0417_intents_mht_s436b/mht0"
INO = "201326720"
files = sorted(glob.glob(D + "/test*.log"))
assert len(files) == 32, f"expected 32 files, got {len(files)}"

def pct(lst, p):
    if not lst: return None
    s = sorted(lst)
    k = (len(s)-1) * p/100.0
    f = int(k); c = min(f+1, len(s)-1)
    if f == c: return s[f]
    return s[f] + (s[c]-s[f])*(k-f)

def kv_parse(line):
    # parse tokens of form key=value (value may not contain space)
    d = {}
    for tok in line.split():
        if '=' in tok:
            k,v = tok.split('=',1)
            d[k]=v
    return d

lines_all = 0
p138_bast = []
p381 = []
p382 = []
p6h_handoff = []
p6h_adopt = []
p138_wait = []
p50_rd_total = 0
fua_ino_total = 0

malformed = {'P138-BAST':0,'P381-UNLK-CONTEND':0,'P382-WAKE':0,'P6H-HANDOFF':0,'P6H-ADOPT':0,'P138-WAIT':0}

for fp in files:
    with open(fp, 'r', errors='replace') as f:
        for line in f:
            lines_all += 1
            if 'P50-RD' in line:
                p50_rd_total += 1
            if 'FUA' in line and f'ino={INO}' in line:
                fua_ino_total += 1

            if 'P138-BAST' in line and f'ino={INO}' in line:
                d = kv_parse(line)
                if d.get('ino') == INO:
                    p138_bast.append(d)
                else:
                    malformed['P138-BAST'] += 1
            elif 'P381-UNLK-CONTEND' in line and f'ino={INO}' in line:
                d = kv_parse(line)
                if d.get('ino') == INO:
                    p381.append(d)
                else:
                    malformed['P381-UNLK-CONTEND'] += 1
            elif 'P382-WAKE' in line and f'ino={INO}' in line:
                d = kv_parse(line)
                if d.get('ino') == INO:
                    p382.append(d)
                else:
                    malformed['P382-WAKE'] += 1
            elif 'P6H-HANDOFF' in line and f'ino={INO}' in line:
                d = kv_parse(line)
                if d.get('ino') == INO:
                    p6h_handoff.append(d)
                else:
                    malformed['P6H-HANDOFF'] += 1
            elif 'P6H-ADOPT' in line and f'ino={INO}' in line:
                d = kv_parse(line)
                if d.get('ino') == INO:
                    p6h_adopt.append(d)
                else:
                    malformed['P6H-ADOPT'] += 1
            elif 'P138-WAIT' in line and f'ino={INO}' in line:
                d = kv_parse(line)
                if d.get('ino') == INO:
                    p138_wait.append(d)
                else:
                    malformed['P138-WAIT'] += 1

print(f"=== File count: {len(files)} ===")
print(f"=== Total lines across all 32 files: {lines_all} ===")
print()

# 1. P138-BAST
NB = len(p138_bast)
print(f"1. P138-BAST ino={INO}: count NB = {NB}")
print()

# 2. P381-UNLK-CONTEND
NC = len(p381)
print(f"2. P381-UNLK-CONTEND ino={INO}: count NC = {NC}")
def numfield(lst, key, cast=int):
    out = []
    bad = 0
    for d in lst:
        v = d.get(key)
        if v is None:
            bad += 1
            continue
        try:
            out.append(cast(v))
        except ValueError:
            bad += 1
    return out, bad

for key in ['retries','miscmp','sleep_ms','wall_ms']:
    vals, bad = numfield(p381, key)
    if vals:
        print(f"   {key}: n={len(vals)} (bad/missing={bad}) p50={pct(vals,50):.3f} p90={pct(vals,90):.3f} mean={st.mean(vals):.3f} min={min(vals)} max={max(vals)}")
    else:
        print(f"   {key}: no valid values (bad/missing={bad})")

print("   sums of flag fields:")
for key in ['benign','contended','fast','ident','multigen','selfbits','removed','noreg','holders','yieldto','control']:
    vals, bad = numfield(p381, key)
    print(f"   {key}: sum={sum(vals)} n_valid={len(vals)} bad/missing={bad}")

ratio = (NC/NB) if NB else float('nan')
print(f"   NC/NB ratio = {NC}/{NB} = {ratio:.6f}" if NB else "   NC/NB ratio: NB=0, undefined")
print()

# 3. P382-WAKE by kind
print(f"3. P382-WAKE ino={INO}: total count = {len(p382)}")
by_kind = {}
for d in p382:
    k = d.get('kind','<missing>')
    by_kind.setdefault(k, []).append(d)
for k, lst in sorted(by_kind.items()):
    print(f"   kind={k}: count={len(lst)}")
    for fld in ['woken','waiters']:
        vals, bad = numfield(lst, fld)
        if vals:
            print(f"      {fld}: p50={pct(vals,50):.3f} mean={st.mean(vals):.3f} n_valid={len(vals)} bad/missing={bad}")
        else:
            print(f"      {fld}: no valid values (bad/missing={bad})")
print()

# 4. P6H-HANDOFF
print(f"4. P6H-HANDOFF ino={INO}: count = {len(p6h_handoff)}")
print()

# 5. P6H-ADOPT
print(f"5. P6H-ADOPT ino={INO}: count = {len(p6h_adopt)}")
by_mode = {}
for d in p6h_adopt:
    m = d.get('mode','<missing>')
    by_mode.setdefault(m, []).append(d)
for m, lst in sorted(by_mode.items()):
    print(f"   mode={m}: count={len(lst)}")
    for fld in ['elapsed_ms','reads']:
        vals, bad = numfield(lst, fld)
        if vals:
            print(f"      {fld}: p50={pct(vals,50):.3f} p90={pct(vals,90):.3f} mean={st.mean(vals):.3f} n_valid={len(vals)} bad/missing={bad}")
        else:
            print(f"      {fld}: no valid values (bad/missing={bad})")
print()

# 6. P138-WAIT
print(f"6. P138-WAIT ino={INO}: count = {len(p138_wait)}")
by_mode2 = {}
for d in p138_wait:
    m = d.get('mode','<missing>')
    by_mode2.setdefault(m, []).append(d)
for m, lst in sorted(by_mode2.items()):
    print(f"   mode={m}: count={len(lst)}")
    for fld in ['elapsed_ms','ffw_ms','caw_try','caw_miss','caw_svc_ms','reads','poll']:
        vals, bad = numfield(lst, fld)
        if vals:
            print(f"      {fld}: p50={pct(vals,50):.3f} p90={pct(vals,90):.3f} mean={st.mean(vals):.3f} n_valid={len(vals)} bad/missing={bad}")
        else:
            print(f"      {fld}: no valid values (bad/missing={bad})")
print()

# 7
print(f"7. P50-RD total lines (all inos, all files) = {p50_rd_total}")
print(f"   FUA lines with ino={INO} (any line containing 'FUA' and f'ino={INO}') = {fua_ino_total}")
print()

print("=== malformed/skipped (tag+ino substring matched but ino field != target after kv-parse) ===")
print(malformed)
