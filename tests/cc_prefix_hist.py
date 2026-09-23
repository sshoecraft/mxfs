import re, pickle, collections

with open('/tmp/claude-1000/-src-mxfs/15472ae1-4ec0-4df1-8a88-9eb5ee167561/scratchpad/cc_results.pkl','rb') as f:
    d = pickle.load(f)

n = 1
phase_ts = d['results'][n]
start_line, _ = phase_ts.get('barrier-ready-done', (None,None))
end_line, _ = phase_ts.get('md5write-done', (None,None))
print("window line range (1-indexed, inclusive):", start_line, "to", end_line)

fn = "/tmp/run_crash_consistency_20260828T202007Z/kernlog_test1"
with open(fn, 'r', errors='replace') as f:
    lines = f.readlines()

# window is lines[start_line-1 : end_line] (end_line inclusive -> index end_line)
window = lines[start_line-1:end_line]
print("num lines in window:", len(window))

PREFIX_RE = re.compile(r'(?:mxfs:|XFS \(dm-1\):)\s*(.*)')
NUM_RE = re.compile(r'^-?\d+$|^0x[0-9a-fA-F]+$')

counter = collections.Counter()
matched_lines = 0
for line in window:
    m = PREFIX_RE.search(line)
    if not m:
        continue
    matched_lines += 1
    rest = m.group(1).strip()
    words = rest.split()
    # take first 4 "words" excluding pure numbers/hex
    picked = []
    for w in words:
        if NUM_RE.match(w):
            continue
        picked.append(w)
        if len(picked) == 4:
            break
    prefix = " ".join(picked)
    counter[prefix] += 1

print("total matched lines (mxfs: or XFS (dm-1):) in window:", matched_lines)
print("top 15 prefixes:")
for prefix, c in counter.most_common(15):
    print(f"  {c:6d}  {prefix}")
print()
print("total distinct prefixes:", len(counter))
