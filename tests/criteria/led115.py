import json
p='tests/criteria/OPEN_DEFECTS.json'
d=json.load(open(p))
ents = d['defects'] if isinstance(d,dict) and 'defects' in d else d
n=0
for e in ents:
    if e.get('id')=='D-SAMENODE-WAITER-CANCEL-COLLISION':
        e['next_step']=("sess115 RULE-5 RULING (supersedes the sess114 plan): the cached-lock code fact was ACCEPTED and blockers 2 and 3 are WITHDRAWN. "
          "PROVEN: MXFS CAW locks are per-mount CACHED grants with NO per-acquire release -- the already-held shortcut (dlm_caw.c:4680/:4790) reaches lreq_finish with held_mode!=NL, so tenure[m] is a monotone tally of grants since the last eviction, NOT a reference count. "
          "The sess114 'refs>1 => do not clear' rule would make EVERY BAST eviction a no-op and wedge the cluster -- DO NOT IMPLEMENT IT. Mandatory snapshot-subtract in lreq_release_all is also withdrawn (blanket epoch retirement is correct once the release boundary holds). "
          "STANDING WORK, in order: (1) NEW BLOCKER -- adoption must be PROVISIONAL: the adopt arm publishes a grant with no local disk CAS, so it lacks the natural CAS ordering that protects every other grant path; no adopter may publish a USABLE grant while a release is committing, and protected XFS activity must not proceed until the adoption is committed against the current release epoch. Pre-CAS and post-CAS grant_seq checks are both insufficient. "
          "(2) NEW BLOCKER -- ICLUSTER resource-granularity quiescence: one CAW resource covers up to 32 inodes, so demoters of DIFFERENT inodes are different threads on the SAME resource and the per-inode i_dlm_state park does not serialize them; a DLM RELEASING state does NOT fix it (T2's transient lock() ends before T1 enters RELEASING). Needs shared ICLUSTER admission/drain state + active-drainer count. "
          "(3) Replacement for blocker 3: a downgrade requires authoritative resource-wide quiescence (mark converting, block admissions, drain, downgrade, publish, reopen), never a tenure-based effective mode. "
          "(4) Audit that EVERY admission path observes pag_dlm_demoting (AG) / i_dlm_state (1:1 inode), and cover any generic CAW path that bypasses the XFS gates. "
          "(5) Re-check sess114 blockers 4, 5, 8, 9 against the cached-lock fact; 6, 7, 10 are believed untouched. "
          "(6) Rename/document tenure[] as epoch-scoped accounting; its use in lreq_plan's holder guard stays (fail-closed 'granted in this epoch'), its use as a reference count is banned. "
          "Evidence: ccmemory ccloop-c7ee71c6-sess115-cached-lock-model-invalidates-blockers-2-3 and ...sess115-GPT-ruling-blockers-2-3-WITHDRAWN-two-new. "
          "Tree is 0.11.441 with the STOP-SHIP core; DO NOT BOARD OR DEPLOY. Closure test remains the sess113 debugfs exerciser with its negative control -- a green board cannot close this (sess111 measured the reconcile arm entered 0 times on all 32 nodes).")
        n+=1
json.dump(d,open(p,'w'),indent=1)
print("updated",n)
