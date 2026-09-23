<!-- sess490 GPT review of the D-0490 fix: marker published AFTER claiming the sync wake credit, before complete(); clear per fresh generation; delwri_fai… -->
# GPT ruling (sess490) on the sync-waiter double terminal completion fix

Defect: D-SYNC-EMULATED-COMPLETION-RUNS-TERMINAL-IOEND-TWICE-UNTOKENED-DIRTY-DEPARTURE-0490.
Root (proven by 133 stack chains + XBF_WRITE-cleared flags): xfs_buf_ioend() runs
__xfs_buf_ioend (retires the departure token) then wakes the sync waiter, whose
xfs_buf_iowait loop runs __xfs_buf_ioend again -> untokened retire -> departure DIRTY.
Upstream has the same two passes but its second pass is idempotent.

Design accepted with corrections:
1. Publish the per-buffer marker (b_mxfs_ioend_ran) only AFTER the actor claims the
   sync wake credit and BEFORE complete(). A losing actor must never set it (a bio
   actor may own the wake and never ran the pass). Use WRITE_ONCE/READ_ONCE.
2. Clear at every FRESH generation start (xfs_buf_submit_ex, fresh=true); a resubmit
   (fresh=false) keeps the credit and never had the marker published (a false return
   publishes nothing).
3. xfs_buf_delwri_fail (xfs_buf_ioend then xfs_buf_iowait, no submit, no token):
   with the marker its single pass is still an untokened retire; it should be classed
   b_mxfs_io_soft. SEPARATE change (one change at a time).
4. Alternative (emulated arms only complete(), waiter owns the pass like the bio
   path) is cleaner but breaks retry ownership: the retry needs a second credit that
   fresh=false deliberately does not add. The marker is the smaller change. A
   once-per-generation guard around all non-idempotent MXFS terminal hooks would be
   more robust if more duplicate callers ever appear (there are only 3
   __xfs_buf_ioend callers today).
5. Coverage rule for every path that runs __xfs_buf_ioend before waking a sync
   waiter: publish only on a true return, only by the wake owner, before complete(),
   never gated on XBF_ASYNC (P-SYNCWAIT-OVERRIDE must publish), never on a resubmit.

Landed as 0.70.3 (frozen sess490_frozen_0703 sv D7027C05). Verification chain
tests/sess490_untokened_verify.sh.
