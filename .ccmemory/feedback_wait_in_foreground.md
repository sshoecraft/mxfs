---
name: feedback_wait_in_foreground
description: "When waiting for a long-running command/test, wait in the FOREGROUND (blocking), not background+Monitor."
metadata: 
  node_type: memory
  type: feedback
  originSessionId: 29f421c9-1a8b-4f81-a9e6-eece13e85ce0
---

When a command or test needs time to finish, run it in the FOREGROUND and let the
turn block on it. Do NOT spawn it with `run_in_background: true` and then poll with
a Monitor/background task.

**Why:** The user wants to watch the work happen in the foreground; backgrounding +
monitor notifications fragments the run, interleaves confusingly, and hides progress
from them. They corrected this explicitly in sess47.

**How to apply:**
- Run the test/command directly in a foreground `Bash` call (it blocks until done).
- Foreground `Bash` timeout max is 600000ms (10 min). If a run is longer, split it
  into chunks that each fit under 10 min (e.g. run ONE test iteration per foreground
  call, ~5 min each) rather than backgrounding the whole batch.
- The harness blocks bare `sleep` to wait on a condition — that block is about idle
  sleeping, not about running a real long command in the foreground. Running the
  actual work command in the foreground is the intended behavior.
- Background execution is only for things the user explicitly wants detached, not as
  a default for "this takes a while."

Related: [[feedback_timing_is_first_class]].
