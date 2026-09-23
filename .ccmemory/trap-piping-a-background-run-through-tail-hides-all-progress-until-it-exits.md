---
name: trap-piping-a-background-run-through-tail-hides-all-progress-until-it-exits
description: TRAP (sess567): a run_in_background Bash whose command ends in `| tail -N` writes NOTHING to its output file until the pipeline exits — interim Read…
metadata:
  type: feedback
tags: [trap, background, harness, sess567, tooling]
---

# Never pipe a backgrounded rig run through `tail`

## What happened (sess567)

The D-0932 probe was launched as:

    timeout 900 tests/d0932_fence_takeover_probe.sh s567 2>&1 | tail -60

`tail` buffers its whole input and emits only at EOF, so the task's output file
stayed **empty for the entire ~14-minute run**. An interim `Read` of
`tasks/<id>.output` returned "the file exists but the contents are empty".

## Why that cost something real

Two decisions in that window needed to know which stage the probe was in:

- whether `run.sh` had finished its prep stage, because a pending edit to
  `run.sh` (the D-0939 reason-string fix) cannot be applied while a bash
  instance may still be reading the file — bash reads a script lazily by byte
  offset, so editing a running script corrupts the running instance;
- whether it was safe to `make modules`, because the probe md5-compares
  `/src/mxfs/mxfs.ko` against the local build on both nodes and a rebuild
  mid-probe fails the deploy check.

With no visible progress, both had to be held, and the session did other work
instead of the work it wanted to do.

## The rule

Let a backgrounded command write its **full** output to the task file. Never
`| tail`, never `| head`, never `| grep` at the top level of a backgrounded
invocation — those all buffer and defeat the interim `Read`.

    # wrong
    long_thing.sh 2>&1 | tail -60
    # right
    long_thing.sh 2>&1

Filter when you READ it, not when you write it:

    Read the output file, or: sed -e 's/noisy=[0-9]* //g' <output file>

This does not conflict with the no-polling rule. The prohibition is on *waiting*
by polling — an `until ... sleep` loop, `TaskOutput` on a local agent. A single
`Read` of the output file to answer a specific question ("is the prep stage
done?") is not a poll, and it is worthless if the file is empty by construction.

## Related

- `trap-never-rebuild-mxfs-ko-while-a-rig-harness-run-is-in-flight` — the build
  half of the same hazard.
