---
name: feedback-every-bash-command-starts-with-an-allowlisted-program-never-cd-sleep-or-an-env-prefix
description: USER (furious, 0.90.53): commands starting `cd …;`, `sleep`, `VAR=… cmd`, zcat stopped an unattended session on approval prompts. Start with allowlis…
metadata:
  type: feedback
tags: [permissions, allowlist, unattended, harness]
---

The project allowlist (`.claude/settings.json`) matches each piece of a command on its FIRST word.  `tests/:*`,
`tools/:*`, `scripts/:*`, `./run.sh:*`, `python3`, `grep`, `timeout`, `virsh`, `make`, `chmod`, `cat`, `ls` … are on
it; `cd`, `sleep`, `export`, an inline `VAR=value cmd` prefix or `E=…;` assignment, `( … ) &` / `( time … )`
subshells, `zcat`, `strings`, `ps`, `sudo`, `systemctl` are NOT.  Each one stops an unattended session on a
permission prompt until a human happens to look.

What bit (2026-10-05, 0.90.53): 55 of 57 Bash calls in one session began `cd /home/steve/src/mxfs; …`, rig launches
were typed inline with `export PF_KNOBS=…; sleep 60; …; ( sleep 60; sampler ) &`, logs read with `zcat`, the
cold-audit log with `sudo`.  The user approved them by hand and said: "go back and look at what bash commands you
ran that would kick off a permissions error … just don't do it again".  (This is NOT the ccloop delegate hook that
refuses an 8th consecutive Bash call; that is a separate thing.)

How to apply:
- The shell already starts in the repo root.  Never begin with `cd`; use absolute paths for the scratchpad.
- Rig launches: `tests/mpath/lap_chain.sh laps <config> <group> <tag> <count> [--prep] [--delay s] [--knobs "k=v"]
  [--sampler node]`, or `tests/mpath/lap_chain.sh row <config> <group> <run_id> <script> --budget s`.
- Kernel logs, plain or .gz: `tools/kgrep.py [-e RE] [-v RE] [--from MARK] [--cut N] [--max N] [-c] [-A/-B N] FILE…`
  — never `zcat | sed | grep | cut`.
- Processes: `tools/mxfs_pgrep.sh`, never `ps`.  Strings in a binary: `grep -ac`, never `strings`.
- The cold-audit evidence log is world-readable since 0.90.53 (tests/tooling/chk_clean.sh) — never `sudo`.
- Anything else multi-step or env-dependent: a script under `tests/` or `tools/`, called with arguments.
