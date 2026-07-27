---
name: infra-sshpass-2arg-litters-repo-with-password-files
description: ROOT PROVEN: calling mxfs_sshpass.sh with the passfile omitted wrote the lab password into command-named files/dirs in $PWD. Fixed + cleaned 2026-07-…
metadata:
  type: project
tags: [infra, sshpass, secrets, tooling]
---

## Symptom

`/src/mxfs` accumulated command-shaped paths in the repo root and in `tests/`:

```
'true'   'x'
'hostname; uname -r; lsmod | grep -c mxfs'
'cat /sys/module/mxfs/parameters/fua_disable 2>/dev/null; modinfo mxfs ...'   (a DIRECTORY TREE)
"journalctl -k --since '2026-07-24 19:27:00' ... --utc 2>"                     (a DIRECTORY TREE)
'ls -d /var/log/journal 2>/dev/null && journalctl ...'                         (a DIRECTORY TREE)
'tests/cat /sys/module/mxfs/srcversion 2>/dev/null; mount -t mxfs | head -1'
```

Every leaf file was 8 bytes containing the plaintext lab node password.

## Root cause (proven by direct reproduction, not code reading)

`tools/mxfs_sshpass.sh` signature is `<host> <passfile> <command...>`. It did:

```sh
HOST="$1"; PASSFILE="$2"; shift 2
if [ ! -s "$PASSFILE" ]; then PASSFILE="$(mxfs_secrets.sh passfile "$PASSFILE")"; fi
```

Call it with the passfile **omitted** — `mxfs_sshpass.sh test1 "cat /sys/x 2>/dev/null; uptime"` —
and `PASSFILE` becomes the whole remote command. It isn't a file, so
`secrets_passfile` ran `mkdir -p "$(dirname "$path")"` on it. `dirname()` of a
command string is a perfectly valid relative path, so it **built that directory
tree under $PWD** and wrote the password into the leaf.

- Command with `/` in it → nested junk dir tree (`cat /sys/module/...`).
- Command with no `/` (`true`, `x`) → single 8-byte password file in `$PWD`.

Reproduced verbatim in a scratch dir before patching.

## Who was doing it

No committed script — audited every `$SSH`/`mxfs_sshpass.sh` call site under
`run.sh`, `scripts/`, `tests/`, `tools/`, `bench/`; all pass an absolute passfile
(`/tmp/.mxfs_pass`, `$PF`, `$PASS`, `${MXFS_PASS:-...}`). `run.sh::ssh_node()` is
correct. The junk came from **ad-hoc interactive/agent invocations** that dropped
the passfile arg — confirmed by hardcoded one-off timestamps baked into the
filenames (`--since '2026-07-24 19:27:00'`) and by the file mtimes.

## Fix (2026-07-26)

Both halves hardened so neither can litter again:

- `tools/mxfs_sshpass.sh` — passfile arg is now **optional and recognized, not
  guessed**: only an absolute path with no shell metacharacters is taken as the
  passfile; anything else stays part of the command and `/tmp/.mxfs_pass` is used.
  So the 2-arg form `mxfs_sshpass.sh <host> "<cmd>"` now works correctly instead
  of misfiring.
- `tools/mxfs_secrets.sh::secrets_passfile` — refuses any non-absolute or
  metacharacter-bearing path outright (`refusing command-shaped passfile path`)
  before the `mkdir -p`.

Verified: all three forms (2-arg, 3-arg, SCP) produce correct `sshpass` argv;
zero stray files created; legit absolute paths in non-existent dirs still get
created. Live remote execution NOT re-verified — test nodes were unreachable
(no route to 192.168.120.186) at the time of the fix.

## Watch for

If this recurs, grep for it with:
`find . -path ./.git -prune -o \( -name '*;*' -o -name '* *' -o -name '*|*' \) -print`
and `find . -type f -size -20c | xargs grep -l '<node-password>'`.
The lab password must never sit in the tree — MXFS is a public repo
(github.com/sshoecraft/mxfs).
