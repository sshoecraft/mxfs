---
name: trap-rig-vm-definitions-have-no-acpi-so-virsh-shutdown-and-guest-poweroff-never-power-off
description: TRAP (fixed 2026-09-23): lab libvirt VMs had no <acpi/>, so virsh shutdown was ignored and guest poweroff never powered off. scripts/libvirt_add_acpi…
metadata:
  type: feedback
---

The libvirt definitions of the rig VMs (test1..test32, machine pc-i440fx-noble) and pve9-1/pve9-2 were written without a `<features>` section, so no ACPI.

**What it looked like:**
- `virsh shutdown <vm>` did nothing (it sends an ACPI power-button press): test1/2/3/32 ignored it for 60+ s.
- `systemctl poweroff` inside a guest ran the whole shutdown (pve9-1's journal reached "Reached target poweroff.target - System Power Off" 17 s after the command), then the VM stayed `running` because the halted kernel could not switch the machine off.

**Fixed 2026-09-23 (user approved):** `scripts/libvirt_add_acpi.sh` added `<features><acpi/><apic/></features>` to all 36 lab domains' persistent definitions; each gets it at its next start. A newly defined VM needs it too — run the script on it.

**How to apply:**
- A VM that "won't shut down" is first a question about its definition, not an MXFS unmount/module hang: read the previous boot's journal (`journalctl -b -1`); if it reached poweroff.target, the guest finished.
- A domain started before the fix still lacks ACPI until restarted; `virsh destroy` it only after the guest has reached poweroff (safe when nothing is mounted).
