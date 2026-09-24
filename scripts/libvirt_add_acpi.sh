#!/bin/bash
#
# libvirt_add_acpi.sh — give lab VMs ACPI so they can power off
#
# Usage: scripts/libvirt_add_acpi.sh <domain> [<domain> ...]
#
# The rig VM definitions (test1..test32, pve9-1, pve9-2) were written without a
# <features> section, so they have no ACPI: `virsh shutdown` (an ACPI power
# button) is ignored, and a guest's own poweroff halts without switching the
# machine off, leaving the domain "running" with nothing inside it.
#
# Adds <features><acpi/><apic/></features> to each domain's persistent
# definition when it has no <features> element.  A running domain picks it up
# at its next start.  A domain that already has <features> is left untouched.
#
set -eu

[ $# -ge 1 ] || { echo "usage: $0 <domain> [...]" >&2; exit 2; }
V="virsh -c qemu:///system"

for dom in "$@"; do
    xml=$(timeout 20 $V dumpxml --inactive "$dom") || { echo "$dom: no such domain" >&2; exit 1; }
    if grep -q "<features>" <<< "$xml"; then
        echo "$dom: already has <features>; unchanged"
        continue
    fi
    DOMXML="$xml" python3 - <<'EOF' | timeout 20 $V define /dev/stdin >/dev/null
import os, sys, xml.etree.ElementTree as ET
root = ET.fromstring(os.environ["DOMXML"])
features = ET.Element("features")
ET.SubElement(features, "acpi")
ET.SubElement(features, "apic")
# libvirt expects <features> after <os>
os_index = list(root).index(root.find("os"))
root.insert(os_index + 1, features)
sys.stdout.write(ET.tostring(root, encoding="unicode"))
EOF
    if timeout 20 $V dumpxml --inactive "$dom" | grep -q "<acpi/>"; then
        echo "$dom: ACPI added (takes effect at next start)"
    else
        echo "$dom: define did not keep <acpi/>" >&2
        exit 1
    fi
done
