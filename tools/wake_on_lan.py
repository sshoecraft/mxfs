#!/usr/bin/env python3
"""Send a Wake-on-LAN magic packet.

For lab hosts with no remote power control (the physical Proxmox pair are
workstations without a BMC): a host that powered itself off can be started
again from the LAN, if its firmware has wake-on-LAN enabled.  A host that is
hung, not off, does not respond to this.

usage: tools/wake_on_lan.py <mac> [broadcast-address] [count]
    broadcast-address defaults to 255.255.255.255; the packet goes to UDP
    port 9 and is sent `count` times (default 3).
"""

import socket
import sys


def magic(mac):
    digits = mac.replace(":", "").replace("-", "").lower()
    if len(digits) != 12 or any(c not in "0123456789abcdef" for c in digits):
        raise ValueError("not a MAC address: %s" % mac)
    return b"\xff" * 6 + bytes.fromhex(digits) * 16


def main():
    if len(sys.argv) < 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    payload = magic(sys.argv[1])
    dest = sys.argv[2] if len(sys.argv) > 2 else "255.255.255.255"
    count = int(sys.argv[3]) if len(sys.argv) > 3 else 3
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for _ in range(count):
            s.sendto(payload, (dest, 9))
    print("sent %d magic packet(s) for %s to %s:9" % (count, sys.argv[1], dest))
    return 0


if __name__ == "__main__":
    sys.exit(main())
