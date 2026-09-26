#!/usr/bin/env python3
#
# qmp_screendump.py — save a QEMU guest's screen as a PNG through its QMP socket
#
# Usage: scripts/qmp_screendump.py SOCKET OUT.png
#
# For a guest with no console to read: an osimager/Packer build waiting on an
# installer ("Waiting for SSH to become available..." and nothing else) shows
# where the installer stopped only on its screen.  Packer names the socket in
# its log ("QMP socket at: ...").  QEMU writes a PPM; PIL converts it.
#
import json
import os
import socket
import sys
import tempfile

from PIL import Image


def qmp(sock, f, cmd, args=None):
    msg = {"execute": cmd}
    if args:
        msg["arguments"] = args
    f.write(json.dumps(msg) + "\n")
    f.flush()
    while True:
        r = json.loads(f.readline())
        if "event" not in r:
            return r


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: qmp_screendump.py SOCKET OUT.png")
    path, out = sys.argv[1], sys.argv[2]
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(10)
    s.connect(path)
    f = s.makefile("rw")
    f.readline()
    qmp(s, f, "qmp_capabilities")
    fd, ppm = tempfile.mkstemp(suffix=".ppm")
    os.close(fd)
    try:
        r = qmp(s, f, "screendump", {"filename": ppm})
        if "error" in r:
            sys.exit("screendump: %s" % r["error"])
        Image.open(ppm).save(out)
    finally:
        os.unlink(ppm)
    print(out)


if __name__ == "__main__":
    main()
