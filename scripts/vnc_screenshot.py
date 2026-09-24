#!/usr/bin/env python3
"""vnc_screenshot.py — save one frame of a VNC console as a PNG.

Usage: scripts/vnc_screenshot.py HOST:PORT OUT.png

For a guest whose console is VNC with no password: packer's installer VMs
(vnc://0.0.0.0:59xx in an osimager job log) and QEMU guests started with
-vnc. It connects SHARED, so a client already watching (packer typing a boot
command) keeps its session. It reads, and sends no key or pointer event.
Needs Pillow.
"""
import socket
import struct
import sys

from PIL import Image


def recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            sys.exit("vnc_screenshot: server closed the connection")
        buf += chunk
    return bytes(buf)


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__.strip().splitlines()[2])
    host, port = sys.argv[1].rsplit(":", 1)
    sock = socket.create_connection((host, int(port)), timeout=15)

    version = recv_exact(sock, 12)
    sock.sendall(b"RFB 003.008\n")
    if version >= b"RFB 003.007":
        count = recv_exact(sock, 1)[0]
        if count == 0:
            reason_len = struct.unpack(">I", recv_exact(sock, 4))[0]
            sys.exit("vnc_screenshot: refused: " + recv_exact(sock, reason_len).decode())
        types = recv_exact(sock, count)
        if 1 not in types:
            sys.exit("vnc_screenshot: server requires authentication (types %s)" % list(types))
        sock.sendall(b"\x01")
    else:
        if struct.unpack(">I", recv_exact(sock, 4))[0] != 1:
            sys.exit("vnc_screenshot: server requires authentication")
    if version >= b"RFB 003.008" and struct.unpack(">I", recv_exact(sock, 4))[0] != 0:
        sys.exit("vnc_screenshot: security handshake failed")

    sock.sendall(b"\x01")                       # ClientInit: shared
    width, height = struct.unpack(">HH", recv_exact(sock, 4))
    recv_exact(sock, 16)                        # server pixel format, replaced below
    recv_exact(sock, struct.unpack(">I", recv_exact(sock, 4))[0])  # desktop name

    # 32 bpp, little-endian, true colour, red/green/blue at bits 16/8/0.
    sock.sendall(struct.pack(">BxxxBBBBHHHBBBxxx", 0, 32, 24, 0, 1, 255, 255, 255, 16, 8, 0))
    sock.sendall(struct.pack(">BxHi", 2, 1, 0))  # SetEncodings: raw only
    sock.sendall(struct.pack(">BBHHHH", 3, 0, 0, 0, width, height))

    image = Image.new("RGB", (width, height))
    while True:
        kind = recv_exact(sock, 1)[0]
        if kind == 0:                           # FramebufferUpdate
            recv_exact(sock, 1)
            (rects,) = struct.unpack(">H", recv_exact(sock, 2))
            for _ in range(rects):
                x, y, w, h, enc = struct.unpack(">HHHHi", recv_exact(sock, 12))
                if enc == 0:
                    tile = Image.frombytes("RGB", (w, h), recv_exact(sock, w * h * 4), "raw", "BGRX")
                    image.paste(tile, (x, y))
                elif enc == -223:               # DesktopSize: pseudo-rectangle, no data
                    continue
                else:
                    sys.exit("vnc_screenshot: unexpected encoding %d" % enc)
            break
        if kind == 1:                           # SetColourMapEntries
            recv_exact(sock, 1)
            _, n = struct.unpack(">HH", recv_exact(sock, 4))
            recv_exact(sock, n * 6)
        elif kind == 2:                         # Bell
            continue
        elif kind == 3:                         # ServerCutText
            recv_exact(sock, 3)
            recv_exact(sock, struct.unpack(">I", recv_exact(sock, 4))[0])
        else:
            sys.exit("vnc_screenshot: unexpected message %d" % kind)
    sock.close()
    image.save(sys.argv[2])
    print("%s %dx%d" % (sys.argv[2], width, height))


if __name__ == "__main__":
    main()
