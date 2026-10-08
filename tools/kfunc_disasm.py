#!/usr/bin/env python3
# kfunc_disasm.py — disassemble named functions of the RUNNING kernel, read-only.
#
# For a kernel whose source is not on this host (the rig's and clyde's Ubuntu
# 6.8.0-101-generic: /src/linux tracks upstream, and a distribution kernel's own
# source is not downloaded), the code that actually runs is still readable: the
# text is in /proc/kcore and the symbols in /proc/kallsyms.  Each function is
# read from its symbol to the next one, disassembled with objdump, and every
# call/jump target, RIP-relative operand and absolute kernel address is
# annotated with the symbol it lands in.
#
# Usage: sudo python3 tools/kfunc_disasm.py <function> [function ...]
# Nothing is written anywhere but stdout.

import bisect, os, re, struct, subprocess, sys, tempfile

KADDR_MIN = 0xffff800000000000


class Kcore:
    def __init__(self, path="/proc/kcore"):
        self.f = open(path, "rb", buffering=0)
        hdr = self.f.read(64)
        if hdr[:4] != b"\x7fELF":
            raise SystemExit("kfunc_disasm: /proc/kcore is not an ELF core")
        e_phoff = struct.unpack_from("<Q", hdr, 0x20)[0]
        e_phentsize = struct.unpack_from("<H", hdr, 0x36)[0]
        e_phnum = struct.unpack_from("<H", hdr, 0x38)[0]
        self.segs = []
        self.f.seek(e_phoff)
        pht = self.f.read(e_phentsize * e_phnum)
        for i in range(e_phnum):
            p_type = struct.unpack_from("<I", pht, i * e_phentsize)[0]
            if p_type != 1:  # PT_LOAD
                continue
            p_offset, p_vaddr, _pa, _fsz, p_memsz = struct.unpack_from(
                "<QQQQQ", pht, i * e_phentsize + 8)
            self.segs.append((p_vaddr, p_memsz, p_offset))
        self.segs.sort()
        self.starts = [s[0] for s in self.segs]

    def read(self, addr, size):
        i = bisect.bisect_right(self.starts, addr) - 1
        if i < 0:
            raise IOError(f"addr {addr:#x} below all segments")
        va, msz, off = self.segs[i]
        if addr + size > va + msz:
            raise IOError(f"addr {addr:#x}+{size} outside segment")
        self.f.seek(off + (addr - va))
        d = self.f.read(size)
        if len(d) != size:
            raise IOError(f"short read at {addr:#x}")
        return d


class Ksyms:
    def __init__(self):
        rows = []
        self.byname = {}
        with open("/proc/kallsyms") as f:
            for line in f:
                p = line.split()
                if len(p) < 3:
                    continue
                a = int(p[0], 16)
                if a == 0:
                    continue
                rows.append((a, p[2]))
                self.byname.setdefault(p[2], a)
        if not rows:
            raise SystemExit("kfunc_disasm: /proc/kallsyms shows no addresses (run as root)")
        rows.sort()
        self.addrs = [a for a, n in rows]
        self.names = [n for a, n in rows]

    def sym(self, addr):
        if addr < KADDR_MIN:
            return None
        i = bisect.bisect_right(self.addrs, addr) - 1
        if i < 0:
            return None
        off = addr - self.addrs[i]
        if off > 0x100000:
            return None
        return f"{self.names[i]}+{off:#x}" if off else self.names[i]

    def end_of(self, addr):
        i = bisect.bisect_right(self.addrs, addr)
        while i < len(self.addrs) and self.addrs[i] == addr:
            i += 1
        return self.addrs[i] if i < len(self.addrs) else addr + 0x1000


def main():
    if len(sys.argv) < 2:
        raise SystemExit("usage: sudo python3 tools/kfunc_disasm.py <function> [function ...]")
    kc, ks = Kcore(), Ksyms()
    hexaddr = re.compile(r"0x(ffff[0-9a-f]{12})")
    for name in sys.argv[1:]:
        if name not in ks.byname:
            print(f"### {name}: not in /proc/kallsyms (inlined or absent)")
            continue
        start = ks.byname[name]
        end = ks.end_of(start)
        code = kc.read(start, end - start)
        with tempfile.NamedTemporaryFile(suffix=".bin") as t:
            t.write(code)
            t.flush()
            out = subprocess.run(
                ["objdump", "-D", "-b", "binary", "-m", "i386:x86-64",
                 f"--adjust-vma={start:#x}", "--no-show-raw-insn", t.name],
                capture_output=True, text=True, check=True).stdout
        print(f"### {name} {start:#x}..{end:#x} ({end - start} bytes)")
        for line in out.splitlines():
            if not re.match(r"\s*ffff[0-9a-f]+:", line):
                continue
            notes = []
            for m in hexaddr.finditer(line):
                s = ks.sym(int(m.group(1), 16))
                if s:
                    notes.append(s)
            m = re.search(r"#\s*(0x)?(ffff[0-9a-f]{12})", line)
            if m:
                s = ks.sym(int(m.group(2), 16))
                if s and s not in notes:
                    notes.append(s)
            print(line + (("    <" + ", ".join(notes) + ">") if notes else ""))
        print()


if __name__ == "__main__":
    main()
