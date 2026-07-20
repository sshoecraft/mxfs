#!/usr/bin/env python3
"""vm_console_type.py — type text into a libvirt VM's VGA console via send-key.

For recovering a test VM whose guest networking failed to come up (no SSH):
log in on the console and fix networking.  Uses `virsh send-key --codeset linux`.

Usage:
  vm_console_type.py <domain> --enter                 # just press Enter
  vm_console_type.py <domain> --text 'root' --enter   # type then Enter
  vm_console_type.py <domain> --passfile /tmp/.mxfs_pass --enter  # type secret
"""
import argparse, subprocess, sys, time

VIRSH = ["virsh", "-c", "qemu:///system"]

# Linux input-event keycodes (include/uapi/linux/input-event-codes.h)
KEY = {
    'a':30,'b':48,'c':46,'d':32,'e':18,'f':33,'g':34,'h':35,'i':23,'j':36,
    'k':37,'l':38,'m':50,'n':49,'o':24,'p':25,'q':16,'r':19,'s':31,'t':20,
    'u':22,'v':47,'w':17,'x':45,'y':21,'z':44,
    '1':2,'2':3,'3':4,'4':5,'5':6,'6':7,'7':8,'8':9,'9':10,'0':11,
    '-':12,'=':13,'[':26,']':27,';':39,"'":40,'`':41,'\\':43,',':51,'.':52,
    '/':53,' ':57,
}
SHIFT = 42
# shifted symbols -> base key
SHIFTED = {
    '!':'1','@':'2','#':'3','$':'4','%':'5','^':'6','&':'7','*':'8','(':'9',
    ')':'0','_':'-','+':'=','{':'[','}':']',':':';','"':"'",'~':'`','|':'\\',
    '<':',','>':'.','?':'/',
}
ENTER = 28

def send(dom, codes):
    cmd = VIRSH + ["send-key", dom, "--codeset", "linux", "--holdtime", "40"] + [str(c) for c in codes]
    subprocess.run(cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.12)

def type_char(dom, ch):
    if ch in KEY:
        send(dom, [KEY[ch]])
    elif ch.isupper() and ch.lower() in KEY:
        send(dom, [SHIFT, KEY[ch.lower()]])
    elif ch in SHIFTED:
        send(dom, [SHIFT, KEY[SHIFTED[ch]]])
    else:
        sys.stderr.write(f"WARN: no keycode for {ch!r}, skipping\n")

def type_string(dom, s):
    for ch in s:
        type_char(dom, ch)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("domain")
    ap.add_argument("--text", default=None)
    ap.add_argument("--passfile", default=None)
    ap.add_argument("--enter", action="store_true")
    ap.add_argument("--pre-enter", action="store_true", help="press Enter first (wake prompt)")
    a = ap.parse_args()
    if a.pre_enter:
        send(a.domain, [ENTER]); time.sleep(0.5)
    if a.text is not None:
        type_string(a.domain, a.text)
    if a.passfile is not None:
        with open(a.passfile) as f:
            secret = f.read().rstrip("\n")
        type_string(a.domain, secret)
    if a.enter:
        send(a.domain, [ENTER])

if __name__ == "__main__":
    main()
