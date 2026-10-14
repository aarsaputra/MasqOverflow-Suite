# 🎭 MasqOverflow-Suite
> *Advanced Security Assessment Tool for Dnsmasq 2.51*

```text
   __  __                  ___                 __ _            
  |  \/  | __ _ ___  __ _ / _ \__   _____ _ __/ _| | _____      __
  | |\/| |/ _` / __|/ _` | | | \ \ / / _ \ '__| |_| |/ _ \ \ /\ / /
  | |  | | (_| \__ \ (_| | |_| |\ V /  __/ |  |  _| | (_) \ V  V / 
  |_|  |_|\__,_|___/\__, |\___/  \_/ \___|_|  |_| |_|\___/ \_/\_/  
                       |_|                                         
                                            v2.0.0 Enterprise
```

## 📜 Description
**MasqOverflow-Suite** is an offensive security framework for assessing legacy
**Dnsmasq** deployments (tested against v2.51). It implements proof-of-concept
vectors for several publicly disclosed CVEs (Google Security Research, JSOF),
with multi-threading and a configurable delivery model.

**⚠️ DISCLAIMER:** For **EDUCATIONAL PURPOSES and AUTHORIZED PENETRATION TESTING ONLY**. Do not use against targets without explicit permission.

## ⚠️ Status & Scope (read before trusting any result)

**Verified working:**
- Delivery of the CVE-2017-14491 malformed DNS reply via an attacker-controlled
  DNS server + cache priming (verified byte-identical to Google's reference PoC,
  2261 bytes) — see `--help`/option 1.

**Not verified / do not claim as results:**
- **RCE is NOT demonstrated.** No offset is validated for any real target; the
  libc offsets in `ARCH_PRESETS` are PLACEHOLDERS (see below). Option 9 only
  *constructs and sends* a chain; it does not prove code execution.
- The "ASLR leak" (CVE-2015-3294) is a **heuristic**: it flags any ≥50-byte
  response as a possible leak and any pointer-looking word as a libc pointer.
  No validation. Treat its "calculated libc base" as a guess.
- The IPV6 RA / DHCPv6 vectors require IPv6 enabled on the target and (for
  DHCPv6) an IPv6 `dhcp-range`; they will simply fail otherwise.
- **Crash semantics:** "target stopped responding" is NOT proof of a crash.
  The tool prints INCONCLUSIVE when its probe cannot run (e.g. without root).

## 🔧 PLACEHOLDER values you MUST replace before use

These are illustrative, NOT target-ready. Calibrate per target (firmware
extraction + Ghidra/GDB — see `reports/offset_discovery.md`):

| Constant | Where | Status |
| :--- | :--- | :--- |
| `ARCH_PRESETS[*]["system" / "pop_rdi" / "bin_sh"]` | masq_overflow.py | **PLACEHOLDER** — not from any real binary |
| `ARCH_PRESETS[*]["leak_offset"]` (0x21bf67) | masq_overflow.py | **PLACEHOLDER** — valid only for one Android hotspot build |
| `ARCH_PRESETS[*]["fallback_base"]` | masq_overflow.py | **PLACEHOLDER** — brute-forcing 32-bit ASLR is infeasible (1:4e9) |

## 🚀 Features
- **[v3] Attacker-DNS delivery** for CVE-2017-14491 (the correct model).
- **Multi-Threaded Spraying**: parallel payload delivery (note: more packets ≠
  more reliability; the 14491 crash is non-deterministic).
- **Stealth Mode**: UDP/TCP fragmentation toggle (evades naive IDS only — not a
  guarantee).
- **Core vectors**:
    - **CVE-2017-14491**: Heap Buffer Overflow (DNS Response) — *delivery verified*.
    - **CVE-2017-14492**: IPv6 Router Advertisement Heap Overflow.
    - **CVE-2017-14493**: Stack Buffer Overflow (DHCPv6).
    - **CVE-2015-3294**: Malformed TCP Packet (Info Leak / DoS) — *heuristic*.
    - **DNSpooq** (CVE-2020-25684/5/6): Cache Poisoning race.
    - **TCP Exhaustion / Heavy DoS**: Architectural resource exhaustion.

## 📦 Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-repo/MasqOverflow-Suite.git
   cd MasqOverflow-Suite
   ```

2. **Run the installer:**
   ```bash
   chmod +x install.sh
   ./install.sh
   ```

## 🛠️ Usage
This tool requires **root privileges** to craft raw packets (Scapy).

```bash
sudo python3 masq_overflow.py <TARGET_IP>
```

**Interactive Menu:**
Once launched, you can choose from **9 Attack Vectors**:

1. `CVE-2017-14491` - Classic Heap Overflow.
2. `CVE-2017-14492` - IPv6 RA Overflow.
3. `CVE-2017-14493` - DHCPv6 Stack Overflow.
4. `CVE-2015-3294` - TCP Malformed Packet (DoS).
5. `CVE-2017-13704` - Oversized EDNS0 (Integer Overflow).
6. `DNSpooq` - Threaded Cache Poisoning.
7. `TCP Exhaustion` - Architectural Resource Exhaustion.
8. `Heavy DOS` - 100MB Flood for Stress Testing.
9. **[ENTERPRISE] Enhanced RCE Chain** (Leak + ROP + Spray).
S. **Toggle Stealth Mode** (Frag ON/OFF).
... and more.

## 📚 References & Credits
This tool is based on deep analysis of the following security research:

| Source | Vulnerability | Link |
| :--- | :--- | :--- |
| **Google Security** | Heap/Stack Overflows | [Behind the Masq](https://security.googleblog.com/2017/10/behind-masq-yet-more-dns-and-dhcp.html) |
| **JSOF Research** | DNSpooq (Poisoning) | [DNSpooq Paper](https://www.jsof-tech.com/disclosures/dnspooq/) |
| **NVD** | TCP DoS / Info Leak | [CVE-2015-3294](https://nvd.nist.gov/vuln/detail/CVE-2015-3294) |
| **BitSight** | Global Exposure | [Observation Footprint](https://www.bitsight.com/groma-explorer/thekelleys/dnsmasq/251) |

## ❓ FAQ / Troubleshooting

#### Q: Saya mendapat "Target stabil" atau "INCONCLUSIVE" pada RCE, apakah gagal?
**A: Ya — belum terbukti berhasil.**
DoA/crash dan RCE itu dua hal berbeda, dan tool ini **tidak** membuktikan RCE.
1.  **INCONCLUSIVE**: probe liveness tidak bisa jalan (mis. tanpa root, raw
    socket ditolak). Ini BUKAN crash — jalankan sebagai root lalu cek ulang.
2.  **Target stabil**: target masih menjawab → payload tidak berefek.
3.  **"Tidak merespons"**: indikasi DoS/crash, tapi BUKAN bukti pasti crash —
    verifikasi lewat log/uptime target. Untuk mencapai RCE perlu offset libc
    hasil debug firmware target (`reports/offset_discovery.md`); angka di
    `ARCH_PRESETS` masih PLACEHOLDER.

#### Q: Apa itu "DNS decompression loop detected"?
**A:** Itu indikator payload kompresi DNS (CVE-2017-14491) sampai ke parser
Dnsmasq target — artinya DELIVERY berhasil, bukan otomatis crash/RCE.

#### Q: Mengapa butuh `sudo`?
**A:** Script memakai Raw Socket + Scapy untuk memalsukan IP/header paket.
Tanpa root, probe liveness gagal dan verdict menjadi INCONCLUSIVE (bukan crash).

**Q: "Too many open files" error?**
A: The tool attempts to auto-increase your system's `ulimit`. If it fails, run `ulimit -n 4096` manually before starting the script.

#### Q: Bagaimana cara uji CVE-2017-14491 dengan benar?
**A:** Dnsmasq hanya memproses DNS reply pada socket tempat ia MENUNGGU jawaban.
Mengirim reply palsu langsung ke port 53 target tidak akan diproses. Model yang
benar: jalankan DNS server milik penyerang, arahkan target untuk FORWARD ke situ
(`server=<ip>#<port>`), lalu picu/prime query. Itulah yang dilakukan opsi 1
(lihat `lab/` untuk testbed dnsmasq 2.51 lokal).

---
## ⚖️ License
This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---
*Created with ❤️ for the Security Community.*
