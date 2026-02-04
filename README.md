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
**MasqOverflow-Suite Enterprise** is an advanced offensive security framework designed to exploit critical vulnerabilities in legacy **Dnsmasq v2.51** deployments. It implements a collection of known CVEs discovered by Google Security Research and JSOF, enhanced with **Multi-Threading**, **ASLR Leak Primitives**, and **ROP Chain** capabilities.

**⚠️ DISCLAIMER:** This tool is for **EDUCATIONAL PURPOSES and AUTHORIZED PENETRATION TESTING ONLY**. Do not use against targets without explicit permission.

## 🚀 Enterprise Features
- **[NEW] Multi-Threaded Spraying**: High-speed payload delivery for maximum heap corruption probability.
- **[NEW] ASLR/Info Leak**: Implements CVE-2015-3294 variant to leak `libc` base address.
- **[NEW] Stealth Mode**: Packet fragmentation engine to bypass simple IDS/WAF signatures.
- **[NEW] ROP Chain Engine**: Dynamic ROP gadget construction for specific architectures.
- **Core Exploits**:
    - **CVE-2017-14491**: Heap Buffer Overflow (DNS Response).
    - **CVE-2017-14492**: IPv6 Router Advertisement Heap Overflow.
    - **CVE-2017-14493**: Stack Buffer Overflow (DHCPv6).
    - **CVE-2015-3294**: Malformed TCP Packet (Info Leak / DoS).
    - **DNSpooq**: Cache Poisoning Assessment.
    - **TCP Exhaustion**: Architectural DoS with File Descriptor limit bypass.

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

### ❓ FAQ

#### Q: Saya mendapat "Target CRASHED" saat mencoba RCE, apakah gagal?
**A: Tidak sepenuhnya.**
Dalam Binary Exploitation, perbedaan antara DoS (Crash) dan RCE seringkali hanya masalah milimeter di **Memory Offset**.
1.  **DoS (Partial Success)**: Payload berhasil menimpa memory (Buffer Overflow terjadi), tapi "alamat lompatan" (Return Address) meleset, sehingga program bingung dan crash. Ini membuktikan target **VULNERABLE**.
2.  **RCE (Full Success)**: Payload menimpa memory dengan presisi sempurna. Program "lompat" ke kode jahat kita (Shellcode/ROP).

**Kesimpulan:** Jika target crash, berarti celah keamanan **ADA**. Untuk mencapai RCE stabil, diperlukan debug mendalam pada firmware router untuk mencari offset `libc_base` yang presisi.

#### Q: Apa itu "DNS decompression loop detected"?
**A:** Itu indikator BAGUS!
Jika Anda menjalankan sniffer (seperti Wireshark/Evilimiter) dan melihat error ini, berarti payload kompresi DNS jahat (CVE-2017-14491) berhasil diproses oleh Dnsmasq target.

#### Q: Mengapa butuh `sudo`?
**A:** Script menggunakan `Raw Socket` untuk memalsukan IP/Header paket. OS Linux membatasi fitur ini hanya untuk user root.

**Q: "Too many open files" error?**
A: The tool attempts to auto-increase your system's `ulimit`. If it fails, run `ulimit -n 4096` manually before starting the script.

---
## ⚖️ License
This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---
*Created with ❤️ for the Security Community.*
