"""Test vectors_2026 — builder offline, tidak mengirim paket."""
import importlib.util
import os
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from vectors_2026 import VECTORS_2026  # noqa: E402


def test_all_five_vectors_build():
    assert len(VECTORS_2026) == 5
    for name, desc, fn in VECTORS_2026:
        pkt = fn()
        raw = bytes(pkt)
        assert len(raw) > 40, f"{name}: paket terlalu kecil"
        # UDP dport 53 (DNS)
        from scapy.all import UDP

        assert pkt[UDP].dport == 53


def test_2291_carries_long_label():
    from vectors_2026 import cve_2026_2291_extract_name_overflow

    raw = bytes(cve_2026_2291_extract_name_overflow())
    # label 63-byte diawali 0x3f, diulang
    assert b"\x3f" + b"A" * 63 in raw


def test_4890_labels_zero():
    from vectors_2026 import cve_2026_4890_dnssec_infinite_loop

    raw = bytes(cve_2026_4890_dnssec_infinite_loop())
    assert b"\x00\x2e" in raw  # type covered = RRSIG


def test_4891_siglen_oversize():
    from vectors_2026 import cve_2026_4891_dnssec_oob_read

    raw = bytes(cve_2026_4891_dnssec_oob_read())
    assert b"\x10\x00" in raw  # sig_len 4096


def test_4893_family_zero():
    from vectors_2026 import cve_2026_4893_ecs_spoof

    raw = bytes(cve_2026_4893_ecs_spoof())
    # Option code 8 (ECS) + family 0
    assert b"\x00\x08\x00\x08\x00\x00" in raw


def test_5172_rdlength_ffff():
    from vectors_2026 import cve_2026_5172_extract_addresses_oob

    raw = bytes(cve_2026_5172_extract_addresses_oob())
    assert b"\xff\xff" in raw
