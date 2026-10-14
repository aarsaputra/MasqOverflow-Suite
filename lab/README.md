# lab/ — local dnsmasq 2.51 testbed (no Docker, no root)

This directory builds and runs a **genuinely vulnerable** dnsmasq 2.51 locally so
the tool can be tested against a real target instead of a live device.

Why not Docker: docker/podman are not installed on this host, and `sudo` needs a
password, so the container route from Google's instructions is unavailable.
Instead we build dnsmasq 2.51 from source and run it **unprivileged on a high
port** (53535) — no root required for the server side.

## What's here

| File | Purpose |
| :--- | :--- |
| `dnsmasq-git/` | dnsmasq source at tag `v2.51` (built → `src/dnsmasq`) |
| `etc/dnsmasq.conf` | test config: port 53535, forwards to attacker 127.0.0.2#5300 |
| `etc/dnsmasq-293.conf` | same, port 53536 (for the patched-system comparison) |
| `google_cve_2017_14491.py` | Google Security Research reference PoC (python2) |
| `run_lab.sh` | start attacker + dnsmasq, prime the cache, report |
| `ab_test.sh` | A/B: vulnerable 2.51 vs patched system 2.93 |
| `repeat.sh` | repeat priming N times (crash is non-deterministic) |
| `e2e.sh` | drives the REPO's `exploit_cve_2017_14491()` against the lab |
| `verify_payload.py` | asserts repo payload == Google reference (byte-for-byte) |
| `diag.sh`, `diag2.sh`, `instrument.sh` | diagnostics used during bring-up |

## Build (already done)

```bash
git clone --depth 1 --branch v2.51 https://thekelleys.org.uk/git/dnsmasq.git dnsmasq-git
cd dnsmasq-git
# 2.51 predates C23; modern GCC needs legacy-C flags. Also fix a K&R prototype
# in src/dnsmasq.h (int (*ipv4_callback)() -> explicit args) or use -std=gnu89.
make COPTS="-w -fcommon -Wno-error -std=gnu89"
./src/dnsmasq --version   # -> Dnsmasq version 2.51
```

## Run the proof

```bash
echo '127.0.0.2 alias needed for the attacker bind:'   # 127.0.0.0/8 is local by default on Linux
python3 verify_payload.py        # payload == Google reference (2261 bytes)
bash repeat.sh 30                # priming loop; reports crash or survival
bash e2e.sh                      # exercise the repo's delivery function
```

Requires `python2` (for Google's PoC), `dig`, `scapy`, and a local `dnsmasq`
(2.93) for the patched-comparison half of `ab_test.sh`.

## Findings from this testbed (2026-10-14)

- **Delivery model confirmed.** dnsmasq 2.51 forwards the PTR query to the
  attacker and **parses the malformed reply** — the log shows it consuming the
  hostile `DCBBEEEE…` records and the `ZZZ` overflow name. Typical run:
  `forwarded 125.8.8.8 = 5`, `hostile records parsed = 60`.
- **Crash is non-deterministic, as Google documents.** On this host (modern
  glibc/heap layout) dnsmasq 2.51 survived 30 priming rounds while still parsing
  the hostile response. So "no crash here" ≠ "wrong payload"; it matches the
  repo's own `reproduction_report.md` marking 14491 "Failed (Stable)".
- **The old delivery could never work.** Sending the reply straight at port 53
  is ignored — dnsmasq only parses replies on a socket awaiting an answer. Fixed
  by the attacker-DNS + priming model now in option 1.
- **False-positive oracle fixed.** The old `check_status_msg()` printed
  "SUCCESS: Target CRASHED" when the probe itself failed (`Operation not
  permitted` without root). It now prints INCONCLUSIVE instead.

## Cleanup

Nothing here binds a privileged port; kill any stray processes with
`kill $(cat dnsmasq.pid) $(cat attacker.pid)` (PID files written by the scripts).
