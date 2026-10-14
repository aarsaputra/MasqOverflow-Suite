# Security Policy

## What this repository is

**MasqOverflow-Suite** is a **proof-of-concept / research** toolkit for assessing
legacy **dnsmasq** deployments (tested against 2.51). It exists to support
**authorized** security assessment, vulnerability research, and defensive
understanding of publicly disclosed CVEs.

It is **not** a weaponized exploit kit, and it does **not** demonstrate RCE — see
"Honest claims" below.

## Authorized use only

Use this tool **only** against systems that are one of:

- your own device / lab, or
- systems for which you hold **explicit written authorization** to test, or
- a local testbed you built yourself (`lab/` in this repo).

Do **not** run it against third-party infrastructure, networks you do not own,
or any host where you lack permission. Unauthorized access or disruption of
computer systems is illegal in most jurisdictions (e.g. Indonesia: UU ITE;
US: CFAA; UK: Computer Misuse Act) and may carry criminal liability.

**Third parties matter.** A DNS/hotspot service you test may be shared. Only test
when no one else depends on that service at that moment.

## Honest claims (so the tool cannot be misused as a false promise)

| Claim | Reality |
| :--- | :--- |
| "RCE chain" | **Not demonstrated.** libc offsets in `ARCH_PRESETS` are PLACEHOLDERS; no target offset is validated. |
| "ASLR leak" | **Heuristic.** Flags any large response as a possible leak; no validation. |
| "Target CRASHED" | Means only "stopped answering a probe". Verified-crash requires target-side logs/uptime. Without root, the probe reports INCONCLUSIVE. |
| RCE ⇒ device root | **No.** dnsmasq drops privileges (`setuid`) and keeps only `CAP_NET_ADMIN`/`CAP_NET_RAW`; a successful code-exec yields the *dnsmasq user*, not root. |
| DoS → security finding | Resource exhaustion is **availability**, not a memory-safety breach. Report it as DoS. |

## Restricted features

The resource-exhaustion vectors (menu 7 "TCP Exhaustion", 8 "Heavy DOS") are
**disabled by default**. They require a deliberate two-key opt-in:

```bash
MASQ_ALLOW_DOS=1 python3 masq_overflow.py <TARGET>   # then type YES at the prompt
```

Rationale: untargeted resource exhaustion is the least defensible part of the
toolkit and the easiest to cause collateral damage with.

## Reporting a problem

- **Vulnerability in dnsmasq itself** → report upstream to the dnsmasq maintainer
  (Simon Kelley) and/or the relevant CNA. Do **not** open a public issue here.
- **Bug in this toolkit** (e.g. a false claim, a crash in the harness, an unsafe
  default) → open a GitHub issue titled `[bug] …`, or contact the maintainer via
  the repository profile. Please include the exact command and observed output.

## No warranty

Provided under the MIT License, **as-is**, without warranty. You are responsible
for how you use it.
