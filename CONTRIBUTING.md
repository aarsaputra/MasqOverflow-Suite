# Contributing to MasqOverflow-Suite

Thank you for your interest in contributing! We welcome help from the security community to improve this framework.

## How to Contribute

### 1. Reporting Bugs 🐛
If you find a bug or a target that *should* be vulnerable but isn't working:
- Open an **Issue** on GitHub.
- Include the output of `nmap -sV` and `masq_overflow.py` (scrub sensitive IPs).
- Describe the expected vs actual behavior.

### 2. Suggesting Features 💡
Have an idea for a new exploit module or evasion technique?
- Open an **Issue** with the tag `enhancement`.
- Explain the theoretical attack vector and provide references (CVE links).

### 3. Submitting Code (Pull Requests) 🛠️
1.  **Fork** the repository.
2.  Create a new branch: `git checkout -b feature/amazing-exploit`
3.  Commit your changes: `git commit -m 'Add exploit for CVE-20xx-xxxx'`
4.  Push to the branch: `git push origin feature/amazing-exploit`
5.  Open a **Pull Request**.

## Coding Standards
- **Python 3**: Ensure compatibility with Python 3.6+.
- **Scapy**: Use Scapy for all packet manipulation.
- **Root Checks**: Always verify root privileges (`os.geteuid()`) if using raw sockets.
- **No Malicious Payloads**: This tool is for **verification/audit**. Do not include active malware, ransomware, or non-audit destructive payloads.

## Disclaimer
By contributing, you agree that your code will be licensed under the **MIT License** of this project.
