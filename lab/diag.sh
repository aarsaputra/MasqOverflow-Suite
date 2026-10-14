#!/usr/bin/env bash
# Diagnose: does the attacker DNS actually receive queries sent to 127.0.0.2:5300?
set -u
LAB="$(cd "$(dirname "$0")" && pwd)"
cd "$LAB"
ATT_PID=""
trap '[ -n "$ATT_PID" ] && kill "$ATT_PID" 2>/dev/null' EXIT

echo "=== lo addresses ==="; ip -4 addr show lo | grep inet

echo "=== start attacker on 127.0.0.2:5300 ==="
( exec python2 google_cve_2017_14491.py 127.0.0.2 5300 > manual_att.log 2>&1 ) &
ATT_PID=$!
sleep 1.2
echo "pid=$ATT_PID alive=$(kill -0 $ATT_PID 2>/dev/null && echo yes || echo no)"
echo "log: $(cat manual_att.log)"
echo "socket table:"; ss -lnup 2>/dev/null | grep 5300 || echo "  no UDP socket on 5300!"

echo "=== dig directly at 127.0.0.2:5300 ==="
dig @127.0.0.2 -p 5300 -x 8.8.8.125 +time=3 +tries=1 2>&1 | head -6
sleep 1
echo "=== attacker log after dig ==="; cat manual_att.log
echo "=== udp count ==="; grep -c UDP manual_att.log || true
