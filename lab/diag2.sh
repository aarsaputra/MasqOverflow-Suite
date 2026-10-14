#!/usr/bin/env bash
# Capture the dnsmasq<->attacker exchange on loopback to find why the reply is dropped.
set -u
LAB="$(cd "$(dirname "$0")" && pwd)"; cd "$LAB"
DM="$LAB/dnsmasq-git/src/dnsmasq"; CONF="$LAB/etc/dnsmasq.conf"
ATT_PID=""; DM_PID=""; TCP_PID=""
trap 'kill $ATT_PID $DM_PID $TCP_PID 2>/dev/null' EXIT

# is tcpdump usable without root?
if command -v tcpdump >/dev/null 2>&1; then
  sudo -n tcpdump -i lo -n -c 20 'port 5300' > capture.txt 2>&1 &
  TCP_PID=$!
  echo "tcpdump launched pid=$TCP_PID (may fail without root)"
else
  echo "no tcpdump"
fi

( exec python2 google_cve_2017_14491.py 127.0.0.2 5300 > att.log 2>&1 ) & ATT_PID=$!
sleep 1
echo "attacker: $(kill -0 $ATT_PID 2>/dev/null && echo up)"

"$DM" -C "$CONF" --no-daemon > dm.log 2>&1 & DM_PID=$!
sleep 1.5
echo "dnsmasq: $(kill -0 $DM_PID 2>/dev/null && echo up)"

echo "=== manual forward test: query dnsmasq on 53535 ==="
dig @127.0.0.1 -p 53535 -x 8.8.8.125 +time=4 +tries=1 > dig.out 2>&1
head -8 dig.out
sleep 1.5

echo "=== attacker log (did it receive?) ==="; cat att.log
echo "=== dnsmasq log ==="; grep -vE '^dnsmasq: reply' dm.log | tail -8
echo "=== tcpdump ==="; [ -f capture.txt ] && head -25 capture.txt
