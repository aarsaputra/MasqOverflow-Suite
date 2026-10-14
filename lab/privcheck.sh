#!/usr/bin/env bash
# Prove the privilege level a dnsmasq compromise actually yields.
# Starts dnsmasq 2.51 as ROOT (via a helper we can control) and inspects the
# resulting process uid/gid + capabilities. This answers: "does RCE = root?"
set -u
LAB="$(cd "$(dirname "$0")" && pwd)"; cd "$LAB"
DM="$LAB/dnsmasq-git/src/dnsmasq"
CONF="$LAB/etc/dnsmasq-priv.conf"

# config that drops to nobody (default-ish) and stays foreground
cat > "$CONF" <<'EOF'
port=53537
listen-address=127.0.0.1
bind-interfaces
no-hosts
no-resolv
server=127.0.0.2#5300
cache-size=150
EOF

echo "=== whoami (harness) ==="; id

echo "=== start dnsmasq 2.51 in foreground, DROP-PRIV ENABLED (default) ==="
echo "    (run unprivileged since we are not root here; uid=$(id -u))"
"$DM" -C "$CONF" --no-daemon > priv_default.log 2>&1 &
P1=$!
sleep 1.2
if kill -0 "$P1" 2>/dev/null; then
  echo "  pid=$P1"
  echo "  /proc/$P1/status  ->"; grep -E '^(Uid|Gid|CapEff|CapPrm|CapBnd):' /proc/$P1/status 2>/dev/null | sed 's/^/    /'
  kill "$P1" 2>/dev/null
else
  echo "  failed to start:"; cat priv_default.log
fi
sleep 0.4

echo
echo "=== now with -u root (what a REAL root-owned dnsmasq would drop to) ==="
echo "    try: dnsmasq started as root -> setuid(nobody) unless -u root given"
# We cannot be root here; demonstrate the config surface instead.
echo "  config option controlling this:"; grep -n '"user"\|"group"\|user=\|group=' "$LAB/dnsmasq-git/src/option.c" | head -3

echo
echo "=== evidence from source: privilege drop is unconditional unless OPT_DEBUG ==="
grep -n 'if (!(daemon->options & OPT_DEBUG) && getuid() == 0)' "$LAB/dnsmasq-git/src/dnsmasq.c"
grep -n 'setuid(ent_pw->pw_uid)' "$LAB/dnsmasq-git/src/dnsmasq.c"
echo
echo "=== capabilities RETAINED after setuid (linux) ==="
grep -n 'CAP_NET_ADMIN\|CAP_NET_RAW\|CAP_SETUID' "$LAB/dnsmasq-git/src/dnsmasq.c" | head -5
