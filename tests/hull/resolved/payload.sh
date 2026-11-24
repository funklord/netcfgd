#!/bin/sh
# What netcfgd leaves in systemd-resolved per link as a scope states, drops
# and loses its settings (project.md 10.916, closing 10.908's open gap).
#
# Always exits 0 and reports through /verdict/resolved, one line a check,
# with `VERDICT ok` or `VERDICT bad` last, so the host reads the verdict
# whatever happened.
#
# HOW IT STOPS: the systemd wait counts to 20 s, every command is a bounded
# one-shot, and the vm takes systemd with it.
set -u
out=/verdict/resolved
: > "$out"
say() { echo "$*" >> "$out"; echo "resolved: $*"; }
waited=0
while [ ! -S /run/systemd/private ] && [ "$waited" -lt 200 ]; do
	waited=$((waited + 1))
	sleep 0.1
done
timeout 60 systemctl is-system-running --wait > /dev/null 2>&1
timeout 60 systemctl start dbus systemd-resolved
# The host's kernel and modules (hull.conf); `dummy` is a module there.
say "kernel $(uname -r); modprobe dummy: [$(modprobe dummy 2>&1)]"

say "systemd $(systemctl --version | head -1 | cut -d' ' -f2); resolved $(systemctl is-active systemd-resolved)"
tls() { resolvectl dnsovertls dummy0 2>&1 | sed 's/^[^:]*: *//'; }
sec() { resolvectl dnssec dummy0 2>&1 | sed 's/^[^:]*: *//'; }
servers() { resolvectl dns dummy0 2>&1 | sed 's/^Link [0-9]* ([^)]*): *//'; }

work=$(mktemp -d)
mkdir -p "$work/etc" "$work/run"
export NCFG_CONFIG_DIR="$work/etc" NCFG_RUN_DIR="$work/run"
ncfg=/mnt/repo/c/ncfg
write() { # $1: the server, $2: the scope's extra lines
	printf 'global {\n\tdns { mode = "resolved" }\n}\ndevice dummy0 { kind = "dummy" }\ninterface dummy0 {\n\tconfig = "10.9.0.1/24"\n\tdns {\n\t\tservers = ["%s"]\n%s\t}\n}\n' \
		"$1" "$2" > "$work/etc/netcfgd.conf"
}

failed=0
check() { # $1 what, $2 actual, $3 expected
	if [ "$2" = "$3" ]; then say "ok   $1: $2"; else say "FAIL $1: [$2], wanted [$3]"; failed=1; fi
}
domains() { resolvectl domain dummy0 2>&1 | sed 's/.*: *//'; }

write '192.0.2.53:853#dns.example' '		transport = "tls"
		dnssec    = "allow"
		domains   = ["corp.example"]
'
timeout 60 "$ncfg" apply > "$work/apply1" 2>&1
sed 's/^/  apply1: /' "$work/apply1" | grep -v '\[observe\]' >> "$out"
check "stated: DNS over TLS" "$(tls)" "yes"
check "stated: dnssec" "$(sec)" "allow-downgrade"
check "stated: servers" "$(servers)" "192.0.2.53#dns.example"
check "stated: domains" "$(domains)" "corp.example"
# 10.916's leak: resolvectl asked with no value prints the link, into apply.
check "apply prints nothing of resolvectl's" "$(grep -c 'Link [0-9]* (' "$work/apply1")" "0"

# The scope drops transport, dnssec and the domains, and keeps a server.
write '192.0.2.53' ''
timeout 60 "$ncfg" apply > "$work/apply2" 2>&1
sed 's/^/  apply2: /' "$work/apply2" | grep -v '\[observe\]' >> "$out"
check "dropped: DNS over TLS back to the global setting" "$(tls)" "$(resolvectl dnsovertls 2>&1 | head -1 | sed 's/.*: //')"
check "dropped: dnssec back to the global setting" "$(sec)" "$(resolvectl dnssec 2>&1 | head -1 | sed 's/.*: //')"
check "dropped: the server kept, so no moment without one" "$(servers)" "192.0.2.53"
check "dropped: the domains cleared" "$(domains)" ""

# And a scope with no servers at all clears them.
printf 'global {\n\tdns { mode = "resolved" }\n}\ndevice dummy0 { kind = "dummy" }\ninterface dummy0 {\n\tconfig = "10.9.0.1/24"\n\tdns { servers = [] }\n}\n' > "$work/etc/netcfgd.conf"
timeout 60 "$ncfg" apply > "$work/apply3" 2>&1
sed 's/^/  apply3: /' "$work/apply3" | grep -v '\[observe\]' >> "$out"
check "no scope left: the link reverted, no servers" "$(servers)" ""
check "no scope left: and a second plan has nothing to do" \
	"$(timeout 60 "$ncfg" plan 2>&1 | grep -c 'nothing to do')" "1"
# 10.918: the globals scope as resolved's own settings, by a drop-in. Never
# `lo`, which resolved refuses as a link (the measure lines below).
global() { resolvectl dns 2>&1 | sed -n 's/^Global: *//p'; }
gdomains() { resolvectl domain 2>&1 | sed -n 's/^Global: *//p'; }
printf 'global {\n\tdns { mode = "resolved"; servers = ["192.0.2.77"]; domains = ["corp.example"] }\n}\ndevice dummy0 { kind = "dummy" }\ninterface dummy0 {\n\tconfig = "10.9.0.1/24"\n\tdns { servers = ["192.0.2.53"] }\n}\n' > "$work/etc/netcfgd.conf"
timeout 60 "$ncfg" apply > "$work/apply4" 2>&1
sed 's/^/  apply4: /' "$work/apply4" | grep -v '\[observe\]' >> "$out"
check "globals: resolved's own servers" "$(global)" "192.0.2.77"
check "globals: and its domains" "$(gdomains)" "corp.example"
check "globals: the link's server beside them" "$(servers)" "192.0.2.53"
check "globals: a second plan has nothing to do" \
	"$(timeout 60 "$ncfg" plan 2>&1 | grep -c 'nothing to do')" "1"
printf 'global {\n\tdns { mode = "resolved" }\n}\ndevice dummy0 { kind = "dummy" }\ninterface dummy0 {\n\tconfig = "10.9.0.1/24"\n\tdns { servers = ["192.0.2.53"] }\n}\n' > "$work/etc/netcfgd.conf"
timeout 60 "$ncfg" apply > "$work/apply5" 2>&1
sed 's/^/  apply5: /' "$work/apply5" | grep -v '\[observe\]' >> "$out"
check "globals dropped: resolved's own servers gone" "$(global)" ""
check "globals dropped: and its domains" "$(gdomains)" ""
check "globals dropped: the drop-in removed" \
	"$(ls /run/systemd/resolved.conf.d/netcfgd.conf 2>/dev/null | wc -l)" "0"
check "globals dropped: the link's server survives the restart" "$(servers)" "192.0.2.53"

# What resolved makes of a value on the loopback, which is where netcfgd has
# sent the global scope: asked directly, so the reading is resolved's own.
said=$(resolvectl dns lo 192.0.2.99 2>&1); status=$?
say "measure: resolvectl dns lo 192.0.2.99 -> exit $status [$said]"
said=$(resolvectl domain lo example.net 2>&1); status=$?
say "measure: resolvectl domain lo example.net -> exit $status [$said]"
[ "$failed" -eq 0 ] && say "VERDICT ok" || say "VERDICT bad"
exit 0
