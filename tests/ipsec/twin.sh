#!/bin/sh
# Measured for decision 0324: run as probe.sh is, with twin.sh in its place.
# Two charons in ONE network namespace, each with a private /run. Bounded:
# each runs under `timeout 8`, and the container's own timeout holds the rest.
apk add -q strongswan iproute2 >/dev/null 2>&1
C=/usr/lib/strongswan/charon
for n in a b; do
	mkdir -p /etc/$n
	printf 'charon {\n\tplugins {\n\t\tinclude /etc/strongswan.d/charon/*.conf\n\t\tvici { socket = unix:///tmp/%s.vici }\n\t}\n}\n' $n > /etc/$n/strongswan.conf
	unshare -m sh -c "mount -t tmpfs t /run; STRONGSWAN_CONF=/etc/$n/strongswan.conf timeout 8 $C > /tmp/$n.log 2>&1" &
	sleep 3
done
wait
for n in a b; do
	echo "twin $n: $(grep -ciE 'unable to bind|bind.*failed|Address in use|could not open socket' /tmp/$n.log) bind failure line(s); $(grep -iE 'bind|socket|500' /tmp/$n.log | head -3 | tr '\n' ' ' | cut -c1-220)"
done
