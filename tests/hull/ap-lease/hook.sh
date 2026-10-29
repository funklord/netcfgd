#!/bin/sh
# dhcpcd's hook: what the server gave, for the payload to read. dhcpcd runs
# it with the lease in its environment; nothing here changes the machine.
case "$reason" in BOUND|RENEW|REBIND|REBOOT)
	printf 'address=%s routers=%s dns=%s lease=%s\n' "$new_ip_address" "$new_routers" \
		"$new_domain_name_servers" "$new_dhcp_lease_time" >> /tmp/ap-lease/given
	;;
esac
exit 0
