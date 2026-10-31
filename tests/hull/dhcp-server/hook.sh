#!/bin/sh
# dhcpcd's hook: what the server gave, for the payload to read. dhcpcd runs
# it with the lease in its environment; nothing here changes the machine.
case "$reason" in BOUND|RENEW|REBIND|REBOOT)
	# The standard options (0303) after the first four, so a pattern on
	# those four still matches.
	printf 'address=%s routers=%s dns=%s lease=%s domain=%s ntp=%s file=%s tftp=%s wpad=%s bootfile=%s\n' \
		"$new_ip_address" "$new_routers" "$new_domain_name_servers" "$new_dhcp_lease_time" \
		"$new_domain_name" "$new_ntp_servers" "$new_filename" "$new_tftp_server_name" \
		"$new_wpad_url" "$new_bootfile_name" >> /tmp/dhcp-server/given
	# The custom options, on a line of their own: empty unless the client
	# was told about them (dhcpcd-options.conf).
	printf 'voip=%s motd=%s mtu2=%s big=%s flag=%s raw=%s one=%s small=%s\n' \
		"$new_tftp_servers" "$new_motd" "$new_mtu2" "$new_big" "$new_flag" "$new_raw" \
		"$new_one" "$new_small" >> /tmp/dhcp-server/custom
	;;
esac
exit 0
