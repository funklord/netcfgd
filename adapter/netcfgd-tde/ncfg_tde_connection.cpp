#include "ncfg_tde_connection.h"

extern "C" {
	#include "ncfg_client.h"
}

#include <tdelocale.h>

ncfg_tde_connection::ncfg_tde_connection()
    : m_client(0), m_observe(false), m_wifi(false), m_admin(false)
{
}

ncfg_tde_connection::~ncfg_tde_connection()
{
	close();
}

void ncfg_tde_connection::forget_tiers()
{
	/*
	 * Nothing granted is the safe direction. A front end that could not ask
	 * what it may do should offer less rather than more, which is what
	 * ncfg_client_tiers() itself does on failure.
	 */
	m_observe = false;
	m_wifi = false;
	m_admin = false;
}

bool ncfg_tde_connection::open()
{
	close();

	char err[256];
	err[0] = '\0';

	m_client = ncfg_client_open(ncfg_client_default_socket(), err, sizeof(err));
	if (!m_client) {
		m_error = err[0] ? TQString::fromLocal8Bit(err)
		                 : i18n("could not reach the netcfgd socket");
		forget_tiers();
		return false;
	}

	m_error = TQString::null;
	refresh_tiers();
	return true;
}

void ncfg_tde_connection::close()
{
	if (m_client) {
		ncfg_client_close(m_client);
		m_client = 0;
	}
	forget_tiers();
}

bool ncfg_tde_connection::refresh_tiers()
{
	forget_tiers();
	if (!m_client) return false;

	ncfg_tiers_t tiers;
	char err[256];
	err[0] = '\0';

	if (!ncfg_client_tiers(m_client, &tiers, err, sizeof(err))) {
		m_error = TQString::fromLocal8Bit(err);
		return false;
	}

	m_observe = tiers.observe != 0;
	m_wifi = tiers.wifi != 0;
	m_admin = tiers.admin != 0;
	return true;
}

TQString ncfg_tde_connection::status_line()
{
	if (!m_client) return i18n("netcfgd is not reachable");

	ncfg_links_t links;
	char err[256];
	err[0] = '\0';

	if (!ncfg_client_links(m_client, &links, err, sizeof(err)))
		return i18n("netcfgd: %1").arg(TQString::fromLocal8Bit(err));

	/*
	 * Deliberately a count rather than a verdict. netcfgd's own claim is
	 * that it is not a black box, and a tray that reduced the whole machine
	 * to one adjective would be arguing the opposite. Anything more
	 * detailed than this belongs in a window that has room for the reason.
	 */
	const unsigned long total = (unsigned long)links.count;
	ncfg_links_free(&links);

	return i18n("netcfgd: 1 interface", "netcfgd: %n interfaces", total);
}

bool ncfg_tde_connection::profiles( TQStringList &names, TQString &chosen )
{
	names.clear();
	chosen = TQString::null;

	if (!m_client) {
		m_error = i18n("netcfgd is not reachable");
		return false;
	}

	ncfg_profiles_t profiles;
	char err[256];
	err[0] = '\0';

	if (!ncfg_client_profiles(m_client, &profiles, err, sizeof(err))) {
		m_error = TQString::fromLocal8Bit(err);
		return false;
	}

	for (size_t i = 0; i < profiles.count; i++)
		if (profiles.items[i].name)
			names.append(TQString::fromLocal8Bit(profiles.items[i].name));

	/*
	 * A null chosen is not a profile called "none": it means the machine
	 * runs its own configuration, which is the default rather than a
	 * selection. The menu says so in those words.
	 */
	if (profiles.chosen)
		chosen = TQString::fromLocal8Bit(profiles.chosen);

	ncfg_profiles_free(&profiles);
	return true;
}

bool ncfg_tde_connection::profile_set( const TQString &name )
{
	if (!m_client) {
		m_error = i18n("netcfgd is not reachable");
		return false;
	}

	char err[256];
	err[0] = '\0';

	/*
	 * An empty name is "stop using a profile". The daemon owns where the
	 * selection is written; this never spells the drop-in's name.
	 */
	const TQCString local = name.local8Bit();
	const char *arg = name.isEmpty() ? "" : local.data();

	if (!ncfg_client_profile_set(m_client, arg, err, sizeof(err))) {
		m_error = TQString::fromLocal8Bit(err);
		return false;
	}

	m_error = TQString::null;
	return true;
}

/*
 * The same reading the Qt tray makes, in the same words, deliberately.
 *
 * Two front ends onto one daemon that describe the same radio differently is
 * how an operator ends up with two names for one condition -- the thing
 * ncfg_client.h refuses to do with the supplicant's own vocabulary, for the
 * same reason. Where this composes a line it composes gui/src/tray.cpp's.
 */
TQString ncfg_tde_connection::state_line( reach &out )
{
	out = reach_no_daemon;
	if (!m_client) return i18n("netcfgd is not reachable");

	ncfg_links_t links;
	char err[256];
	err[0] = '\0';

	if (!ncfg_client_links(m_client, &links, err, sizeof(err)))
		return i18n("netcfgd: %1").arg(TQString::fromLocal8Bit(err));

	TQString radio;
	for (size_t i = 0; i < links.count; i++) {
		if (links.items[i].wireless) {
			radio = TQString::fromLocal8Bit(links.items[i].name);
			break;
		}
	}

	if (radio.isEmpty()) {
		/*
		 * A wired-only machine is ordinary, so this is a state and not a
		 * complaint. The addresses are what an operator wants to read.
		 */
		TQStringList addressed;
		bool routed = false;
		for (size_t i = 0; i < links.count; i++) {
			const ncfg_link_t &link = links.items[i];
			const TQString name = TQString::fromLocal8Bit(link.name);
			if (name == TQString::fromLatin1("lo")) continue;
			const TQString addr = TQString::fromLocal8Bit(link.addresses ? link.addresses : "");
			if (!addr.isEmpty())
				addressed.append(TQString::fromLatin1("%1 %2").arg(name).arg(addr));
			/*
			 * Any link with a default route will do. Which one carries the
			 * traffic is the kernel's business and a metric's, and an icon
			 * that picked one would answer a question nobody asked.
			 */
			routed = routed || link.default_route;
		}
		ncfg_links_free(&links);

		out = routed ? reach_routed
		    : (!addressed.isEmpty() ? reach_local : reach_offline);

		TQString line = addressed.isEmpty()
		    ? i18n("no addressed interface")
		    : addressed.join(TQString::fromLatin1(", "));
		if (out == reach_local) {
			/*
			 * Said outright, because this is the state that used to be drawn
			 * as connected: an address with nothing to route through is a
			 * machine that will fail every request and look configured while
			 * it does.
			 */
			line += i18n(" -- no default route");
		}
		return line;
	}

	/* The radio's own row, for the rungs above association. */
	bool addressed = false;
	bool routed = false;
	for (size_t i = 0; i < links.count; i++) {
		if (radio != TQString::fromLocal8Bit(links.items[i].name)) continue;
		addressed = links.items[i].addresses && links.items[i].addresses[0] != '\0';
		routed = links.items[i].default_route;
		break;
	}
	ncfg_links_free(&links);

	ncfg_wifi_status_t status;
	err[0] = '\0';
	if (!ncfg_client_wifi_status(m_client, radio.local8Bit().data(),
	                             &status, err, sizeof(err))) {
		out = reach_offline;
		return TQString::fromLocal8Bit(err);
	}

	const TQString state   = TQString::fromLocal8Bit(status.state ? status.state : "");
	const TQString network = TQString::fromLocal8Bit(status.network ? status.network : "");
	TQString display = TQString::fromLocal8Bit(status.name ? status.name : "");
	if (display.isEmpty())
		display = TQString::fromLocal8Bit(status.ssid ? status.ssid : "");

	TQString line = TQString::fromLatin1("%1: %2").arg(radio).arg(state);
	if (!display.isEmpty())
		line += i18n(" on %1").arg(display);
	if (!display.isEmpty() && network.isEmpty())
		line += i18n(" -- not from any network block");
	else if (!network.isEmpty())
		line += TQString::fromLatin1(" (%1)").arg(network);

	ncfg_wifi_status_free(&status);

	/*
	 * **Association is not connectivity.** A non-empty network means the
	 * supplicant joined something, which is the earliest rung and is true of
	 * a radio that never got a lease.
	 */
	const bool joined = !network.isEmpty() || !display.isEmpty();
	out = routed ? reach_routed
	    : ((joined || addressed) ? reach_local : reach_offline);

	if (out == reach_local)
		line += addressed ? i18n(" -- no default route")
		                  : i18n(" -- joined, no address");

	return line;
}
