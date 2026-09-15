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
