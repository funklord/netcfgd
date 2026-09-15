/*
 * A TQt3-shaped handle on netcfgd's C client library.
 *
 * Both the tray and the control module need the same four questions answered
 * and the same one written, so they ask through this rather than each calling
 * the C API. Nothing here reimplements the protocol: every method is a thin
 * turn of ncfg_client.h into TQt3 types, which is the whole reason a TDE front
 * end is cheap.
 */
#ifndef NCFG_TDE_CONNECTION_H
#define NCFG_TDE_CONNECTION_H

#include <tqstring.h>
#include <tqstringlist.h>

struct ncfg_client;

class ncfg_tde_connection
{
public:
	ncfg_tde_connection();
	~ncfg_tde_connection();

	//! open the socket; false leaves error() set and every query refusing
	bool open();
	void close();
	bool is_open() const { return m_client != 0; }

	//! the last failure, in the daemon's own words where it gave any
	TQString error() const { return m_error; }

	//! what this connection may do. Three independent grants, not a ladder.
	bool may_observe() const { return m_observe; }
	bool may_wifi() const { return m_wifi; }
	bool may_admin() const { return m_admin; }

	//! one line for the tray tooltip and the module's header
	TQString status_line();

	/*
	 * How far this machine actually got, which is a different question from
	 * whether the daemon answers -- and the one a tray icon is asked.
	 *
	 * The rungs are netcfgd's own, from ncfg_client.h: a link can be up with
	 * no carrier, carry traffic with no address, and hold an address with
	 * nothing to route through, so "connected" is none of up, carrier or a
	 * non-empty addresses. A default route is the last thing observable
	 * without putting a packet on the wire, which makes it the honest
	 * ceiling for an icon.
	 */
	enum reach { reach_no_daemon, reach_offline, reach_local, reach_routed };

	TQString state_line( reach &out );

	//! profiles on this machine, and which is in effect
	bool profiles( TQStringList &names, TQString &chosen );
	//! switch; an empty name stops using a profile altogether
	bool profile_set( const TQString &name );

private:
	ncfg_client *m_client;
	TQString     m_error;
	bool         m_observe;
	bool         m_wifi;
	bool         m_admin;

	void forget_tiers();
	bool refresh_tiers();
};

#endif
