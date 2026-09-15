/*
 * netcfgd's TDE system tray icon.
 *
 * Modelled on tdepowersave, which is TDE's own example of a tray application
 * that watches a daemon and offers actions against it: KSystemTray for the
 * icon, DCOPObject so the desktop can drive it like any other TDE component.
 */
#ifndef NCFG_TDE_TRAY_H
#define NCFG_TDE_TRAY_H

#include <ksystemtray.h>
#include <dcopobject.h>
#include <tqstringlist.h>

class TDEPopupMenu;
class TQTimer;
class ncfg_tde_connection;

class ncfg_tde_tray : public KSystemTray, public DCOPObject
{
	TQ_OBJECT
	K_DCOP

public:
	ncfg_tde_tray( TQWidget *parent = 0, const char *name = 0 );
	~ncfg_tde_tray();

k_dcop:
	//! open the Qt window, as the menu's first item does
	void open_window();
	//! open the text interface in a terminal
	void open_terminal();
	//! open the text interface in a terminal, as root
	void open_terminal_as_root();
	//! switch profile; an empty name stops using one
	bool set_profile( TQString name );

private slots:
	/*
	 * The menu connects to these rather than to the k_dcop methods above.
	 * A k_dcop section is not a slots section -- it is the DCOP interface,
	 * and connecting a menu item straight to one fails at runtime with
	 * "No such slot" while compiling perfectly. Found by running it.
	 */
	void menu_window()        { open_window(); }
	void menu_terminal()      { open_terminal(); }
	void menu_terminal_root() { open_terminal_as_root(); }

	void refresh();
	void rebuild_profiles();
	void profile_chosen( int id );
	void open_control_module();

private:
	ncfg_tde_connection *m_connection;
	TDEPopupMenu        *m_menu;
	TDEPopupMenu        *m_profiles;
	TQTimer             *m_timer;

	int          m_status_id;
	TQStringList m_profile_names;   //!< index matches the menu id offset
	TQString     m_chosen;

	void build_menu();
	//! launch a command in the user's terminal, optionally through tdesu
	void run_in_terminal( const TQString &command, bool as_root );
	//! the terminal TDE is configured to use, konsole when unset
	TQString terminal_application() const;
};

#endif
