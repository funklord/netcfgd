#include "ncfg_tde_tray.h"
#include "ncfg_tde_connection.h"

#include <tdepopupmenu.h>
#include <tdelocale.h>
#include <tdeconfig.h>
#include <tdeapplication.h>
#include <tdemessagebox.h>
#include <kiconloader.h>
#include <tdeglobal.h>
#include <kprocess.h>
#include <kshell.h>

#include <tqtimer.h>
#include <tqtooltip.h>

/* Menu ids. Profiles start above these and are offset by their list index. */
enum {
	ID_STATUS = 1,
	ID_WINDOW,
	ID_TERMINAL,
	ID_TERMINAL_ROOT,
	ID_CONFIGURE,
	ID_QUIT,
	ID_PROFILE_NONE = 100,
	ID_PROFILE_FIRST = 101
};

/* How often the tray re-asks the daemon. */
static const int REFRESH_INTERVAL_MS = 10000;

ncfg_tde_tray::ncfg_tde_tray( TQWidget *parent, const char *name )
    : KSystemTray(parent, name),
      DCOPObject("netcfgd"),
      m_connection(new ncfg_tde_connection),
      m_profiles(0),
      m_status_id(0)
{
	setPixmap(loadIcon("network"));

	m_menu = contextMenu();
	build_menu();

	m_connection->open();

	m_timer = new TQTimer(this);
	connect(m_timer, TQ_SIGNAL(timeout()), this, TQ_SLOT(refresh()));
	m_timer->start(REFRESH_INTERVAL_MS);

	refresh();
}

ncfg_tde_tray::~ncfg_tde_tray()
{
	delete m_connection;
}

void ncfg_tde_tray::build_menu()
{
	/*
	 * The first item is the state, disabled, exactly as tdepowersave's is:
	 * a tray menu that opens with what the thing is doing reads as native,
	 * and one that opens with a verb does not.
	 */
	m_status_id = m_menu->insertItem(i18n("netcfgd"), ID_STATUS);
	m_menu->setItemEnabled(m_status_id, false);
	m_menu->insertSeparator();

	/*
	 * The profile submenu is the mode switcher, and it is the same one the
	 * Qt tray offers: an exclusive list with "this machine's own
	 * configuration" at the top, because a null selection is the default
	 * rather than a profile named "none".
	 */
	m_profiles = new TDEPopupMenu(m_menu);
	m_menu->insertItem(SmallIconSet("configure"), i18n("&Profile"), m_profiles);
	connect(m_profiles, TQ_SIGNAL(activated(int)), this, TQ_SLOT(profile_chosen(int)));
	m_menu->insertSeparator();

	m_menu->insertItem(SmallIconSet("network"),
	                   i18n("Open netcfgd &Window"), this, TQ_SLOT(menu_window()),
	                   0, ID_WINDOW);
	m_menu->insertItem(SmallIconSet("terminal"),
	                   i18n("Open netcfgd in a &Terminal"), this, TQ_SLOT(menu_terminal()),
	                   0, ID_TERMINAL);
	m_menu->insertItem(SmallIconSet("system-lock-screen"),
	                   i18n("Open netcfgd in a Terminal as &Root..."),
	                   this, TQ_SLOT(menu_terminal_root()), 0, ID_TERMINAL_ROOT);
	m_menu->insertSeparator();

	m_menu->insertItem(SmallIconSet("configure"),
	                   i18n("&Configure netcfgd..."), this, TQ_SLOT(open_control_module()),
	                   0, ID_CONFIGURE);
}

/*
 * The glyph for a state, and a glyph that is certainly there.
 *
 * **A themed icon name is never wrong, only absent**, and the loader
 * substitutes the generic `unknown` picture without telling anybody. The
 * no-daemon rung asked for `network-disconnect`, which is a freedesktop name
 * that no TDE theme carries -- so that rung drew a question mark, and it drew
 * it at exactly the moment an operator was looking: the daemon is restarted by
 * every package upgrade.
 *
 * So the wanted name is probed with `canReturnNull`, which is the only way to
 * find out whether a theme has one, and a name from the same family answers
 * when it does not. The fallback is not a guess either: `connect_no` is in
 * every TDE theme that carries any of these.
 */
static TQPixmap state_glyph(const char *wanted, const char *fallback)
{
	const TQPixmap probe = TDEGlobal::iconLoader()->loadIcon(
	    TQString::fromLatin1(wanted), TDEIcon::Panel, 0, TDEIcon::DefaultState, 0, true);
	return KSystemTray::loadIcon(
	    TQString::fromLatin1(probe.isNull() ? fallback : wanted));
}

void ncfg_tde_tray::refresh()
{
	if (!m_connection->is_open())
		m_connection->open();

	ncfg_tde_connection::reach reach;
	TQString line = m_connection->state_line(reach);
	/*
	 * **A daemon restarted between two ticks, which is what an upgrade is.**
	 * The socket it closed is found out about by the request above failing,
	 * and `is_open()` is false from here on. Reopening and asking once more
	 * costs one connect and saves the ten seconds of "netcfgd is not
	 * reachable" that would otherwise be shown after netcfgd is already back.
	 *
	 * Once, not in a loop: if the second attempt fails too, the daemon really
	 * is not there and saying so is the right answer.
	 */
	if (reach == ncfg_tde_connection::reach_no_daemon && !m_connection->is_open()) {
		if (m_connection->open())
			line = m_connection->state_line(reach);
	}
	m_menu->changeItem(m_status_id, line);
	TQToolTip::remove(this);
	TQToolTip::add(this, line);

	/*
	 * Three rungs, not two, and the icon reports the furthest one actually
	 * reached.
	 *
	 * This used to read `is_open()`, which answers whether the DAEMON is
	 * reachable -- so a machine with no network at all drew the connected
	 * glyph as long as netcfgd was running, which is the one case an
	 * operator looks at a tray to find out about. The rungs are netcfgd's
	 * own and the reasoning is in ncfg_client.h beside `default_route`.
	 *
	 * `connect_creating` for the middle rung because that is what it means:
	 * addressed, or joined, and not yet able to send anything anywhere.
	 */
	const char *glyph = "connect_no";
	switch (reach) {
	case ncfg_tde_connection::reach_routed:    glyph = "connect_established"; break;
	case ncfg_tde_connection::reach_local:     glyph = "connect_creating";    break;
	case ncfg_tde_connection::reach_offline:   glyph = "connect_no";          break;
	/*
	 * **A fault in the tool rather than a report about the network**, which is
	 * why this one is not another `connect_` glyph: netcfgd not answering says
	 * nothing at all about whether this machine can reach anything. It used to
	 * ask for `network-disconnect`, a name from the freedesktop set that no
	 * TDE theme has.
	 */
	case ncfg_tde_connection::reach_no_daemon: glyph = "messagebox_warning";  break;
	}
	setPixmap(state_glyph(glyph, "connect_no"));

	rebuild_profiles();
}

void ncfg_tde_tray::rebuild_profiles()
{
	m_profiles->clear();
	m_profile_names.clear();

	TQStringList names;
	TQString chosen;

	if (!m_connection->profiles(names, chosen)) {
		/* Say why rather than showing an empty menu, which reads as
		 * "this machine has no profiles" and is a different fact. */
		const int id = m_profiles->insertItem(m_connection->error());
		m_profiles->setItemEnabled(id, false);
		return;
	}

	m_chosen = chosen;

	const int none_id = m_profiles->insertItem(
	    i18n("This machine's own configuration"), ID_PROFILE_NONE);
	m_profiles->setItemChecked(none_id, chosen.isEmpty());

	if (names.isEmpty()) {
		m_profiles->insertSeparator();
		const int id = m_profiles->insertItem(i18n("no profiles on this machine"));
		m_profiles->setItemEnabled(id, false);
	}

	for (unsigned i = 0; i < names.count(); i++) {
		const int id = m_profiles->insertItem(names[i], ID_PROFILE_FIRST + i);
		m_profiles->setItemChecked(id, names[i] == chosen);
		m_profile_names.append(names[i]);
	}

	/*
	 * Switching writes configuration, which is the admin tier. Showing the
	 * menu greyed rather than hiding it is the honest form: the operator
	 * can see the machine has profiles and that they may not change them.
	 */
	m_profiles->setEnabled(m_connection->may_admin());
}

void ncfg_tde_tray::profile_chosen( int id )
{
	if (id == ID_PROFILE_NONE) {
		set_profile(TQString::null);
		return;
	}
	const int index = id - ID_PROFILE_FIRST;
	if (index < 0 || index >= (int)m_profile_names.count()) return;
	set_profile(m_profile_names[index]);
}

bool ncfg_tde_tray::set_profile( TQString name )
{
	/*
	 * Asked before anything is written, and this is the menu's stand-in for
	 * `ncfg plan`: the daemon reconciles as soon as the selection changes,
	 * so there is no later step at which somebody gets to look. A profile
	 * switch can take down the link the operator is connected over.
	 */
	const TQString what = name.isEmpty()
	    ? i18n("Stop using a profile, and run this machine's own configuration?")
	    : i18n("Switch to the '%1' profile?").arg(name);

	const int answer = KMessageBox::warningContinueCancel(0,
	    what + i18n("\n\nThe network is reconfigured as soon as this is written. "
	                "Over a remote connection, this can take the link down."),
	    i18n("netcfgd"), KStdGuiItem::cont(), "ncfg_profile_switch");

	if (answer != KMessageBox::Continue) {
		/* Put the ticks back: the menu has not moved, but the next
		 * refresh should not be what corrects it. */
		rebuild_profiles();
		return false;
	}

	if (!m_connection->profile_set(name)) {
		/* The daemon's own words, which name the tier when it refused. */
		KMessageBox::sorry(0, m_connection->error(), i18n("netcfgd"));
		rebuild_profiles();
		return false;
	}

	refresh();
	return true;
}

TQString ncfg_tde_tray::terminal_application() const
{
	/*
	 * Whatever the operator told TDE to use, which is what makes this feel
	 * like part of the desktop rather than a program with an opinion.
	 */
	TDEConfigGroup general(TDEGlobal::config(), "General");
	return general.readEntry("TerminalApplication", TQString::fromLatin1("konsole"));
}

void ncfg_tde_tray::run_in_terminal( const TQString &command, bool as_root )
{
	TDEProcess *process = new TDEProcess;

	*process << KShell::splitArgs(terminal_application()) << TQString::fromLatin1("-e");

	if (as_root) {
		/*
		 * tdesu inside the terminal rather than around it. `-t` keeps it
		 * attached to that terminal, so the password is asked where the
		 * program will run and a text interface stays a text interface.
		 */
		*process << TQString::fromLatin1("tdesu") << TQString::fromLatin1("-t");
	}

	*process << command;

	connect(process, TQ_SIGNAL(processExited(TDEProcess *)),
	        process, TQ_SLOT(deleteLater()));

	if (!process->start(TDEProcess::DontCare)) {
		KMessageBox::sorry(0,
		    i18n("Could not start %1.").arg(terminal_application()),
		    i18n("netcfgd"));
		delete process;
	}
}

void ncfg_tde_tray::open_window()
{
	TDEProcess *process = new TDEProcess;
	*process << TQString::fromLatin1("netcfgd-gui");
	connect(process, TQ_SIGNAL(processExited(TDEProcess *)),
	        process, TQ_SLOT(deleteLater()));
	if (!process->start(TDEProcess::DontCare)) {
		KMessageBox::sorry(0, i18n("Could not start netcfgd-gui."), i18n("netcfgd"));
		delete process;
	}
}

void ncfg_tde_tray::open_terminal()
{
	run_in_terminal(TQString::fromLatin1("netcfgd-tui"), false);
}

void ncfg_tde_tray::open_terminal_as_root()
{
	run_in_terminal(TQString::fromLatin1("netcfgd-tui"), true);
}

void ncfg_tde_tray::open_control_module()
{
	/*
	 * tdecmshell is what makes a control module also a standalone window,
	 * so the tray opens the same thing the control centre contains rather
	 * than a second dialog that happens to look like it.
	 */
	TDEProcess *process = new TDEProcess;
	*process << TQString::fromLatin1("tdecmshell") << TQString::fromLatin1("netcfgd");
	connect(process, TQ_SIGNAL(processExited(TDEProcess *)),
	        process, TQ_SLOT(deleteLater()));
	if (!process->start(TDEProcess::DontCare)) {
		KMessageBox::sorry(0, i18n("Could not open the control module."), i18n("netcfgd"));
		delete process;
	}
}

#include "ncfg_tde_tray.moc"
