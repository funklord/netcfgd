/*
 * The tray application's entry point.
 *
 * KUniqueApplication rather than TDEApplication: a second tray icon for the
 * same daemon is never wanted, and running the command again should raise what
 * is already there.
 */
#include "ncfg_tde_tray.h"

#include <tdeapplication.h>
#include <tdeaboutdata.h>
#include <tdecmdlineargs.h>
#include <kuniqueapplication.h>
#include <tdelocale.h>

static const char description[] =
    I18N_NOOP("System tray monitor for the netcfgd network configuration daemon");

class ncfg_tde_application : public KUniqueApplication
{
public:
	ncfg_tde_application() : KUniqueApplication(), m_tray(0) {}

	/*
	 * **`show()` every time, not only on the first instance.**
	 *
	 * The comment at the top of this file says running the command again
	 * should raise what is already there, and this did not: with `m_tray`
	 * already set it returned 0 and did nothing at all.
	 *
	 * That is what makes a hidden icon unrecoverable. `KSystemTray` hides on
	 * close rather than quitting, so the process lives on with its icon window
	 * unmapped; `KUniqueApplication` then refuses to start a second instance,
	 * hands the launch to this method over DCOP, and this method ignored it.
	 * From the menu it looks exactly like a program that will not start.
	 *
	 * Reproduced on the reporting machine: the icon window was there, 22x22,
	 * carrying `_KDE_NET_WM_SYSTEM_TRAY_WINDOW_FOR`, unmapped and still a
	 * child of the root window -- never swallowed by the panel, while three
	 * other trays were docked and working. Only a map makes the panel take it,
	 * and only `show()` maps it.
	 */
	virtual int newInstance()
	{
		/*
		 * **A hidden icon is remade, not shown.**
		 *
		 * `show()` is not enough and that was measured rather than assumed.
		 * When the icon is closed the panel reparents its window back to the
		 * root and unmaps it, and the process stays alive -- `KSystemTray`
		 * hides on close rather than quitting. Mapping that same window again
		 * puts a loose 22x22 window at the top-left corner of the screen: the
		 * panel swallows a window when it first asks to dock, and this one has
		 * already asked and been let go.
		 *
		 * Observed on the reporting machine in exactly that state: window
		 * 0x800008, 22x22, carrying `_KDE_NET_WM_SYSTEM_TRAY_WINDOW_FOR`,
		 * `IsUnMapped` at +0+0 as a child of root, while three other trays sat
		 * docked at +3330+1406. Before it was closed the same window was
		 * `IsViewable` inside the panel.
		 *
		 * A new widget asks again, which is the only thing the panel answers.
		 */
		if (m_tray && !m_tray->isVisible()) {
			delete m_tray;
			m_tray = 0;
		}
		if (!m_tray) {
			m_tray = new ncfg_tde_tray;
		}
		m_tray->show();
		return 0;
	}

private:
	ncfg_tde_tray *m_tray;
};

int main( int argc, char **argv )
{
	TDEAboutData about("netcfgd-tde-tray", I18N_NOOP("netcfgd"),
	                   "0.1", description, TDEAboutData::License_GPL_V2);

	TDECmdLineArgs::init(argc, argv, &about);
	KUniqueApplication::addCmdLineOptions();

	if (!KUniqueApplication::start())
		return 0;

	ncfg_tde_application application;
	return application.exec();
}
