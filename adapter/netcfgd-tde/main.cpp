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

	virtual int newInstance()
	{
		if (!m_tray) {
			m_tray = new ncfg_tde_tray;
			m_tray->show();
		}
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
