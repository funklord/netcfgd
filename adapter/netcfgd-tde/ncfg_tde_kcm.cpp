#include "ncfg_tde_kcm.h"
#include "ncfg_tde_connection.h"

#include <tdeglobal.h>
#include <tdelocale.h>
#include <tdeconfig.h>
#include <tdeaboutdata.h>
#include <tdemessagebox.h>
#include <kgenericfactory.h>
#include <kdialog.h>
#include <kprocess.h>
#include <kshell.h>

#include <tqlayout.h>
#include <tqlabel.h>
#include <tqcombobox.h>
#include <tqpushbutton.h>
#include <tqcheckbox.h>
#include <tqgroupbox.h>

typedef KGenericFactory<ncfg_tde_kcm, TQWidget> ncfg_tde_kcm_factory;
K_EXPORT_COMPONENT_FACTORY( kcm_netcfgd, ncfg_tde_kcm_factory("kcm_netcfgd") )

ncfg_tde_kcm::ncfg_tde_kcm( TQWidget *parent, const char *name, const TQStringList & )
    : TDECModule(ncfg_tde_kcm_factory::instance(), parent, name),
      m_connection(new ncfg_tde_connection)
{
	TDEGlobal::locale()->insertCatalogue("kcm_netcfgd");

	TQVBoxLayout *top = new TQVBoxLayout(this, 0, KDialog::spacingHint());

	m_status = new TQLabel(this);
	top->addWidget(m_status);

	m_tiers = new TQLabel(this);
	top->addWidget(m_tiers);

	/*
	 * The same mode switcher the tray and the Qt window offer, in the form a
	 * settings page uses: a list with an explicit button, rather than an
	 * exclusive menu that acts on the click. A control module that
	 * reconfigured the network as a side effect of moving a combo box would
	 * be unlike every other module in TDE.
	 */
	TQGroupBox *box = new TQGroupBox(1, Qt::Horizontal, i18n("Profile"), this);
	top->addWidget(box);

	m_profile = new TQComboBox(box);
	m_switch = new TQPushButton(i18n("S&witch to This Profile"), box);
	connect(m_switch, TQ_SIGNAL(clicked()), this, TQ_SLOT(apply_profile()));

	TQGroupBox *tools = new TQGroupBox(3, Qt::Horizontal, i18n("Open"), this);
	top->addWidget(tools);

	TQPushButton *window = new TQPushButton(i18n("netcfgd &Window"), tools);
	connect(window, TQ_SIGNAL(clicked()), this, TQ_SLOT(open_window()));

	TQPushButton *terminal = new TQPushButton(i18n("In a &Terminal"), tools);
	connect(terminal, TQ_SIGNAL(clicked()), this, TQ_SLOT(open_terminal()));

	TQPushButton *root = new TQPushButton(i18n("In a Terminal as &Root..."), tools);
	connect(root, TQ_SIGNAL(clicked()), this, TQ_SLOT(open_terminal_as_root()));

	/*
	 * The autostart entry this package ships is conditional on
	 * netcfgdrc:General:Autostart, which is TDE's own mechanism -- the same
	 * shape tdepowersave, korgac and irkick use. Shipping the entry without
	 * somewhere to turn it off would leave a key that can only be edited by
	 * hand, so the checkbox is not a convenience: it is the other half of
	 * the entry.
	 *
	 * Unlike the profile switch above, this follows the module's Apply
	 * button rather than acting immediately. It changes what happens at the
	 * next login and nothing about the running machine, so there is no
	 * reason for it to be the exception.
	 */
	m_autostart = new TQCheckBox(
	    i18n("&Start in the system tray on login"), this);
	top->addWidget(m_autostart);
	connect(m_autostart, TQ_SIGNAL(toggled(bool)), this, TQ_SLOT(setting_changed()));

	top->addStretch(1);

	setAboutData(new TDEAboutData("kcm_netcfgd", I18N_NOOP("netcfgd"), "0.1"));
	load();
}

ncfg_tde_kcm::~ncfg_tde_kcm()
{
	delete m_connection;
}

TQString ncfg_tde_kcm::quickHelp() const
{
	return i18n("<h1>netcfgd</h1> This shows whether the network configuration "
	            "daemon is running, what this account may ask it to do, and which "
	            "profile the machine is using. Configuration itself is edited in "
	            "the netcfgd window or its text interface.");
}

void ncfg_tde_kcm::load()
{
	if (!m_connection->is_open())
		m_connection->open();

	/*
	 * The same line the tray's tooltip carries, so a person who looks in
	 * both places is told one thing. The interface count status_line()
	 * returns says nothing about whether traffic can leave.
	 */
	ncfg_tde_connection::reach reach;
	m_status->setText(m_connection->state_line(reach));

	/*
	 * Three independent grants, not a level, so they are listed rather than
	 * summarised. A module that said "you are an administrator" would be
	 * wrong on a machine that grants admin without wifi.
	 */
	if (m_connection->is_open()) {
		TQStringList held;
		if (m_connection->may_observe()) held.append(i18n("observe"));
		if (m_connection->may_wifi())  held.append(i18n("wifi"));
		if (m_connection->may_admin()) held.append(i18n("admin"));
		m_tiers->setText(held.isEmpty()
		    ? i18n("This account holds none of netcfgd's permissions.")
		    : i18n("This account holds: %1").arg(held.join(", ")));
	} else {
		m_tiers->setText(m_connection->error());
	}

	m_profile->clear();
	TQStringList names;
	TQString chosen;

	if (m_connection->profiles(names, chosen)) {
		m_profile->insertItem(i18n("This machine's own configuration"));
		for (unsigned i = 0; i < names.count(); i++) {
			m_profile->insertItem(names[i]);
			if (names[i] == chosen)
				m_profile->setCurrentItem(i + 1);
		}
	}

	m_profile->setEnabled(m_connection->may_admin());
	m_switch->setEnabled(m_connection->may_admin());

	/*
	 * Default true, matching the condition in the autostart file. The two
	 * defaults have to agree: if they disagree the box shows one thing and
	 * the desktop does another, and nothing would report it.
	 */
	TDEConfig config("netcfgdrc");
	config.setGroup("General");
	m_autostart->setChecked(config.readBoolEntry("Autostart", true));
}

void ncfg_tde_kcm::save()
{
	TDEConfig config("netcfgdrc");
	config.setGroup("General");
	config.writeEntry("Autostart", m_autostart->isChecked());
	config.sync();
}

void ncfg_tde_kcm::setting_changed()
{
	emit changed(true);
}

void ncfg_tde_kcm::apply_profile()
{
	/* Index 0 is "this machine's own configuration", which is an empty name. */
	const TQString name = m_profile->currentItem() == 0
	    ? TQString::null : m_profile->currentText();

	const TQString what = name.isEmpty()
	    ? i18n("Stop using a profile, and run this machine's own configuration?")
	    : i18n("Switch to the '%1' profile?").arg(name);

	if (KMessageBox::warningContinueCancel(this,
	        what + i18n("\n\nThe network is reconfigured as soon as this is written. "
	                    "Over a remote connection, this can take the link down."),
	        i18n("netcfgd")) != KMessageBox::Continue) {
		load();
		return;
	}

	if (!m_connection->profile_set(name))
		KMessageBox::sorry(this, m_connection->error(), i18n("netcfgd"));

	load();
}

void ncfg_tde_kcm::run_in_terminal( const TQString &command, bool as_root )
{
	TDEConfigGroup general(TDEGlobal::config(), "General");
	const TQString term = general.readEntry("TerminalApplication",
	                                        TQString::fromLatin1("konsole"));

	TDEProcess *process = new TDEProcess;
	*process << KShell::splitArgs(term) << TQString::fromLatin1("-e");
	if (as_root)
		*process << TQString::fromLatin1("tdesu") << TQString::fromLatin1("-t");
	*process << command;

	connect(process, TQ_SIGNAL(processExited(TDEProcess *)),
	        process, TQ_SLOT(deleteLater()));

	if (!process->start(TDEProcess::DontCare)) {
		KMessageBox::sorry(this, i18n("Could not start %1.").arg(term), i18n("netcfgd"));
		delete process;
	}
}

void ncfg_tde_kcm::open_window()
{
	TDEProcess *process = new TDEProcess;
	*process << TQString::fromLatin1("netcfgd-gui");
	connect(process, TQ_SIGNAL(processExited(TDEProcess *)),
	        process, TQ_SLOT(deleteLater()));
	if (!process->start(TDEProcess::DontCare)) {
		KMessageBox::sorry(this, i18n("Could not start netcfgd-gui."), i18n("netcfgd"));
		delete process;
	}
}

void ncfg_tde_kcm::open_terminal()
{
	run_in_terminal(TQString::fromLatin1("netcfgd-tui"), false);
}

void ncfg_tde_kcm::open_terminal_as_root()
{
	run_in_terminal(TQString::fromLatin1("netcfgd-tui"), true);
}

#include "ncfg_tde_kcm.moc"
