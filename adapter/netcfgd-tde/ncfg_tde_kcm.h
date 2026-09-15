/*
 * netcfgd's TDE Control Center module.
 *
 * Deliberately small. The Qt window is where configuration is edited; this is
 * where a TDE user looks first, so it answers "is it running, what is it doing,
 * which profile is in effect" and hands off for anything more.
 */
#ifndef NCFG_TDE_KCM_H
#define NCFG_TDE_KCM_H

#include <tdecmodule.h>

class TQLabel;
class TQComboBox;
class TQPushButton;
class ncfg_tde_connection;

class ncfg_tde_kcm : public TDECModule
{
	TQ_OBJECT

public:
	ncfg_tde_kcm( TQWidget *parent = 0, const char *name = 0,
	              const TQStringList &args = TQStringList() );
	~ncfg_tde_kcm();

	virtual void load();
	virtual TQString quickHelp() const;

private slots:
	void apply_profile();
	void open_window();
	void open_terminal();
	void open_terminal_as_root();

private:
	ncfg_tde_connection *m_connection;
	TQLabel      *m_status;
	TQLabel      *m_tiers;
	TQComboBox   *m_profile;
	TQPushButton *m_switch;

	void run_in_terminal( const TQString &command, bool as_root );
};

#endif
