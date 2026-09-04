/*
 * main_window.cpp -- the three tabs, and the two things beside them.
 */
#include "main_window.h"

#include "access_view.h"
#include "dns_view.h"
#include "apply_dialog.h"
#include "devices_view.h"
#include "global_view.h"
#include "modems_view.h"
#include "secrets_view.h"
#include "profiles_view.h"
#include "rules_view.h"
#include "bluetooth_view.h"
#include "hooks_view.h"
#include "events_view.h"
#include "ncfg_connection.h"
#include "plan_view.h"
#include "tray.h"
#include "wifi_view.h"

#include <QApplication>
#include <QCloseEvent>
#include <QLabel>
#include <QPushButton>
#include <QStatusBar>
#include <QTabWidget>
#include <QTimer>
#include <QToolBar>
#include <QVBoxLayout>
#include <QWidget>

ncfg_main_window::ncfg_main_window(ncfg_connection *connection, QWidget *parent)
    : QMainWindow(parent), connection(connection)
{
	setWindowTitle(QStringLiteral("netcfgd"));

	auto *central = new QWidget(this);
	auto *layout = new QVBoxLayout(central);

	/* Which machine this is, on screen and not in a menu. A client that can
	 * configure a router across the room must never leave the operator
	 * unsure whose network they are about to change. Above the tabs, so it
	 * is true of every one of them. */
	where = new QLabel(central);
	where->setTextInteractionFlags(Qt::TextSelectableByMouse);
	layout->addWidget(where);

	tabs = new QTabWidget(central);

	/* **Three groups, and the split is the question an operator arrives
	 * with.** Thirteen tabs in one row was the cost of a tab per fundamental
	 * thing, and that rule was right while controls were still missing: one
	 * that is absent cannot be found by anybody, while one in the wrong tab
	 * can. Now that nothing is invisible, the row is a list to read rather
	 * than a place to look.
	 *
	 *   machine        what this machine has, and what it is doing with it
	 *   configuration  what it has been told to do
	 *   changes        what is about to happen, and what already did
	 *
	 * Nested tabs rather than a sidebar, because the second level is where
	 * the tabs already were: an operator who knew where `dns` was still finds
	 * it in two clicks, and nothing had to be renamed. */
	machine = new QTabWidget(tabs);
	configuration = new QTabWidget(tabs);
	changes = new QTabWidget(tabs);

	devices = new ncfg_devices_view(connection, machine);
	wifi = new ncfg_wifi_view(connection, machine);
	modems = new ncfg_modems_view(connection, machine);
	bluetooth = new ncfg_bluetooth_view(connection, machine);
	machine->addTab(devices, QStringLiteral("devices"));
	machine->addTab(wifi, QStringLiteral("wifi"));
	/* Beside wifi: a modem is the other way this machine reaches a network,
	 * and an operator looking for one looks where the radios are. */
	machine->addTab(modems, QStringLiteral("modems"));
	machine->addTab(bluetooth, QStringLiteral("bluetooth"));

	global = new ncfg_global_view(connection, configuration);
	access = new ncfg_access_view(connection, configuration);
	dns = new ncfg_dns_view(connection, configuration);
	profiles = new ncfg_profiles_view(connection, configuration);
	rules = new ncfg_rules_view(connection, configuration);
	hooks = new ncfg_hooks_view(connection, configuration);
	secrets = new ncfg_secrets_view(connection, configuration);
	/* `global` first because it is the frame the rest sit in, and `access`
	 * immediately after it because the two are one subject seen twice:
	 * `global` shows the control tiers read-only and `access` is where they
	 * are edited. Apart, an operator reads a policy on one tab and hunts for
	 * where to change it on another. */
	configuration->addTab(global, QStringLiteral("global"));
	configuration->addTab(access, QStringLiteral("access"));
	/* Early rather than last. It used to be last on the argument that it is
	 * the one tab still useful while every other says no -- which is a reason
	 * to make it *findable*, and burying it at the end of a row of thirteen
	 * was the opposite of that. */
	configuration->addTab(dns, QStringLiteral("dns"));
	configuration->addTab(profiles, QStringLiteral("profiles"));
	configuration->addTab(rules, QStringLiteral("rules"));
	configuration->addTab(hooks, QStringLiteral("hooks"));
	configuration->addTab(secrets, QStringLiteral("secrets"));

	plan = new ncfg_plan_view(connection, changes);
	events = new ncfg_events_view(connection, changes);
	/* The plan before the events: one is what would happen and the other is
	 * what did, and that is the order they are wanted in. */
	changes->addTab(plan, QStringLiteral("plan"));
	changes->addTab(events, QStringLiteral("events"));

	tabs->addTab(machine, QStringLiteral("machine"));
	tabs->addTab(configuration, QStringLiteral("configuration"));
	tabs->addTab(changes, QStringLiteral("changes"));
	layout->addWidget(tabs);

	connect(devices, &ncfg_devices_view::reported, this, &ncfg_main_window::note);
	connect(modems, &ncfg_modems_view::reported, this, &ncfg_main_window::note);
	connect(global, &ncfg_global_view::reported, this, &ncfg_main_window::note);
	connect(secrets, &ncfg_secrets_view::reported, this, &ncfg_main_window::note);
	connect(global, &ncfg_global_view::changed, this, &ncfg_main_window::reload);
	connect(profiles, &ncfg_profiles_view::reported, this, &ncfg_main_window::note);
	connect(rules, &ncfg_rules_view::reported, this, &ncfg_main_window::note);
	connect(bluetooth, &ncfg_bluetooth_view::reported, this, &ncfg_main_window::note);
	connect(hooks, &ncfg_hooks_view::reported, this, &ncfg_main_window::note);
	connect(profiles, &ncfg_profiles_view::changed, this, &ncfg_main_window::reload);
	connect(devices, &ncfg_devices_view::changed, this, &ncfg_main_window::reload);
	connect(wifi, &ncfg_wifi_view::reported, this, &ncfg_main_window::note);
	connect(wifi, &ncfg_wifi_view::changed, this, &ncfg_main_window::reload);
	connect(access, &ncfg_access_view::reported, this, &ncfg_main_window::note);
	connect(access, &ncfg_access_view::changed, this, &ncfg_main_window::reload);
	connect(dns, &ncfg_dns_view::reported, this, &ncfg_main_window::note);
	connect(dns, &ncfg_dns_view::changed, this, &ncfg_main_window::reload);
	connect(plan, &ncfg_plan_view::reported, this, &ncfg_main_window::note);
	connect(events, &ncfg_events_view::reported, this, &ncfg_main_window::note);
	/* Every level, not just the outer one: switching from `rules` to `secrets`
	 * never touches the outer widget, and a pane that refreshed only when the
	 * *group* changed would be stale exactly when somebody went looking at
	 * it. */
	for (QTabWidget *level : { tabs, machine, configuration, changes }) {
		connect(level, &QTabWidget::currentChanged, this, &ncfg_main_window::tab_changed);
	}

	setCentralWidget(central);

	auto *tools = addToolBar(QStringLiteral("main"));
	auto *refresh_button = new QPushButton(QStringLiteral("Refresh"), tools);
	connect(refresh_button, &QPushButton::clicked, this, &ncfg_main_window::refresh);
	tools->addWidget(refresh_button);
	/* The button says "Apply..." with the ellipsis the platform uses for "this
	 * opens something first", because that is the promise: it shows the plan
	 * and applies nothing until somebody has read it. */
	auto *apply_button = new QPushButton(QStringLiteral("Apply..."), tools);
	connect(apply_button, &QPushButton::clicked, this, &ncfg_main_window::open_apply);
	tools->addWidget(apply_button);

	/*
	 * Do not offer what will be refused. gui/project.md sec 4 asks for exactly
	 * this: a connection holding `observe` should not have an apply button
	 * whose first effect is a refusal.
	 *
	 * Asked once, at startup, because it cannot change for a connection -- the
	 * peer credentials are fixed when the socket is opened, and re-asking would
	 * suggest otherwise.
	 *
	 * A daemon that answers nothing leaves the button enabled. That is the safe
	 * direction here and it is worth saying why, because the instinct is the
	 * other one: being refused produces a sentence naming the tier that was
	 * needed, which the window shows, and a disabled button produces silence.
	 * Guessing "not allowed" against an older daemon would make this client
	 * useless on it.
	 */
	const ncfg_tiers_t held = connection->tiers();
	const bool asked = held.observe || held.wifi || held.admin;
	if (asked && !held.admin) {
		apply_button->setEnabled(false);
		apply_button->setToolTip(QStringLiteral(
		    "This connection does not hold the `admin` control tier, so netcfgd "
		    "would refuse an apply from it."));
	}

	/* Long enough that a bring-up settles into one refresh, short enough that
	 * a table is not visibly behind the events list beside it. */
	settle = new QTimer(this);
	settle->setSingleShot(true);
	settle->setInterval(400);
	connect(settle, &QTimer::timeout, this, &ncfg_main_window::refresh);
	connect(events, &ncfg_events_view::moved, this, &ncfg_main_window::moved);

	status = new QLabel(this);
	statusBar()->addWidget(status);

	resize(880, 560);

	where->setText(QStringLiteral("netcfgd at %1").arg(connection->where()));
	devices->refresh();
	plan->refresh();
	/* Subscribed from the start rather than when the tab is first opened: an
	 * event that arrived while somebody was looking at the devices table is
	 * exactly the one they will want to find when they go looking for why it
	 * changed. */
	events->refresh();
	tab_changed();
}

void ncfg_main_window::attach_tray(ncfg_tray *adopted)
{
	tray = adopted;
	connect(tray, &ncfg_tray::window_requested, this, [this]() {
		showNormal();
		raise();
		activateWindow();
	});
	connect(tray, &ncfg_tray::quit_requested, this, []() { QApplication::quit(); });
	/* The tray changed the machine, so the tabs are stale. Same path an event
	 * takes, so there is one answer to "something moved". */
	connect(tray, &ncfg_tray::changed, this, &ncfg_main_window::reload);
}

void ncfg_main_window::closeEvent(QCloseEvent *event)
{
	if (tray && !QApplication::quitOnLastWindowClosed()) {
		hide();
		event->ignore();
		return;
	}
	QMainWindow::closeEvent(event);
}

void ncfg_main_window::refresh()
{
	where->setText(QStringLiteral("netcfgd at %1").arg(connection->where()));

	if (tray) {
		tray->refresh();
	}

	QWidget *current = current_pane();
	if (current == devices) {
		devices->refresh();
	} else if (current == wifi) {
		/* Re-reads the radios and what they are doing. Never scans: a scan
		 * blocks for seconds and a refresh button is not consent to that. */
		wifi->refresh();
	} else if (current == modems) {
		modems->refresh();
	} else if (current == global) {
		global->refresh();
	} else if (current == secrets) {
		secrets->refresh();
	} else if (current == profiles) {
		profiles->refresh();
	} else if (current == rules) {
		rules->refresh();
	} else if (current == bluetooth) {
		bluetooth->refresh();
	} else if (current == hooks) {
		hooks->refresh();
	} else if (current == dns) {
		dns->refresh();
	} else if (current == access) {
		access->refresh();
	} else if (current == plan) {
		plan->refresh();
	} else if (current == events) {
		events->refresh();
	}
}

void ncfg_main_window::reload()
{
	devices->refresh();
	plan->refresh();
	/* **The tray too, which this did not do.** `reload` is the path a
	 * configuration change takes -- the profiles view emits `changed` into it
	 * when an operator switches profile -- and the tray's menu carries a
	 * checkmark saying which profile is in use. Without this the mark stayed on
	 * the old one until something unrelated moved: the daemon's event stream
	 * starts a 400ms settle timer that calls `refresh`, which does rebuild the
	 * tray, so a switch that reconciles something heals itself and a switch
	 * that reconciles nothing does not.
	 *
	 * The other direction was already right: the tray's own `choose_profile`
	 * refreshes itself before emitting `changed`. This is the same value with
	 * two consumers where only one was wired.
	 *
	 * No loop: `ncfg_tray::refresh` rebuilds the menu and emits nothing. */
	if (tray) {
		tray->refresh();
	}
	tab_changed();
}

void ncfg_main_window::open_apply()
{
	ncfg_apply_dialog dialog(connection, this);

	/* Both tables describe the machine before the apply, and a confirm or a
	 * revert changes it again -- so this is connected rather than done once
	 * after exec(), which would leave the window stale for as long as the
	 * dialog stayed open. */
	connect(&dialog, &ncfg_apply_dialog::changed, this, &ncfg_main_window::reload);
	dialog.exec();
}

void ncfg_main_window::note(const QString &summary)
{
	auto *from = qobject_cast<QWidget *>(sender());

	if (!from) {
		return;
	}
	summaries.insert(from, summary);

	/* Only the tab in front of the operator gets the status bar. The events
	 * pane reports on every event that arrives, and without this it would
	 * overwrite the devices count seconds after anybody read it.
	 *
	 * The *leaf*, not the group: comparing against the outer widget would
	 * match nothing at all now, and every pane's summary would be dropped. */
	if (from == current_pane()) {
		status->setText(summary);
	}
}

QWidget *ncfg_main_window::current_pane() const
{
	QWidget *current = tabs->currentWidget();
	/* One level down: an outer tab holds a group and a group draws nothing.
	 * `qobject_cast` rather than assuming, so a future tab that is a pane in
	 * its own right still answers for itself. */
	if (auto *group = qobject_cast<QTabWidget *>(current)) {
		return group->currentWidget();
	}
	return current;
}

void ncfg_main_window::tab_changed()
{
	status->setText(summaries.value(current_pane()));
	/* And ask again for the tab now in front of the operator. Without this a
	 * pane that went stale while another was showing stays stale until the
	 * next event, and "the tab I am looking at is current" is the property
	 * worth having. */
	refresh();
}

void ncfg_main_window::moved()
{
	/* Restarted, not started: a link coming up produces a run of events, and
	 * refreshing per event would make the client's cost scale with the
	 * kernel's chattiness -- which is the reason the daemon's own loop
	 * collapses a burst into one pass. */
	settle->start();
}
