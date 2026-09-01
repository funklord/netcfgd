/*
 * ncfg_connection.h -- the C client, wrapped for Qt.
 *
 * WHERE THE SEAM IS
 *   gui/project.md sec 3: connection handling, framing, the reader and the
 *   models behind interfaces/wifi/plan are in client/, in C, because a second
 *   frontend would want all of it and none of it is visual. This file is the
 *   thin layer on the Qt side of that seam: it turns the C model structs into
 *   the types a widget can use, and owns nothing else.
 *
 *   If a function here grows logic that is not "call the C layer and convert",
 *   it is on the wrong side and belongs below. The first commit walked the
 *   `status` JSON here, which was exactly that mistake; the models moved down
 *   and this file lost the walking rather than keeping it as a precedent.
 *
 * WHY NOT QLocalSocket
 *   Qt has a perfectly good unix socket class, and using it would mean the
 *   framing, the reader and the request vocabulary living here in C++ -- where
 *   an ncurses client, an Android service or a headless probe could not reach
 *   them. The transport being replaceable later (an encrypted datagram one is
 *   sec 6) is the other half: the swap happens in client/, and nothing in this
 *   directory should notice.
 */
#ifndef NCFG_CONNECTION_H
#define NCFG_CONNECTION_H

#include <QList>
#include <QStringList>
#include <QObject>
#include <QString>

extern "C" {
#include "ncfg_client.h"
}

/* One row of the devices table. Qt types because it is on this side of the
 * seam; the names are netcfgd's own so that a reader of both sees one word per
 * concept. */
struct ncfg_link_row {
	QString name;
	QString kind;
	QString state;
	QString mac;
	QString addresses;
	int     mtu = 0;
	/* Whether the wifi tab should offer this one. Answered below the seam so
	 * that the rule lives with the other models rather than in a table. */
	bool    wireless = false;
	/* Whether a default route in the main table leaves through this link.
	 * The last thing observable without sending a packet, and the reason the
	 * tray can say "connected" rather than "associated". */
	bool    default_route = false;
};

/*
 * One saved wireless network, as the document describes it.
 *
 * Separate from `ncfg_access_point_row`, which is what a scan found: a
 * configured network out of range appears in this list and in no scan, which
 * is exactly the case that had nowhere to be shown.
 */
/*
 * One link-detection script, as netcfgd sees it.
 *
 * `editable` is whether netcfgd would overwrite this file. A shipped example
 * is not edited in place: an edit becomes a copy in /etc of the same name,
 * which shadows it.
 */
struct ncfg_probe_row {
	QString name;
	QString directory;
	QString text;
	bool    editable = false;
};

/*
 * One profile the machine could be switched to.
 *
 * `shipped` says it came from the factory directory rather than /etc. An
 * operator's copy of a shipped profile reads as theirs, because theirs is
 * what layers on top.
 */
struct ncfg_profile_row {
	QString name;
	bool    shipped = false;
};

/*
 * One modem device: what the document asks for, and what is in force.
 *
 * `sim` and `selected` are separate because they answer different questions.
 * The first is the operator's ordered preference and never moves on its own;
 * the second is where netcfgd has got to, which changes when a probe says a
 * source does not work. A view showing only one of them would either not say
 * what was asked for, or describe a machine that is not the machine.
 */
struct ncfg_modem_row {
	QString     device;
	QStringList sim;
	QString     selected;
	QString     apn;
	/* netcfgd has moved the selection and the link has not been cycled yet:
	 * it wants the other SIM rather than being on it. */
	bool        cycle_pending = false;
};

/* One routing rule. `selector` is the matching half as one string: a rule with
 * six of the eight selectors set is unreadable as six columns, most of them
 * empty on every other row. */
struct ncfg_rule_row {
	QString id;
	int     priority = 0;
	QString family;
	QString selector;
	QString action;
	QString table;
};

struct ncfg_bluetooth_row {
	QString id;
	QString address;
	QString profile;
	bool    autoconnect = false;
};

/* One hook, flattened across interfaces: a hook belongs to an interface, but
 * the question is "what runs on this machine, and when". */
struct ncfg_hook_row {
	QString interface;
	QString phase;
	QString path;
	QString run_as;
	int     timeout = 0;
};

/* The host-wide policy: the `global` block, minus the dns half the dns view
 * already owns. Rendered strings rather than typed values, because these have
 * little in common beyond living in one block. */
struct ncfg_globals {
	QString networking;
	QString profile;
	QString hostname;
	QString on_drift;
	int     confirm = 0;
	QString control_observe;
	QString control_wifi;
	QString control_admin;
	bool    remote_observe = false;
	bool    remote_wifi = false;
	bool    remote_admin = false;
};

struct ncfg_saved_network_row {
	QString id;
	QString name;
	QString ssid;
	QString security;
	/* The secret this network refers to, or empty where it needs none. A
	 * reference rather than a presence: the document says what the network
	 * wants, not whether the file is there. */
	QString credential;
	int     priority = 0;
	bool    autoconnect = false;
	bool    hidden = false;
};

/*
 * How name resolution is configured, and whether it is in effect.
 *
 * `mode` is "none" unless a document says otherwise, and "none" means netcfgd
 * does not touch resolution -- a correct default that is invisible until a
 * screen shows it.
 */
struct ncfg_dns_row {
	QString     mode;
	QStringList servers;
	QStringList search;
	bool        managing = false;

	/* One sentence for a screen, composed here so the tray and any pane
	 * cannot drift into two descriptions of one setting. */
	QString summary() const;
};

/*
 * One action of a plan, with its reason attached and not beside it.
 *
 * `field`, `desired` and `observed` are in the same struct as `op` because
 * project.md constraint 7 is that netcfgd is not a black box: a screen that
 * could hold an action without its reason would eventually show one. Keeping
 * them together means the only way to draw an action is to have the reason in
 * hand.
 */
struct ncfg_action_row {
	qlonglong id = 0;
	QString   op;
	QString   interface;
	QString   field;
	QString   desired;
	QString   observed;
	bool      reversible = true;
};

/* A warning, a refusal or a stranded credential. One shape for three lists
 * because they are one thing to the reader -- something the operator has to
 * know -- differing only in how hard they stop the apply, which is the list a
 * row is in rather than a field on it. */
struct ncfg_note_row {
	QString message;
	QString interface;
	QString detail;
	/* Two remedies, because they are two answers: `remedy` is the config
	 * change that makes the situation not arise, `consent` the flag that
	 * proceeds anyway. Shown in that order for the reason `ncfg` prints them
	 * in it -- a flag offered first reads as the fix. */
	QString remedy;
	QString consent;
	/* What the refused action would have been. Empty for a warning and for a
	 * stranded credential, neither of which is a dropped action. */
	QString field;
	QString desired;
	QString observed;
};

struct ncfg_plan_data {
	QList<ncfg_action_row> actions;
	QList<ncfg_note_row>   warnings;
	QList<ncfg_note_row>   refusals;
	QList<ncfg_note_row>   stranded;

	/* A plan with a refusal in it is a plan that will not run. The screen
	 * asks this rather than counting the list itself, so that "is this a
	 * stop" has one answer in one place. */
	bool blocked() const { return !refusals.isEmpty(); }
};

/* One line of what an apply did. `outcome` is the daemon's own word -- "done",
 * "failed", "skipped" -- because a client that renamed them would make two
 * vocabularies for one thing. */
struct ncfg_record_row {
	qlonglong id = 0;
	QString   op;
	QString   interface;
	QString   outcome;
	QString   detail;
};

/*
 * One access point a scan found.
 *
 * `display` is what a row shows and is built below the seam's rules rather than
 * by the table: a network whose SSID is not valid UTF-8 has no text name at all,
 * and one that is hidden has a name that is genuinely empty. Those are different
 * networks and a table that printed both as blank would merge them, so the
 * distinction is resolved once, here, into something a cell can hold.
 *
 * `configured` is the network id and empty means the configuration has no
 * `network` block for it. That is the difference between an entry this client
 * can join and one that needs a config file written first (0013, 0069) -- shown
 * rather than discovered by pressing a button and being refused.
 */
/* One radio, as the daemon reports it. */
struct ncfg_radio_row {
	QString name;
	bool    activated = false;
	bool    supplicant = false;

	/* The sentence a view shows, so that the three clients say the same
	 * thing about the same condition -- the reason `display` exists on a
	 * scan row rather than being formatted per widget. */
	QString state() const
	{
		if (activated) {
			return supplicant ? QStringLiteral("netcfgd's")
			          : QStringLiteral("netcfgd's, but no supplicant is answering");
		}
		return supplicant
		    ? QStringLiteral("another manager's -- stop it before activating this radio")
		    : QStringLiteral("not activated");
	}
};

struct ncfg_access_point_row {
	QString bssid;
	QString ssid; /* hex, the canonical name */
	QString display;
	QString configured;
	int     frequency = 0;
	int     signal = 0;
	bool    secured = false;
	/* The credential is 802.1X rather than a passphrase. Decides which
	 * fields the add dialog shows, so that a corporate network is not met
	 * with a box asking for a password it does not have. */
	bool    enterprise = false;

	bool joinable() const { return !configured.isEmpty(); }
};

/* What a radio is doing. `state` is the supplicant's own word, kept rather than
 * translated so that this window and every other tool on the machine say the
 * same thing about the same condition. */
struct ncfg_wifi_status_row {
	QString interface;
	QString state;
	QString display;
	QString bssid;
	QString network;

	/*
	 * The one line that says what a radio is doing.
	 *
	 * On the struct rather than in a view because two things draw it -- the
	 * wifi tab and the tray -- and a second copy is how three clients came to
	 * spell one access point's name three ways. One spelling, one place.
	 *
	 * An associated radio whose network the document does not name is called
	 * out rather than hidden: after 0015 the supplicant holds no profiles of
	 * its own, so something else put it there, and a client that said nothing
	 * would hide the only sign of it.
	 */
	QString summary() const;
};

/* One event off a monitor stream. `raw` travels with the rest because an event
 * netcfgd grows a field for should not become invisible to a client built
 * before it. */
struct ncfg_event_row {
	QString kind;
	QString interface;
	QString summary;
	QString raw;
};

/* What the operator has agreed to, beyond the plan itself.
 *
 * Two lists and never one switch, because the daemon asks two questions: an
 * operator who accepted a brief outage on one interface has not agreed to leave
 * a private key on another. `ncfg` spells them `--allow-disruption IFACE` and
 * `--strand-credentials DEV`, both repeatable and "deliberately not a blanket
 * --force" -- and a single checkbox marked "override refusals" would be exactly
 * the blanket that wording rules out.
 *
 * Each entry names the one interface or device the operator ticked. */
struct ncfg_consent_rows {
	QStringList disrupt;
	QStringList strand;

	bool isEmpty() const { return disrupt.isEmpty() && strand.isEmpty(); }
};

class ncfg_connection : public QObject {
	Q_OBJECT

public:
	explicit ncfg_connection(QObject *parent = nullptr);
	~ncfg_connection() override;

	/* `socket_path` empty means the default -- $NCFG_RUN_DIR or the
	 * installed location, resolved by the C layer so that this client and
	 * `ncfg` cannot disagree about which daemon they are talking to. */
	bool open(const QString &socket_path, QString *error);
	void close();
	bool is_open() const { return client != nullptr; }

	/* Which machine this is. A client that can configure a router across the
	 * room must never leave the operator unsure whose network it is about to
	 * change (gui/project.md sec 4), so the window shows this. It is also
	 * what a monitor stream is opened against, since that takes a connection
	 * of its own. */
	QString where() const;

	/*
	 * Each of these returns false and fills `error` with the daemon's own
	 * words when the daemon refused, and with the C layer's when it could
	 * not be reached. The two are not distinguished here on purpose: the
	 * caller shows the sentence either way, and a refusal already names the
	 * tier that would have been needed (0013) -- a screen that replaced it
	 * with wording of its own would throw away the one part that says what
	 * to do about it.
	 */
	bool links(QList<ncfg_link_row> *out, QString *error);
	bool plan(ncfg_plan_data *out, QString *error);

	/*
	 * The wireless half, on one named interface.
	 *
	 * A scan blocks for as long as the radio takes to visit its channels,
	 * which on real hardware is seconds. It is called from the pane's own
	 * action rather than from a timer for that reason: a window that scanned
	 * on a refresh tick would freeze on a cadence nobody asked for.
	 *
	 * `wifi_connect` names a network by its id in the document and carries no
	 * credential, which is not this class being careful -- it is the only
	 * shape the socket offers (0013), and the reason no passphrase can leak
	 * through a client. Joining a network the configuration does not describe
	 * is writing a file (0069) and is not available here at all.
	 */
	/*
	 * The 802.1X half of an add, in this layer's own types.
	 *
	 * Every certificate is the **name of a secret the daemon already holds**
	 * and never a path: a path would be an instruction to open a file as
	 * root, which is privileged, and there is no field here one could go in.
	 * Storing one is `ncfg secret set NAME < file` at a terminal -- the C
	 * client has no secret_put call, so this window can name a certificate
	 * and cannot put one there.
	 *
	 * Empty means "not given". `method` and `identity` are the two the daemon
	 * requires.
	 */
	struct eap_request {
		QString method;
		QString identity;
		QString anonymous_identity;
		QString phase2;
		QString ca_cert;
		QString client_cert;
	};

	/*
	 * Add a network, and store its credential through the daemon.
	 *
	 * The only call here that carries a secret, and it carries it one way:
	 * the daemon writes it through the provider and the config keeps an
	 * `@secret:` reference, so nothing reads one back (0029, 0031). Needs
	 * the `wifi` tier, which 0124 moved it to: a request carrying an SSID
	 * and a credential is not what `admin` exists to bound. A refusal names
	 * the tier that would have been needed.
	 *
	 * `ssid` is lowercase hex because an SSID is arbitrary octets --
	 * `ncfg_access_point_row::ssid` is exactly this, so a row from a scan
	 * can be handed straight in.
	 *
	 * `eap` is null for an ordinary network. With one, `proto` must be empty:
	 * it pins the generation protecting a passphrase and an enterprise
	 * network negotiates its own, and the daemon refuses the pair rather
	 * than picking.
	 */
	bool wifi_add(const QString &ssid, const QString &id, const QString &passphrase,
	          const QString &proto, bool hidden, const eap_request *eap,
	          QString *error);

	/*
	 * Store a credential under a name, which is how a certificate gets to
	 * where an `eap` block can refer to it.
	 *
	 * **`admin`, while wifi_add() is `wifi`**, so a window may be able to add
	 * a network and not to do this. The difference is the blast radius of the
	 * name: an add writes a secret it also names and refuses if either the
	 * network file or the secret is already there, and this writes any name
	 * the configuration might refer to. Ask tiers() before offering it --
	 * a refusal after the operator has chosen a file is a refusal that wasted
	 * their time.
	 *
	 * Inbound only. Nothing here reads a secret back (0029, 0031).
	 */
	bool secret_put(const QString &name, const QString &value, bool replace, QString *error);

	/*
	 * The radios this machine has, and what netcfgd is doing about each.
	 *
	 * Three states rather than two, and the third is the one that traps
	 * somebody: not activated with a supplicant answering means another
	 * manager holds the radio -- netcfgd declines those rather than taking
	 * them, so an Activate button on that row would do nothing and say
	 * little. A view showing these should say who to stop.
	 */
	bool radios(QList<ncfg_radio_row> *out, QString *error);

	/* Take a radio on, or hand it back. `wifi` tier: what it writes is a
	 * `device` block, but what crosses is a name and a flag, which can name
	 * no hook, no path and no `run_as`. */
	bool set_radio(const QString &interface, bool activate, QString *error);

	bool wifi_scan(const QString &interface, QList<ncfg_access_point_row> *out, QString *error);
	bool wifi_status(const QString &interface, ncfg_wifi_status_row *out, QString *error);
	bool wifi_connect(const QString &interface, const QString &network, QString *error);
	bool wifi_disconnect(const QString &interface, QString *error);
	bool saved_networks(QList<ncfg_saved_network_row> *out, QString *error);
	bool dns(ncfg_dns_row *out, QString *error);
	/*
	 * Write a configuration drop-in by name.
	 *
	 * Admin, and the daemon refuses text granting more than configuring a
	 * network however this is called. The GUI composes the block rather than
	 * taking one typed in: a text box wired straight to this would be 0117's
	 * remote code execution with a nicer font.
	 */
	bool config_put(const QString &name, const QString &text, bool replace, QString *error);
	/*
	 * Write a link-detection script, through the daemon.
	 *
	 * Needs root on this machine, not merely `admin`: a probe is a program
	 * netcfgd runs as root on an interval. A gui running as an ordinary user
	 * gets a refusal saying so, which is the right answer -- and the reason
	 * this goes over the socket at all is 0127, a client cannot write system
	 * files.
	 */
	bool probe_put(const QString &name, const QString &text, bool replace, QString *error);
	/*
	 * The link-detection scripts, from the daemon.
	 *
	 * Asked rather than read off this machine's disk: a client only ever talks
	 * to netcfgd, and these files belong to the machine netcfgd runs on. A gui
	 * listing its own /etc would show the operator's laptop while configuring
	 * a remote machine.
	 */
	bool probes(QList<ncfg_probe_row> *out, QString *error);
	/*
	 * The profiles, and which one is chosen, from the daemon.
	 *
	 * `chosen` is empty when none is, which is the default and is not a
	 * profile called "none": it means the machine runs its own configuration.
	 *
	 * Asked rather than read off this machine's disk, for the reason `probes`
	 * gives -- a gui listing its own /etc/netcfgd/profile would offer to
	 * switch a remote machine to a profile that machine does not have.
	 */
	bool profiles(QList<ncfg_profile_row> *out, QString *chosen, QString *error);
	/*
	 * The modem devices, their SIM order, and which source is in use.
	 *
	 * From the daemon rather than assembled here, for the reason `probes`
	 * gives and one more: the order is in the document and the choice is
	 * runtime state under /run, so a client joining them would be a second
	 * copy of a rule that belongs to the daemon.
	 */
	bool modems(QList<ncfg_modem_row> *out, QString *error);
	/* The routing rules the configuration declares -- what was asked for,
	 * rather than what the kernel currently has, which is drift's question. */
	bool rules(QList<ncfg_rule_row> *out, QString *error);
	bool bluetooth(QList<ncfg_bluetooth_row> *out, QString *error);
	/* Every hook on every interface, in interface order. */
	bool hooks(QList<ncfg_hook_row> *out, QString *error);
	/* The host-wide policy the configuration declares. */
	bool globals(ncfg_globals *out, QString *error);
	/*
	 * Choose a profile, or stop using one with an empty name. Needs `admin`.
	 *
	 * A verb rather than a write of netcfgd's own filename, so the gui never
	 * spells it. The network is reconfigured as soon as this returns -- the
	 * daemon reconciles a changed configuration on its own -- so ask first.
	 */
	bool profile_set(const QString &name, QString *error);

	/*
	 * Apply, with a confirm window in seconds or 0 for none.
	 *
	 * The window is an argument rather than a policy for the reason the C
	 * header gives: a change can cut off the person making it, and neither
	 * "always arm one" nor "never arm one" is right for every apply. The
	 * screen asks, and passes the answer through.
	 *
	 * `consent` is the same shape of argument and for a stronger version of
	 * the same reason: the plan says what is refused and this says which of
	 * those the person at the screen agreed to, and the two must not be one
	 * value. An empty one is the ordinary apply.
	 */
	bool apply(unsigned confirm_seconds, const ncfg_consent_rows &consent,
	       QList<ncfg_record_row> *out, QString *error);
	/*
	 * What this connection may do, asked once at the handshake.
	 *
	 * Three independent answers rather than a level: netcfgd's tiers are three
	 * group memberships, and a machine may grant `admin` to a group the
	 * operator is in while `wifi` goes to one they are not.
	 *
	 * A daemon that does not answer -- one older than the field -- grants
	 * nothing here, and the caller decides what to make of that. This window
	 * treats "could not tell" as permitted: the daemon refusing produces a
	 * sentence naming the tier that was needed, and a greyed-out button
	 * produces nothing at all.
	 */
	ncfg_tiers_t tiers();

	/* The machine's own commit-confirm window in seconds, or 0 if its
	 * configuration names none. Asked rather than assumed: a client with a
	 * default of its own would disagree with `ncfg apply` on the same machine
	 * about how long an operator has to confirm. */
	unsigned confirm_default();

	bool confirm(QString *error);
	bool revert(QString *error);

private:
	ncfg_client_t *client = nullptr;
	QString        path;
};

#endif /* NCFG_CONNECTION_H */
