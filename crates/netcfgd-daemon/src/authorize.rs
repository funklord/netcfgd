//! Deciding whether a caller may do what they asked.
//!
//! One function answers "who may do this?", so there is one place to read and
//! one place a mistake can be. Decision 0013 has the reasoning; this is the
//! part that runs.

use netcfgd_model::{Control, Principal, RemotePolicy, Tier};
use netcfgd_proto::Request;
use netcfgd_sys::peer::{group_id, user_id, Peer};

/// Which tier a request belongs to.
///
/// Exhaustive on purpose. A request added without a tier fails to compile,
/// which is a better reminder than a review checklist -- the failure mode of a
/// permission system is a verb nobody remembered to cover.
#[must_use]
pub(crate) fn tier_of(request: &Request) -> Tier {
	match request {
		// Reading. Hello is here rather than unauthenticated because even
		// knowing which versions a daemon speaks is more than a stranger needs.
		Request::Hello
		| Request::Status
		| Request::Plan
		| Request::Show
		| Request::Explain { .. }
		| Request::Monitor
		// Asking what the radio is doing is reading, and a status display that
		// needs the wifi tier is a status display that ends up being given it.
		| Request::WifiStatus { .. }
		// Listing associated stations is reading too, and the same argument
		// applies twice over: a client list is what a monitoring display is
		// for, and a tier that could change the network to see it would be
		// worse for everyone.
		//
		// It is worth naming what this exposes, because it is not the same
		// kind of reading as the rest of this tier. A station list is other
		// people's hardware addresses and how strong their signal is, which is
		// a proximity sensor for anybody granted `observe`. Under the default
		// policy that is root; a site that opens `observe` to `any` is opening
		// this too, deliberately.
		| Request::ApStations { .. } => Tier::Observe,

		// Scanning is not reading: it transmits probe requests, it interrupts
		// whatever the radio was doing, and it is one of the things design
		// section 13 could not express. Decision 0013 puts it here with the
		// other two.
		//
		// `WifiAdd` is here too, since 0124. It was `admin` because 0013 wrote
		// the wifi tier as "join, leave and scan *known* networks" and adding
		// one is beyond that by definition -- but 0013 named that a gap and
		// said "until that exists, adding a network is admin", waiting on a
		// mechanism that could write a network safely. 0117 built one: a typed
		// request whose privilege is bounded by the shape of the message
		// rather than by the caller's manners. What kept this in `admin`
		// afterwards was the old definition rather than the old danger, so
		// what 0124 changes is the definition.
		//
		// What the tier now grants is exactly one `network` block and one
		// secret at 0600. There is no field here that could name a hook, a
		// path, a `run_as`, an interface, a device or a control policy, and
		// nothing outbound: 0031's bridge runs one way and `GetSecrets`
		// refuses. Adding does not apply -- `Apply` stays `admin` below -- so
		// a wifi-tier caller writes a network and joins it with `WifiConnect`,
		// which was already theirs.
		Request::WifiScan { .. }
		| Request::WifiConnect { .. }
		| Request::WifiDisconnect { .. }
		| Request::WifiAdd { .. } => Tier::Wifi,

		// Everything that changes the machine. Apply is Admin even when the
		// only thing in the plan is a wifi association: a tier that could call
		// Apply could apply any config change at all, which would make the
		// wifi tier Admin wearing a hat.
		// Writing configuration is what `admin` names, and `ConfigPut` writes
		// arbitrary configuration -- which is why the tier is not the whole
		// answer for it. `check_content` runs afterwards and refuses anything
		// in the text granting more than configuring a network, so opening
		// `admin` to a group is survivable rather than equivalent to handing
		// it root.
		Request::Apply { .. }
		| Request::Confirm
		| Request::Revert
		| Request::Reload
		| Request::ConfigPut { .. }
		// Storing a credential is `admin` and not `wifi`, even though
		// `wifi_add` carries one at the wifi tier. The difference is the
		// blast radius of the *name*: `wifi_add` writes a secret it also
		// names, for a network it is creating, and this writes any name the
		// configuration might refer to -- including one a `wireguard` block
		// reads, which 0042 calls the one thing on a machine nobody can get
		// back.
		| Request::SecretPut { .. }
		// Deleting is writing. `SecretDelete` in particular is the one verb
		// here with no way back -- 0042's private key, and no `replace` flag
		// to make somebody say it twice, because a caller asking to delete has
		// already said it once. What guards it is this tier and nothing else.
		| Request::ConfigDelete { .. }
		| Request::SecretDelete { .. } => Tier::Admin,
	}
}

/// Whether a peer satisfies a principal.
///
/// Root satisfies everything. That is not a special case bolted on: a
/// configuration that named a group and thereby locked root out would be
/// unrecoverable without editing the file the daemon is refusing to let you
/// reach.
#[must_use]
pub(crate) fn satisfies(peer: &Peer, principal: &Principal) -> bool {
	if peer.is_root() {
		return true;
	}
	match principal {
		Principal::Root => false,
		Principal::Any => true,
		Principal::User(name) => user_id(name).is_some_and(|uid| uid == peer.uid),
		Principal::Group(name) => group_id(name).is_some_and(|gid| peer.in_group(gid)),
	}
}

/// Why a request was refused, in words the caller can act on.
///
/// A permission error that says only "denied" sends the reader to the source.
/// This one names the tier, what the policy says, and where to change it.
#[must_use]
pub(crate) fn refusal(tier: Tier, principal: &Principal) -> String {
	format!(
		"not permitted: this needs the `{}` tier, which the configuration \
		 opens to `{}`. Change it in the `control` block of netcfgd.conf.",
		tier.name(),
		principal.render()
	)
}

/// Where a connection came from (0128).
///
/// Observed rather than claimed: it is which socket the connection arrived on,
/// so there is no field for a caller to set and nothing for the daemon to
/// evaluate. A `Local` connection is one on the control socket; a `Remote` one
/// is on the socket only `agent/` has a reason to open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Origin {
	/// On this machine, identified by peer credentials.
	Local,
	/// Terminated by `agent/`, which arrived from off the machine.
	Remote,
}

/// Decide for a remote caller: may this tier be reached from off the machine?
///
/// **Peer credentials are not consulted, and that is deliberate.** Every
/// remote caller arrives as the agent, so its uid says who is running the
/// agent rather than who is calling -- checking it would be checking the
/// wrong thing while appearing to check the right one. The agent decides who
/// the caller is; this decides what remote can ever reach, whoever they are.
fn check_remote(remote: &RemotePolicy, request: &Request) -> Result<(), String> {
	let tier = tier_of(request);
	if remote.allows(tier) {
		return Ok(());
	}
	Err(format!(
		"not permitted from off this machine: this needs the `{}` tier, which the \
		 configuration does not open remotely. Change it in the `remote` block of \
		 netcfgd.conf.",
		tier.name()
	))
}

/// Decide, and say why if the answer is no.
///
/// # Errors
///
/// Returns the refusal text, which names the tier, what the policy says, and
/// where to change it.
pub(crate) fn check(
	control: &Control,
	remote: &RemotePolicy,
	origin: Origin,
	peer: &Peer,
	request: &Request,
) -> Result<(), String> {
	if origin == Origin::Remote {
		return check_remote(remote, request);
	}
	let tier = tier_of(request);
	let principal = control.principal(tier);
	if satisfies(peer, principal) {
		Ok(())
	} else {
		Err(refusal(tier, principal))
	}
}

/// The second gate: may this caller send *this content*?
///
/// [`check`] answers whether a caller may make a request of this kind.
/// Configuration is the one payload where that is not enough, because the same
/// request can carry a wifi network or a shell script. So the text is parsed
/// and classified, and a production granting more than configuring a network
/// needs more than the `admin` tier.
///
/// **Root on this machine, and nothing else.** Not the `admin` tier, which a
/// site may have opened to a group -- that is the whole point, since 0127's
/// architecture only survives an open local policy if opening it cannot grant
/// root. And never from off the machine, whatever the remote policy says: a
/// remote caller has no uid the daemon can check, so there is no version of
/// "is this root" to ask, and inventing one would be trusting the agent for
/// the one thing the split exists to avoid.
///
/// # Errors
///
/// Returns a sentence naming the production and what it grants. Both, because
/// "not permitted" sends the reader to the source and the reason is usually
/// something they did not know their configuration could do.
pub(crate) fn check_content(origin: Origin, peer: &Peer, request: &Request) -> Result<(), String> {
	let Request::ConfigPut { text, .. } = request else {
		return Ok(());
	};
	// Unparseable text is not this gate's to refuse: the writer compiles it
	// and reports diagnostics that point at the line. Refusing here would
	// answer a syntax error with a sentence about privilege.
	let Ok(file) = netcfgd_compile::parse::parse(netcfgd_compile::SourceId(0), text) else {
		return Ok(());
	};
	let findings = netcfgd_compile::privilege::findings(&file);
	let Some(first) = findings.first() else {
		return Ok(());
	};
	if origin == Origin::Local && peer.is_root() {
		return Ok(());
	}
	Err(format!(
		"`{}` needs root on this machine: {}. {}",
		first.what,
		first.reason.why(),
		if findings.len() > 1 {
			format!("{} such productions in this configuration.", findings.len())
		} else {
			"Send it as root, or leave it out.".to_owned()
		}
	))
}

/// May this caller do this, all of it?
///
/// The module's opening claim is that one function answers "who may do this?",
/// so there is one place to read and one place a mistake can be. 0127 gave it
/// a second gate and briefly made that untrue -- the caller had to remember to
/// ask both, and forgetting the second one is invisible: every test of
/// [`check_content`] calls it directly and passes whether or not anything in
/// the daemon does.
///
/// So this is the one place, and the daemon calls nothing else.
///
/// # Errors
///
/// Whichever gate refused, with its own sentence.
pub(crate) fn permitted(
	control: &Control,
	remote: &RemotePolicy,
	origin: Origin,
	peer: &Peer,
	request: &Request,
) -> Result<(), String> {
	check(control, remote, origin, peer, request)?;
	check_content(origin, peer, request)
}

/// Every tier this peer satisfies.
///
/// The same question `check` asks per request, asked once for all three. A
/// client is told what it may do rather than finding out by being refused --
/// which is the only way it could have found out before (0092).
///
/// Not "the highest tier": the tiers are three separate group memberships, not
/// a ladder. A machine may grant `admin` to a group somebody is in and `wifi`
/// to one they are not, and reporting a maximum would say they can do something
/// they cannot.
pub(crate) fn granted(
	control: &Control,
	remote: &RemotePolicy,
	origin: Origin,
	peer: &Peer,
) -> Vec<Tier> {
	[Tier::Observe, Tier::Wifi, Tier::Admin]
		.into_iter()
		.filter(|tier| match origin {
			// The same answer `check` gives, reached the same way. 0092 exists
			// because a client that finds out by being refused puts a button on
			// a screen that fails when pressed, and a second implementation of
			// "may I" is how the two come to disagree.
			Origin::Remote => remote.allows(*tier),
			Origin::Local => satisfies(peer, control.principal(*tier)),
		})
		.collect()
}

#[cfg(test)]
mod tests {
	use super::*;

	/// The local path, which is what every test below this was written for.
	///
	/// Wrapped rather than threaded through each call so that a test naming an
	/// origin is a test that is *about* origins -- the ones that are not stay
	/// about what they were about.
	fn check_local(control: &Control, peer: &Peer, request: &Request) -> Result<(), String> {
		check(
			control,
			&RemotePolicy::default(),
			Origin::Local,
			peer,
			request,
		)
	}

	fn granted_local(control: &Control, peer: &Peer) -> Vec<Tier> {
		granted(control, &RemotePolicy::default(), Origin::Local, peer)
	}

	fn peer(uid: u32, gid: u32, groups: &[u32]) -> Peer {
		Peer {
			pid: 1234,
			uid,
			gid,
			groups: groups.to_vec(),
		}
	}

	/// Root satisfies every tier, always. A config that locked root out would
	/// be unrecoverable without editing the file the daemon will not let you
	/// reach.
	#[test]
	fn root_is_never_locked_out() {
		let control = Control {
			observe: Principal::Group("nobody-real".to_owned()),
			wifi: Principal::User("nobody-real".to_owned()),
			admin: Principal::Group("nobody-real".to_owned()),
		};
		let root = peer(0, 0, &[]);
		for request in [Request::Status, Request::Reload] {
			assert!(check_local(&control, &root, &request).is_ok());
		}
	}

	/// The default denies everything to everybody but root, so a machine that
	/// never edits the block behaves exactly as design section 13 describes.
	#[test]
	fn the_default_is_root_only() {
		let control = Control::default();
		let user = peer(1000, 1000, &[]);
		assert!(check_local(&control, &user, &Request::Status).is_err());
		assert!(check_local(&control, &user, &Request::Reload).is_err());
	}

	/// The case the whole design exists for: a user may see the network, may
	/// not reconfigure it.
	#[test]
	fn observe_can_be_opened_without_opening_admin() {
		let control = Control {
			observe: Principal::Any,
			..Control::default()
		};
		let user = peer(1000, 1000, &[]);
		assert!(check_local(&control, &user, &Request::Status).is_ok());
		assert!(check_local(&control, &user, &Request::Plan).is_ok());
		assert!(check_local(&control, &user, &Request::Reload).is_err());
		assert!(check_local(
			&control,
			&user,
			&Request::Apply {
				confirm: None,
				allow_disruption: Vec::new(),
				strand_credentials: Vec::new()
			}
		)
		.is_err());
	}

	fn put(text: &str) -> Request {
		Request::ConfigPut {
			name: "from-a-client".to_owned(),
			text: text.to_owned(),
			replace: false,
		}
	}

	/// Both gates are in the path a request actually takes.
	///
	/// Written after removing the content gate from the daemon and watching
	/// every test still pass: they called `check_content` directly, so they
	/// proved the function right and proved nothing about it being called. A
	/// correct function nobody invokes is the shape this tree keeps finding,
	/// and it is why the daemon now calls one function rather than two.
	#[test]
	fn permitted_asks_both_gates() {
		let member = peer(1000, 1000, &[]);
		let control = Control {
			admin: Principal::Any,
			..Control::default()
		};
		let remote = RemotePolicy::default();
		let hook = put("interface eth0 {\n\tpost_up {\n\t\tid\n\t}\n}\n");

		// The tier gate alone admits it.
		assert!(check(&control, &remote, Origin::Local, &member, &hook).is_ok());
		// The one the daemon calls does not.
		assert!(permitted(&control, &remote, Origin::Local, &member, &hook).is_err());

		// And the tier gate still refuses what it always refused, so this is
		// both gates rather than the second one wearing both hats.
		let closed = Control::default();
		assert!(permitted(&closed, &remote, Origin::Local, &member, &Request::Reload).is_err());
		assert!(permitted(&control, &remote, Origin::Local, &member, &Request::Reload).is_ok());
	}

	/// 0127: opening `admin` to a group does not hand that group root.
	///
	/// The property the whole classification exists for. `admin` is what
	/// writing configuration needs, and a site that opens it -- which is the
	/// stated intent for local -- would be granting root outright if config
	/// text could carry a hook, because a hook with no `run_as` runs as the
	/// daemon's user. So the tier lets the request through and the content
	/// gate stops it.
	#[test]
	fn an_admin_group_member_may_send_config_but_not_a_hook() {
		let member = peer(1000, 1000, &[]);
		let ordinary = put("interface eth0 {\n\tconfig = \"dhcp\"\n}\n");
		let with_hook = put("interface eth0 {\n\tconfig = \"dhcp\"\n\tpost_up {\n\t\tid\n\t}\n}\n");

		// The tier says yes to both: it is the same kind of request.
		let control = Control {
			admin: Principal::Any,
			..Control::default()
		};
		for request in [&ordinary, &with_hook] {
			assert!(
				check(
					&control,
					&RemotePolicy::default(),
					Origin::Local,
					&member,
					request
				)
				.is_ok(),
				"the admin tier should admit the request itself"
			);
		}

		// The content gate is what tells them apart.
		assert!(check_content(Origin::Local, &member, &ordinary).is_ok());
		let refusal = check_content(Origin::Local, &member, &with_hook)
			.expect_err("a hook from a non-root caller must be refused");
		assert!(
			refusal.contains("root") && refusal.contains("shell"),
			"the refusal must name what it grants: {refusal}"
		);
	}

	/// Root on this machine may send it, or the gate would forbid the
	/// configuration rather than bounding who writes it.
	#[test]
	fn root_may_send_a_hook() {
		let with_hook = put("interface eth0 {\n\tpost_up {\n\t\tid\n\t}\n}\n");
		assert!(check_content(Origin::Local, &peer(0, 0, &[]), &with_hook).is_ok());
	}

	/// And never from off the machine, whatever the remote policy says.
	///
	/// A remote caller has no uid the daemon can check, so there is no version
	/// of "is this root" to ask. The peer here *is* root -- `agent/` running
	/// as root is a plausible deployment -- which is exactly the case that
	/// would pass if the check asked about the peer before asking about the
	/// origin.
	#[test]
	fn a_hook_never_arrives_from_off_the_machine() {
		let with_hook = put("interface eth0 {\n\tpost_up {\n\t\tid\n\t}\n}\n");
		assert!(check_content(Origin::Remote, &peer(0, 0, &[]), &with_hook).is_err());
	}

	/// Text that does not parse is not this gate's to refuse.
	///
	/// The writer compiles it and reports diagnostics pointing at the line.
	/// Answering a syntax error with a sentence about privilege would send the
	/// reader looking for a permission problem they do not have.
	#[test]
	fn unparseable_text_is_left_to_the_compiler() {
		assert!(
			check_content(Origin::Local, &peer(1000, 1000, &[]), &put("interface {{{")).is_ok()
		);
	}

	/// 0128: a wide-open local policy does not reach the network.
	///
	/// The property the split exists for, and the one that would be worth
	/// nothing if it held only when local was closed. The holder's intent is
	/// that a distribution could put every user in the `netcfgd` group, so
	/// this sets local to the widest thing expressible -- `any` on all three
	/// tiers -- and asserts that a remote caller still reaches nothing.
	#[test]
	fn an_open_local_policy_opens_nothing_remotely() {
		let control = Control {
			observe: Principal::Any,
			wifi: Principal::Any,
			admin: Principal::Any,
		};
		let remote = RemotePolicy::default();
		let caller = peer(1000, 1000, &[]);

		for request in [Request::Status, Request::Reload] {
			assert!(
				check(&control, &remote, Origin::Local, &caller, &request).is_ok(),
				"local should be wide open here"
			);
			assert!(
				check(&control, &remote, Origin::Remote, &caller, &request).is_err(),
				"{request:?} reached the machine from off it"
			);
		}
	}

	/// And a remote policy opens exactly what it names.
	#[test]
	fn a_remote_policy_opens_the_tiers_it_names_and_no_others() {
		let remote = RemotePolicy {
			observe: true,
			wifi: true,
			admin: false,
		};
		// Local is root-only, so anything that got through did so on the
		// remote policy rather than by falling back to the local one.
		let control = Control::default();
		let caller = peer(1000, 1000, &[]);

		assert!(check(&control, &remote, Origin::Remote, &caller, &Request::Status).is_ok());
		assert!(check(
			&control,
			&remote,
			Origin::Remote,
			&caller,
			&Request::WifiScan {
				interface: "wlan0".to_owned(),
			}
		)
		.is_ok());
		assert!(check(&control, &remote, Origin::Remote, &caller, &Request::Reload).is_err());
	}

	/// Peer credentials are not consulted for a remote caller.
	///
	/// The one that would pass by accident if `check` fell through to the
	/// local path: root satisfies every local principal, so a remote
	/// connection whose peer happens to be root would reach everything if
	/// origin were not decided first. `agent/` running as root is a plausible
	/// deployment, which makes this the case to pin rather than a contrived
	/// one.
	#[test]
	fn a_remote_caller_that_is_root_is_still_bounded_by_the_remote_policy() {
		let remote = RemotePolicy {
			observe: true,
			..RemotePolicy::default()
		};
		let root = peer(0, 0, &[]);

		assert!(check(
			&Control::default(),
			&remote,
			Origin::Remote,
			&root,
			&Request::Status
		)
		.is_ok());
		assert!(
			check(
				&Control::default(),
				&remote,
				Origin::Remote,
				&root,
				&Request::Reload
			)
			.is_err(),
			"root over the remote socket reached admin"
		);
	}

	/// What a remote peer is told it may do is what it may do.
	///
	/// 0092's rule, which the split could have broken quietly: `granted`
	/// answers `hello`, and answering it from the local policy while `check`
	/// answers from the remote one puts buttons on a screen that fail when
	/// pressed.
	#[test]
	fn a_remote_peer_is_told_what_the_remote_policy_allows() {
		let remote = RemotePolicy {
			observe: true,
			wifi: true,
			admin: false,
		};
		let control = Control {
			admin: Principal::Any,
			..Control::default()
		};
		let caller = peer(1000, 1000, &[]);

		let told = granted(&control, &remote, Origin::Remote, &caller);
		assert_eq!(told, vec![Tier::Observe, Tier::Wifi]);
		for tier in [Tier::Observe, Tier::Wifi, Tier::Admin] {
			let request = match tier {
				Tier::Observe => Request::Status,
				Tier::Wifi => Request::WifiScan {
					interface: "wlan0".to_owned(),
				},
				Tier::Admin => Request::Reload,
			};
			assert_eq!(
				told.contains(&tier),
				check(&control, &remote, Origin::Remote, &caller, &request).is_ok(),
				"a remote peer was told the wrong thing about {tier:?}"
			);
		}
	}

	/// 0124: the wifi tier adds a network, and that is the whole of what it
	/// gained.
	///
	/// Stated as a pair, because one half alone would pass for the wrong
	/// reason. Moving `WifiAdd` to `wifi` is only correct if `admin` still
	/// holds everything that changes the machine -- a change that opened the
	/// tier by widening it, rather than by moving one request into it, would
	/// satisfy the first assertion and fail every one below it.
	///
	/// The policy names `any` rather than `group:netcfgd`, which is the shape
	/// `debian/postinst` prints. That is deliberate: resolving a group asks
	/// this machine's `/etc/group`, and on one without a `netcfgd` group --
	/// a CI runner on a clean checkout, which is exactly where this would be
	/// read as evidence -- the member would satisfy nothing and the whole test
	/// would pass for the wrong reason. `any` needs no lookup and cannot.
	/// That groups resolve at all is
	/// [`a_supplementary_group_satisfies_a_group_rule`]'s job, and proving it
	/// twice here would only add the way to be wrong.
	#[test]
	fn the_wifi_tier_adds_a_network_and_nothing_else() {
		let control = Control {
			wifi: Principal::Any,
			..Control::default()
		};
		let member = peer(1000, 1000, &[]);
		let add = Request::WifiAdd {
			ssid: "43616665".to_owned(),
			id: None,
			passphrase: Some("hunter2hunter2".to_owned()),
			proto: None,
			hidden: false,
			priority: None,
			eap: None,
		};

		assert_eq!(tier_of(&add), Tier::Wifi);
		assert!(check_local(&control, &member, &add).is_ok());
		// Joining what it just wrote, which is the point of the change: adding
		// and connecting are one tier, so a new network needs no root shell.
		assert!(check_local(
			&control,
			&member,
			&Request::WifiConnect {
				interface: "wlan0".to_owned(),
				network: "Cafe".to_owned(),
			}
		)
		.is_ok());

		// And nothing else moved.
		for denied in [
			Request::Reload,
			Request::Confirm,
			Request::Revert,
			Request::Apply {
				confirm: None,
				allow_disruption: Vec::new(),
				strand_credentials: Vec::new(),
			},
		] {
			assert!(
				check_local(&control, &member, &denied).is_err(),
				"the wifi tier reached {denied:?}, which is admin's"
			);
		}
	}

	/// Apply is Admin even though a plan may contain nothing but a wifi
	/// association, because a tier that can call Apply can apply anything.
	#[test]
	fn apply_is_admin_whatever_it_would_do() {
		assert_eq!(
			tier_of(&Request::Apply {
				confirm: None,
				allow_disruption: Vec::new(),
				strand_credentials: Vec::new()
			}),
			Tier::Admin
		);
	}

	/// The case decision 0013 exists for, end to end: a laptop user joins
	/// wireless networks and cannot touch anything else. Two lines of config.
	/// What a connection is told it may do is what it may do.
	///
	/// The whole value of answering this in `hello` is that a client stops
	/// having to find out by being refused (0092), so the answer has to agree
	/// with `check` for every tier -- a list that said more would put a button
	/// on a screen that fails when pressed, and one that said less would hide a
	/// thing the operator is allowed to do.
	#[test]
	fn what_a_peer_is_told_it_may_do_is_what_check_allows() {
		let control = Control {
			observe: Principal::Any,
			wifi: Principal::Root,
			admin: Principal::Root,
		};

		for (who, peer) in [
			("an ordinary user", peer(1000, 1000, &[])),
			("root", peer(0, 0, &[])),
		] {
			let told = granted_local(&control, &peer);
			for tier in [Tier::Observe, Tier::Wifi, Tier::Admin] {
				// One request per tier, taken through the same `check` a real
				// request goes through rather than through `satisfies` again --
				// two answers to "may I" is the thing this is here to prevent.
				let request = match tier {
					Tier::Observe => Request::Status,
					Tier::Wifi => Request::WifiScan {
						interface: "wlan0".to_owned(),
					},
					Tier::Admin => Request::Reload,
				};
				assert_eq!(
					told.contains(&tier),
					check_local(&control, &peer, &request).is_ok(),
					"{who} was told the wrong thing about {tier:?}: {told:?}"
				);
			}
		}
	}

	/// The tiers are three memberships, not a ladder.
	///
	/// A machine may grant `admin` to a group somebody is in and `wifi` to one
	/// they are not. Reporting a highest tier, or filling in the ones below it,
	/// would tell them they can do something they cannot.
	#[test]
	fn the_tiers_are_not_a_ladder() {
		let control = Control {
			observe: Principal::Any,
			// Nobody in this test is in a group, so this is the tier that is
			// out of reach while the one "above" it is not.
			wifi: Principal::Group("netdev".to_owned()),
			admin: Principal::Any,
		};
		let told = granted_local(&control, &peer(1000, 1000, &[]));

		assert!(told.contains(&Tier::Observe), "{told:?}");
		assert!(told.contains(&Tier::Admin), "{told:?}");
		assert!(!told.contains(&Tier::Wifi), "{told:?}");
	}

	#[test]
	fn the_desktop_case_works_as_advertised() {
		let control = Control {
			observe: Principal::Any,
			wifi: Principal::Group("netdev".to_owned()),
			admin: Principal::Root,
		};
		// Group 44 stands in for netdev; `satisfies` resolves the name through
		// /etc/group, which a test cannot arrange, so the tier mapping is what
		// is checked here and `satisfies` is covered separately.
		let user = peer(1000, 1000, &[44]);

		assert!(check_local(&control, &user, &Request::Status).is_ok());
		assert_eq!(
			tier_of(&Request::WifiScan {
				interface: "wlan0".to_owned()
			}),
			Tier::Wifi
		);
		assert_eq!(
			tier_of(&Request::WifiConnect {
				interface: "wlan0".to_owned(),
				network: "home".to_owned()
			}),
			Tier::Wifi
		);
		// And the tier that would let them rewrite the network is not open.
		assert!(check_local(&control, &user, &Request::Reload).is_err());
		assert!(check_local(
			&control,
			&user,
			&Request::Apply {
				confirm: None,
				allow_disruption: Vec::new(),
				strand_credentials: Vec::new()
			}
		)
		.is_err());
	}

	/// Asking what the radio is doing is reading. A status display that needs
	/// the wifi tier is one that ends up being given it.
	#[test]
	fn wifi_status_is_only_observe() {
		let control = Control {
			observe: Principal::Any,
			..Control::default()
		};
		let user = peer(1000, 1000, &[]);
		let interface = "wlan0".to_owned();

		assert!(check_local(
			&control,
			&user,
			&Request::WifiStatus {
				interface: interface.clone()
			}
		)
		.is_ok());
		// But scanning transmits, so it is not.
		assert!(check_local(&control, &user, &Request::WifiScan { interface }).is_err());
	}

	/// Supplementary groups count. Checking the primary gid alone would deny
	/// nearly everybody a `group:` rule is meant to allow, while appearing to
	/// work -- the worst kind of security control.
	#[test]
	fn a_supplementary_group_satisfies_a_group_rule() {
		let member = peer(1000, 1000, &[27, 44]);
		assert!(member.in_group(44), "supplementary membership must count");
		assert!(member.in_group(1000), "and so must the primary group");
		assert!(!member.in_group(999));
	}

	/// A refusal names the tier, the policy and where to change it. "Denied"
	/// on its own sends the reader to the source code.
	#[test]
	fn a_refusal_says_what_to_do_about_it() {
		let message = refusal(Tier::Wifi, &Principal::Group("netdev".to_owned()));
		assert!(message.contains("wifi"));
		assert!(message.contains("group:netdev"));
		assert!(message.contains("netcfgd.conf"));
	}
}
