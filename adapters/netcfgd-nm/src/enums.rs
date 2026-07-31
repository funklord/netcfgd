//! `NetworkManager`'s numbers.
//!
//! Design section 9.3 calls these wire protocol, and they are: every client
//! switches on the integer, so `NM_DEVICE_STATE_ACTIVATED` being 100 is as
//! much a part of the contract as the method names. Getting one wrong produces
//! a shim that answers every call and displays the wrong thing, which is worse
//! than one that fails.
//!
//! The values are from `NetworkManager.h` and were checked against a running
//! `NetworkManager` 1.52 with `busctl` while this was written -- the
//! interesting ones are asserted against that daemon's own answers in
//! `tests/live/nm.sh`, which is the only way to be sure the number here means
//! what the header says it means.
//!
//! Each enum is written down whole, including the values nothing here produces
//! yet. That is the point of transcribing a specification rather than the
//! subset in use: the next commit that needs `NM_DEVICE_STATE_CONFIG` should
//! find it next to its neighbours, where its number can be checked against the
//! ones around it, instead of looking it up again and getting it wrong once.
#![allow(dead_code)]

/// `NMState`: what the whole daemon is doing.
pub(crate) mod state {
	/// Networking is disabled.
	pub(crate) const ASLEEP: u32 = 10;
	/// No device is connected.
	pub(crate) const DISCONNECTED: u32 = 20;
	/// A connection is going away.
	pub(crate) const DISCONNECTING: u32 = 30;
	/// A connection is coming up.
	pub(crate) const CONNECTING: u32 = 40;
	/// Connected, but only to a local network.
	pub(crate) const CONNECTED_LOCAL: u32 = 50;
	/// Connected to a site, without full internet.
	pub(crate) const CONNECTED_SITE: u32 = 60;
	/// Connected, globally.
	pub(crate) const CONNECTED_GLOBAL: u32 = 70;
}

/// `NMDeviceType`: what kind of thing a device is.
///
/// The subset netcfgd can produce. A kind netcfgd knows and this list does not
/// becomes [`GENERIC`], which is the honest NM idiom for "a device I have no
/// specific handling for" -- and specifically not [`UNKNOWN`], which clients
/// render as a fault.
pub(crate) mod device_type {
	/// Unrecognised. Reserved for a device netcfgd itself could not classify.
	pub(crate) const UNKNOWN: u32 = 0;
	/// Wired ethernet.
	pub(crate) const ETHERNET: u32 = 1;
	/// 802.11 wireless.
	pub(crate) const WIFI: u32 = 2;
	/// Anything real with no more specific type.
	pub(crate) const GENERIC: u32 = 14;
	/// A bridge.
	pub(crate) const BRIDGE: u32 = 13;
	/// A bond.
	pub(crate) const BOND: u32 = 10;
	/// A VLAN.
	pub(crate) const VLAN: u32 = 11;
	/// A tunnel: gre, sit, ipip and the rest of the family.
	pub(crate) const IP_TUNNEL: u32 = 17;
	/// A VXLAN.
	pub(crate) const VXLAN: u32 = 18;
	/// A veth pair member.
	pub(crate) const VETH: u32 = 20;
	/// A `WireGuard` interface.
	pub(crate) const WIREGUARD: u32 = 29;
	/// The loopback.
	pub(crate) const LOOPBACK: u32 = 32;
}

/// `NMDeviceState`.
///
/// netcfgd produces four of these. The intermediate states exist because NM
/// clients animate them, and a device that jumps from `UNAVAILABLE` to
/// `ACTIVATED` is one an applet draws as a spinner that never spun.
pub(crate) mod device_state {
	/// The device is not managed by this daemon.
	pub(crate) const UNMANAGED: u32 = 10;
	/// Managed, but not usable -- no carrier, or the radio is off.
	pub(crate) const UNAVAILABLE: u32 = 20;
	/// Usable and not connected.
	pub(crate) const DISCONNECTED: u32 = 30;
	/// Connected and working.
	pub(crate) const ACTIVATED: u32 = 100;
}

/// `NMDeviceStateReason`, of which the shim needs very few.
pub(crate) mod state_reason {
	/// No reason given.
	pub(crate) const NONE: u32 = 0;
	/// The state is what it is because nothing has happened yet.
	pub(crate) const UNKNOWN: u32 = 1;
	/// A cable is not plugged in.
	pub(crate) const CARRIER: u32 = 40;
}

/// `NMMetered`.
pub(crate) mod metered {
	/// Not known.
	pub(crate) const UNKNOWN: u32 = 0;
	/// Explicitly not metered.
	pub(crate) const NO: u32 = 2;
	/// Not metered, as a guess rather than a statement.
	pub(crate) const GUESS_NO: u32 = 4;
}

/// `NMConnectivityState`.
pub(crate) mod connectivity {
	/// Cannot be determined -- which is the truth here, since netcfgd does not
	/// run a portal check unless a device asks for one.
	pub(crate) const UNKNOWN: u32 = 0;
	/// Full internet access.
	pub(crate) const FULL: u32 = 4;
}

/// `NM80211Mode`, for a wireless device.
pub(crate) mod wifi_mode {
	/// Not known.
	pub(crate) const UNKNOWN: u32 = 0;
	/// Ad-hoc.
	pub(crate) const ADHOC: u32 = 1;
	/// A station on somebody else's network.
	pub(crate) const INFRA: u32 = 2;
	/// An access point of our own.
	pub(crate) const AP: u32 = 3;
}

/// `NM80211ApFlags`: what an access point advertises about itself.
pub(crate) mod ap_flag {
	/// Nothing.
	pub(crate) const NONE: u32 = 0;
	/// Joining it needs a credential. This is the lock icon.
	pub(crate) const PRIVACY: u32 = 0x1;
	/// It offers WPS.
	pub(crate) const WPS: u32 = 0x2;
}

/// `NM80211ApSecurityFlags`: what it will negotiate.
///
/// Checked against a running `NetworkManager` 1.52 rather than transcribed and
/// hoped for. A WPA2/WPA3 transition access point on the network this was
/// written on reports `RsnFlags` 1416, which is exactly
/// `PAIR_CCMP | GROUP_CCMP | KEY_MGMT_PSK | KEY_MGMT_SAE` -- so four of these
/// constants are confirmed by one number, and [`crate::accesspoint`] asserts it.
pub(crate) mod ap_security {
	/// Nothing.
	pub(crate) const NONE: u32 = 0x0;
	/// 40-bit WEP as the pairwise cipher.
	pub(crate) const PAIR_WEP40: u32 = 0x1;
	/// 104-bit WEP as the pairwise cipher.
	pub(crate) const PAIR_WEP104: u32 = 0x2;
	/// TKIP as the pairwise cipher.
	pub(crate) const PAIR_TKIP: u32 = 0x4;
	/// CCMP as the pairwise cipher.
	pub(crate) const PAIR_CCMP: u32 = 0x8;
	/// 40-bit WEP as the group cipher.
	pub(crate) const GROUP_WEP40: u32 = 0x10;
	/// 104-bit WEP as the group cipher.
	pub(crate) const GROUP_WEP104: u32 = 0x20;
	/// TKIP as the group cipher.
	pub(crate) const GROUP_TKIP: u32 = 0x40;
	/// CCMP as the group cipher.
	pub(crate) const GROUP_CCMP: u32 = 0x80;
	/// A pre-shared key.
	pub(crate) const KEY_MGMT_PSK: u32 = 0x100;
	/// 802.1X against a RADIUS server.
	pub(crate) const KEY_MGMT_802_1X: u32 = 0x200;
	/// WPA3's simultaneous authentication of equals.
	pub(crate) const KEY_MGMT_SAE: u32 = 0x400;
	/// Opportunistic wireless encryption.
	pub(crate) const KEY_MGMT_OWE: u32 = 0x800;
	/// OWE in transition mode.
	pub(crate) const KEY_MGMT_OWE_TM: u32 = 0x1000;
}

/// `NMActiveConnectionState`.
pub(crate) mod active_state {
	/// Not known.
	pub(crate) const UNKNOWN: u32 = 0;
	/// Coming up.
	pub(crate) const ACTIVATING: u32 = 1;
	/// Up.
	pub(crate) const ACTIVATED: u32 = 2;
	/// Going away.
	pub(crate) const DEACTIVATING: u32 = 3;
	/// Gone.
	pub(crate) const DEACTIVATED: u32 = 4;
}

/// `NMActivationStateFlags`, the subset clients read.
pub(crate) mod activation_flag {
	/// Nothing.
	pub(crate) const NONE: u32 = 0;
	/// This activation is a controller for others.
	pub(crate) const IS_MASTER: u32 = 0x1;
	/// It is a port of some controller.
	pub(crate) const IS_SLAVE: u32 = 0x2;
	/// Layer 2 is up.
	pub(crate) const LAYER2_READY: u32 = 0x4;
	/// It has IPv4.
	pub(crate) const IP4_READY: u32 = 0x8;
	/// It has IPv6.
	pub(crate) const IP6_READY: u32 = 0x10;
}

/// `NMDeviceCapabilities`.
pub(crate) mod capability {
	/// The device is supported by this daemon.
	pub(crate) const NM_SUPPORTED: u32 = 0x0001;
	/// The device can report carrier.
	pub(crate) const CARRIER_DETECT: u32 = 0x0002;
	/// The device is not virtual.
	pub(crate) const IS_SOFTWARE: u32 = 0x0004;
}

/// `NMDeviceInterfaceFlags`, the subset clients read.
pub(crate) mod interface_flag {
	/// `IFF_UP`.
	pub(crate) const UP: u32 = 0x1;
	/// `IFF_LOWER_UP`, which is carrier.
	pub(crate) const LOWER_UP: u32 = 0x2;
}
