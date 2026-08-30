//! Bluetooth devices this machine uses.
//!
//! [0149]: a device is a block like a network -- labelled by a handle the
//! operator chose, carrying the address as a fact. The vocabulary is
//! deliberately the wifi one in different words, so that reading either
//! teaches the other.
//!
//! **No pairing state and no codec.** Whether a device is paired is a fact
//! about the adapter's key store, established interactively, and writing it
//! here would be a second source of truth for something netcfgd does not own.
//! Codecs and volume belong to `bluealsa` and to whatever is playing.
//!
//! [0149]: ../../../doc/decision/0149-a-bluetooth-device-is-a-block-like-a-network.md

use serde::{Deserialize, Serialize};

/// What a Bluetooth device is to this machine.
///
/// A closed set from the start, deliberately: the configuration language is
/// the part that cannot be changed quietly later, and a free-form string would
/// have to keep accepting whatever anybody wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BluetoothProfile {
	/// This machine plays to it: a speaker, headphones.
	A2dpSink,
	/// This machine receives from it: a phone, another computer.
	A2dpSource,
	/// Hands-free: a microphone and an earpiece, which is a different thing to
	/// the audio layer than a sink and so is a different block.
	Hfp,
	/// This machine is a client on the device's network. Produces a `bnep`
	/// interface, which is configured like any other link.
	Pan,
	/// This machine serves a network to the device.
	Nap,
}

impl BluetoothProfile {
	/// The spelling the configuration language uses.
	#[must_use]
	pub fn as_str(self) -> &'static str {
		match self {
			Self::A2dpSink => "a2dp-sink",
			Self::A2dpSource => "a2dp-source",
			Self::Hfp => "hfp",
			Self::Pan => "pan",
			Self::Nap => "nap",
		}
	}

	/// Whether this profile carries audio rather than packets.
	///
	/// What it decides is which backend the device needs: an audio profile
	/// wants `bluealsa` running, and a network one produces a link instead.
	#[must_use]
	pub fn is_audio(self) -> bool {
		matches!(self, Self::A2dpSink | Self::A2dpSource | Self::Hfp)
	}
}

/// One Bluetooth device the configuration describes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BluetoothDevice {
	/// The operator's handle for it: the block's label, the filename, and what
	/// `ncfg` prints. Not the address, so that replacing the hardware does not
	/// mean rewriting whatever refers to it.
	pub id: String,
	/// The address, uppercase and colon-separated, which is the fact.
	pub address: String,
	/// What this machine uses it for.
	pub profile: BluetoothProfile,
	/// Whether to connect it without being asked.
	pub autoconnect: bool,
}
