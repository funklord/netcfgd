Link state files copied verbatim from a **running** `systemd-networkd`,
systemd 257 (257.13-1~deb13u1), Debian trixie, in a privileged container --
because networkd drops privileges to `systemd-network` and cannot start inside
a user namespace, which is why this had never been checked before.

Two dummy interfaces, one with a `.network` matching it and one without:

- `configured` -- the one with a `.network`. `ADMIN_STATE=configured`.
- `unmanaged`  -- the one without. `ADMIN_STATE=unmanaged`.
- `pending`    -- a link networkd had seen and not yet decided about. It stayed
  that way for the whole run, so `pending` is not merely a startup flicker.

Kept as files rather than as string literals in the test so that what is being
matched is what networkd really writes, header line and all -- including the
`# This is private data. Do not parse.` that the detector deliberately parses.
