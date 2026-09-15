# netcfgd's TDE front end

A TDE Control Center module and a system tray monitor, both TQt3, both over
the same `client/` library the Qt window uses. Nothing here reimplements the
socket protocol.

    kcm_netcfgd.so        the control centre module
    netcfgd-tde-tray      the tray monitor

## Why TQt3 rather than reusing the Qt window

A control-centre module, a panel applet and a kded service are shared
libraries loaded into a host process that is already running TQt3, and the
factory contract hands back a `TDECModule *`. Two Qt-family toolkits cannot
share one process's event loop, X connection and metaobject system, so the
Qt window cannot be one of these however it is packaged.

The APIs are not the obstacle -- TQt3 is Qt 3 with the types renamed and
reads like Qt Widgets throughout. `doc/tde-integration.md` has the full
reasoning, including the embedding route this deliberately does not take.

## Building

Needs TDE's development packages and TQt3. It is not wired into the
top-level build, because a TDE dependency has no business being mandatory
for a daemon whose core has none:

    cmake -S . -B build -DCMAKE_INSTALL_PREFIX=/opt/trinity
    make -C build
    make -C build install

`NCFG_CLIENT_DIR` points at `client/` by default and can be overridden.

## What the tray does

- **Status**, as the first, disabled menu item, the way tdepowersave's is.
- **Profile**, an exclusive submenu -- the same mode switcher the Qt tray
  offers, with "this machine's own configuration" at the top because a null
  selection is the default rather than a profile named none. Greyed when the
  connection lacks the admin tier, so the operator can see that profiles
  exist and that they may not change them.
- **Open netcfgd Window**, which runs `netcfgd-gui`.
- **Open netcfgd in a Terminal**, which runs `netcfgd-tui` in whatever
  terminal TDE is configured to use.
- **Open netcfgd in a Terminal as Root**, which runs `tdesu -t netcfgd-tui`
  *inside* that terminal rather than around it, so the password is asked
  where the program will run and a text interface stays one.
- **Configure netcfgd**, which opens the control module through
  `tdecmshell` -- the same thing the control centre contains, not a second
  dialog that resembles it.

Switching a profile asks first. The daemon reconciles as soon as the
selection is written, so there is no later step at which somebody gets to
look, and a profile switch can take down the link the operator is connected
over. That confirmation is the menu's stand-in for `ncfg plan`.

## What is tested, and what is not

Built clean, and run against a live daemon on a nested X display: the tray
starts with no failed signal connections, and the module loads under
`tdecmshell` and renders.

**Not exercised:** actually switching a profile, and the three launchers.
Those change the machine or start programs, and neither belonged in an
automated run on somebody's desktop.

Two things were found by running it rather than by building it, and are
worth knowing before editing:

- **`k_dcop:` is not a slots section.** Connecting a menu item straight to
  a `k_dcop` method compiles perfectly and fails at runtime with "No such
  slot". The menu goes through thin private slots that call the DCOP
  methods, which is what tdepowersave does.
- **A staged install is invisible without `XDG_DATA_DIRS`.** `TDEDIRS`
  alone is not enough for `tdecmshell` to find the module: the desktop file
  lives in an XDG applications directory, so that variable has to name the
  staged prefix too, and `tdebuildsycoca --noincremental` has to run after.

## Against R14.2

This builds against TDE 14.1.6, where the process class is `TDEProcess` but
its header is still `kprocess.h`, and the unique-application class is still
`KUniqueApplication`. Upstream master has renamed some of these. Adjust the
includes if building against it.
