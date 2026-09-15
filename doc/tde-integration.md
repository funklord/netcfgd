# Making netcfgd native in TDE

**Audience: whoever implements netcfgd's desktop half (M8).** Written
2026-09-15, on being asked how netcfgd could integrate with the Trinity
Desktop Environment -- control centre, tray, panel -- so that it reads as
though the people who wrote KDE had written it.

**Status: TDE's surfaces are measured, netcfgd's are cited.** Everything
below about TDE was read out of a TDE 14.1.6 source tree and a running TDE
desktop on 2026-09-15, and is checkable there. Everything about netcfgd is
quoted from this repository's own `project.md` and `gui/project.md` and is
yours to correct. Where the two are weighed against each other, the
judgement is mine and says so.

---

## 1. The one-line answer

**TDE cannot load netcfgd's Qt Widgets GUI as a control-centre module, a
panel applet or a background service.** Those three are TQt3 shared
libraries loaded into a TQt3 host process, and a Qt6 binary cannot be one
however it is packaged.

But `client/ncfg_client.h` is a C API, and TQt3 C++ links C without
ceremony. So the native route is **a small TQt3 front end over the existing
client library** -- not a port of the GUI, and not a second implementation
of anything netcfgd already knows how to do. The GUI stays exactly as
`gui/project.md` describes it, desktop and Android from one source, and TDE
gets its own thin shell.

That split is what "as if the KDE people wrote it" actually costs. Anything
short of it leaves a Qt6 window that TDE launches but does not contain.

## 2. The four surfaces TDE offers, and what each one is

Measured from `tdebase` 14.1.6. Each is a shared library plus a `.desktop`
file; the differences are the base class, the entry point and where the
file is installed.

### 2.1 Control centre module (KCM)

The thing that appears in TDE Control Center. `kcontrol/nics` is the
smallest complete example in the tree.

    class KCMNic : public TDECModule
    typedef KGenericFactory<KCMNic, TQWidget> KCMNicFactory;
    K_EXPORT_COMPONENT_FACTORY( kcm_nic, KCMNicFactory("kcmnic") )

    tde_add_kpart( kcm_nic AUTOMOC
      SOURCES nic.cpp
      LINK tdeio-shared
      DESTINATION ${PLUGIN_INSTALL_DIR} )

and `nic.desktop`:

    Type=Application
    Exec=tdecmshell nic
    Icon=network
    X-DocPath=kcontrol/nics/index.html
    X-TDE-Library=nic
    X-TDE-FactoryName=nic
    X-TDE-ParentApp=kcontrol
    Categories=Qt;TDE;X-TDE-settings-information;

`Exec=tdecmshell nic` is what makes the module also runnable as a standalone
window, which is how a tray menu's "Configure..." should open it.

### 2.2 Panel applet

Embeds in the kicker panel. `kicker/applets/lockout` is the simplest.

    class Lockout : public KPanelApplet
    extern "C" {
      TDE_EXPORT KPanelApplet* init(TQWidget *parent, const TQString& configFile)
    }

    Type=Plugin
    X-TDE-Library=lockout_panelapplet

### 2.3 System tray icon

Not an applet. A normal TDE application whose main window is a
`KSystemTray`. **tdepowersave is the precedent worth copying**, because it
is a TDE tray application that monitors a daemon and offers actions, which
is structurally the same job:

    class tdepowersave : public KSystemTray, public DCOPObject

Inheriting `DCOPObject` and declaring a `k_dcop:` section is what makes the
tray scriptable from the desktop, and it is cheap. tdepowersave exposes
`lockScreen()`, `do_setScheme(TQString)` and so on that way.

### 2.4 kded background module

A service loaded into TDE's daemon, with no window at all. Right for
watching netcfgd and raising notifications when nobody wants a tray icon.

    Type=Service
    X-TDE-ServiceTypes=KDEDModule
    X-TDE-Library=<name>

installed into `share/services/kded/`.

## 3. The gap this would fill

**TDE ships no network configuration manager.** Measured on a full 14.1.6
install: `tdenetwork` is applications (krdc, kopete and friends), and the
only network entry in the control centre is `kcontrol/nics`, which is
*read-only information* -- a list of interfaces, addresses and masks, with
no way to change anything.

The settings taxonomy already has the slot. Twelve `X-TDE-settings-*`
categories exist, and one of them is **`X-TDE-settings-network`**.

So netcfgd would not be displacing anything or competing with an incumbent.
It would be the first, which is a rare and comfortable position: no
migration story to write and no existing UI whose conventions must be
matched beyond TDE's own.

One naming caution: the existing module's library is `nic` and its factory
`kcmnic`. Do not collide with it. `kcm_netcfgd` / `netcfgd` is free.

## 4. What "seamless" actually consists of

The parts that make something feel native in TDE are mostly not the widget
code. In rough order of how much they matter:

- **Live in the control centre, not in a menu.** A network configuration
  tool that appears under Internet & Network in TDE Control Center reads as
  part of the desktop. The same window launched from the applications menu
  reads as a third-party program, whatever it contains.
- **Use TDE's icon names, not bundled images.** `Icon=network` in the
  desktop file resolves through the active icon theme, so it changes when
  the user changes theme. A bundled PNG does not and is the single most
  visible tell.
- **Put settings in TDE's config system.** `TDEConfig` writes
  `~/.trinity/share/config/`, which is where a TDE user expects to find
  them and what their backup tooling copies.
- **Declare `X-DocPath`** so F1 in the module opens a handbook page in
  KHelpCenter rather than doing nothing.
- **Expose DCOP.** It costs a `k_dcop:` block and makes the thing
  scriptable the way every other TDE component is.
- **Install an i18n catalogue** and call `TDEGlobal::locale()->insertCatalogue()`
  in the factory, as the lockout applet does. Untranslated strings in a
  translated desktop are conspicuous.

## 5. Three shapes, with what each costs

**A. Qt6 GUI only, with a TDE menu entry.** Cheapest. The existing GUI
gets a `.desktop` file in the right category. It will not match TDE's
widget style, will not appear in the control centre, and its tray icon will
be a `QSystemTrayIcon` rather than a `KSystemTray`. Honest, and visibly a
guest.

**B. Thin TQt3 shell over `libncfg_client`, Qt6 GUI retained for depth.**
A `kcm_netcfgd` control module and a `KSystemTray` monitor, both TQt3, both
linking the C client library directly. They cover status, per-interface
state, connect and disconnect, and the tray's context menu. The Qt6 GUI
stays for anything elaborate, launched from the module when wanted. My
recommendation, and section 6 says why.

**C. Full TQt3 reimplementation.** Everything native, nothing shared with
Android, two GUIs to maintain against one daemon. I would not, and
`gui/project.md`'s insistence on one source for desktop and Android is the
reason.

## 6. Why B

The work splits along a line that already exists in netcfgd rather than a
new one. `project.md` records that the daemon's remote path is "an ordinary
unprivileged socket client, not a new authority layer" -- a TDE front end is
exactly another such client, and needs no daemon change at all.

What a TQt3 shell has to do is small because the client library already
does the hard parts: `ncfg_client_status()`, `ncfg_client_plan()`,
`ncfg_client_tiers()` and `ncfg_link_is_wireless()` are the shape of a
status panel and a tray menu almost directly. There is no protocol to
reimplement, no JSON to re-parse, and no risk of the two front ends
disagreeing about what the daemon said, because they would be asking
through the same code.

And it keeps the expensive half -- the configuration editor, the wifi tab,
the Android build -- in one place.

## 7. The privilege question, which is yours and already open

`project.md` records the blocker plainly: what stands between the GUI and a
network manager is "adding a network -- which is a security decision rather
than a UI task, because writing config needs privileges a desktop client
does not have."

Nothing in this report changes that, and TDE does not solve it for you. But
TDE does have the two mechanisms a KCM would reach for, both present on a
stock install:

- **`tdesu`** (`/opt/trinity/bin/tdesu`, with `tdesud` and `tdesu_stub`),
  which is how TDE control modules that need root have always got it.
- **`polkit-agent-tde`**, installed by default on this machine, so a polkit
  policy shipped by netcfgd would get a TDE-native authentication dialog
  rather than a mismatched one.

The second is the one I would look at first, because it keeps the authority
decision in netcfgd's own policy file rather than in "the UI ran something
as root", and because the agent already exists. **Whether netcfgd wants a
polkit dependency at all is a question for whoever owns its dependency
budget** -- `project.md` is emphatic that the core has none, and adapters
carry their own. A TDE front end is an adapter by that rule, so the
dependency would sit in the right place, but that is an inference about
netcfgd's intent and not something I measured.

## 8. What I did not check

- **Whether tdehw is worth using.** TDE has its own hardware layer,
  `TDEHardwareDevices`, and tdepowersave uses it for device events. A
  netcfgd tray might learn about link changes from it rather than by
  polling the daemon. I did not investigate what it reports for network
  interfaces or whether it would be better than asking netcfgd.
- **Whether a KCM can usefully show a plan.** `ncfg plan` is netcfgd's
  distinguishing feature and a control-centre module that showed the
  pending diff before applying would be unlike anything else in TDE. I
  think it is the most interesting thing available here and I have not
  thought about what it looks like.
- **Build integration.** netcfgd builds with Cargo and a Makefile; a TQt3
  component wants TDE's CMake macros (`tde_add_kpart`). Whether that lives
  in this tree, in a `tde/` adapter directory beside `adapter/netcfgd-nm`,
  or in a separate package, I did not consider.
- **Anything about how this looks.** No mockups, no widget layout, no
  judgement about what the module should contain. This is about the
  sockets it plugs into.
