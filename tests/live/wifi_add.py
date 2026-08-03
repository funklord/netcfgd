#!/usr/bin/env python3
"""`ncfg wifi add` against a real terminal.

The second python test here, for the reason the first one exists: what this
checks is invisible to a pipe. A passphrase prompt has exactly one property
worth testing -- that the passphrase does not appear on the terminal -- and a
pipe has no echo to turn off, so a test that drives standard input through one
would pass whether the code cleared `ECHO` or not.

It also checks the other half of that: that the terminal is the way it was
afterwards. `netcfgd_sys::signals` exists because a killed TUI left a shell with
echo off, and a passphrase prompt is the second place in this program that can
do it.

No daemon and no namespace. `wifi add` writes a configuration file and talks to
nothing, which is the point of it -- the machine that needs it has no network.
"""

import os
import pty
import shutil
import subprocess
import sys
import tempfile
import termios
import time

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
NCFG = os.path.join(REPO, "target/debug/ncfg")

PASSPHRASE = "correct horse battery"

failures = 0


def check(label, actual, expected):
    global failures
    if actual == expected:
        print(f"ok   {label}")
    else:
        print(f"FAIL {label}")
        print(f"       expected: {expected!r}")
        print(f"       actual:   {actual!r}")
        failures += 1


def ok(label, condition, detail=""):
    global failures
    if condition:
        print(f"ok   {label}")
        return
    print(f"FAIL {label}")
    if detail:
        print(f"       saw: {detail!r}")
    failures += 1


def skip(why):
    if os.environ.get("NCFG_LIVE"):
        print(f"wifi_add.py: NCFG_LIVE is set but this cannot run: {why}", file=sys.stderr)
        sys.exit(1)
    print(f"wifi_add.py: skipping: {why}")
    sys.exit(0)


if not os.access(NCFG, os.X_OK):
    skip("ncfg is not built")

work = tempfile.mkdtemp(prefix="ncfg-wifi-add-")
try:
    os.makedirs(f"{work}/etc")
    os.makedirs(f"{work}/run")
    with open(f"{work}/etc/netcfgd.conf", "w") as handle:
        handle.write('device wlan0 {\n\twifi { backend = "wpa_supplicant" }\n}\n')
    env = dict(
        os.environ,
        NCFG_CONFIG_DIR=f"{work}/etc",
        NCFG_RUN_DIR=f"{work}/run",
    )

    master, slave = pty.openpty()
    before = termios.tcgetattr(slave)
    ok("echo is on to begin with", before[3] & termios.ECHO)

    proc = subprocess.Popen(
        [NCFG, "wifi", "add", "HomeFiber"],
        env=env,
        stdin=slave,
        stdout=slave,
        stderr=slave,
    )

    # The prompt, then the passphrase. Read what the terminal shows before
    # typing, because after the newline the answer and the report arrive
    # together and there is no way to tell which characters came from where.
    os.set_blocking(master, False)
    seen = ""
    deadline = time.time() + 5
    while "passphrase" not in seen and time.time() < deadline:
        try:
            seen += os.read(master, 4096).decode(errors="replace")
        except BlockingIOError:
            time.sleep(0.02)
    ok("the prompt names the network", "passphrase for `HomeFiber`" in seen, seen)

    # Echo off is asserted on the descriptor as well as by what comes back: a
    # terminal that echoed into a buffer nothing read would look identical.
    during = termios.tcgetattr(slave)
    ok("echo is off while the passphrase is typed", not during[3] & termios.ECHO)

    os.write(master, (PASSPHRASE + "\n").encode())
    after_prompt = ""
    deadline = time.time() + 5
    while proc.poll() is None and time.time() < deadline:
        try:
            after_prompt += os.read(master, 4096).decode(errors="replace")
        except BlockingIOError:
            time.sleep(0.02)
    try:
        after_prompt += os.read(master, 65536).decode(errors="replace")
    except (BlockingIOError, OSError):
        pass

    check("it succeeded", proc.wait(timeout=5), 0)
    ok(
        "the passphrase was never echoed",
        PASSPHRASE not in seen + after_prompt,
        (seen + after_prompt),
    )
    ok(
        "and the terminal is the way it was",
        termios.tcgetattr(slave)[3] & termios.ECHO,
    )

    # The file, and what is and is not in it.
    profile = f"{work}/etc/conf.d/wifi-HomeFiber.conf"
    ok("the block was written", os.path.exists(profile))
    with open(profile) as handle:
        text = handle.read()
    ok("it refers to the secret", '@secret:HomeFiber' in text, text)
    ok("and holds no passphrase", PASSPHRASE not in text, text)

    secret = f"{work}/etc/secrets/HomeFiber"
    check("the passphrase is stored exactly", open(secret).read(), PASSPHRASE)
    check("at mode 0600", oct(os.stat(secret).st_mode & 0o777), "0o600")
    check("in a directory only root can list", oct(os.stat(f"{work}/etc/secrets").st_mode & 0o777), "0o700")

    # And netcfgd can read back what it wrote, which is the whole contract.
    shown = subprocess.run(
        [NCFG, "show"], env=env, capture_output=True, text=True, check=False
    )
    check("the configuration still compiles", shown.returncode, 0)
    ok('the network is in the document', '"id": "HomeFiber"' in shown.stdout)
    ok("and the document holds no passphrase", PASSPHRASE not in shown.stdout)

    # A passphrase is never an argument, and there is no flag that would make it
    # one. `ps` shows an argument to every user on the machine.
    attempt = subprocess.run(
        [NCFG, "wifi", "add", "Other", "--passphrase", PASSPHRASE],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    ok(
        "there is no way to pass a passphrase on the command line",
        attempt.returncode != 0 and "unknown option" in attempt.stderr,
        attempt.stderr,
    )

    os.close(master)
    os.close(slave)
finally:
    shutil.rmtree(work, ignore_errors=True)

print()
if failures:
    print(f"wifi_add.py: {failures} failed")
    sys.exit(1)
print("wifi_add.py: all checks passed")
