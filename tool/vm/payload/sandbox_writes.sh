# `tests/live/sandbox_writes.sh`, in a guest that has systemd.
#
# **This is the script the tier was built for.** On the development machine it
# ends `make live` with a non-zero exit -- "NCFG_LIVE is set but this cannot
# run: no systemd here, so the unit's real sandbox is unchecked" -- because that
# machine runs sysvinit. Its last block asks systemd to impose the unit's own
# properties and reads back whether /etc is writable, which is the one question
# the other blocks cannot ask: they make their own mounts, so they check what
# netcfgd does GIVEN a sandbox rather than what the unit's declaration produces.
# Decision 0176 records that those are different questions, and that the file
# went on passing throughout the period when the shipped pairing granted
# nothing.
#
# `NCFG_LIVE=1` on purpose: it turns the script's own skips into failures, so a
# guest that cannot run it says so instead of reporting a pass over nothing.
#
# The repository is the read-only share, which is enough -- the script computes
# its own `$repo` from `$0` and writes only under TMPDIR.
set -u
echo "systemd:  $(systemctl --version 2>/dev/null | head -1)"
echo "pid1:     $(cat /proc/1/comm)"
echo "run/systemd: $([ -d /run/systemd/system ] && echo present || echo ABSENT)"
echo "systemd-run: $(command -v systemd-run || echo ABSENT)"
echo "ncfg:     $([ -x /mnt/repo/target/debug/ncfg ] && echo present || echo MISSING)"
echo
NCFG_LIVE=1 sh /mnt/repo/tests/live/sandbox_writes.sh
