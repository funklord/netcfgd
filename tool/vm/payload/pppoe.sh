# `tests/live/pppoe-session.sh` in a guest, which is where it can run: /dev/ppp
# is root-only and the rp-pppoe plugin opens it as the plugin loads.
set -u
cd /mnt/repo || { echo "the repository is not mounted"; exit 1; }
export DEBIAN_FRONTEND=noninteractive
apt-get -qq update >/dev/null 2>&1
apt-get -qq -y install ppp pppoe >/dev/null 2>&1 && echo "ppp, pppoe: installed"
NCFG_LIVE=1 sh tests/live/pppoe-session.sh
