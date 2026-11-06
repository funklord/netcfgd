#!/bin/sh
# node_second_user.sh -- another user holds the daemon's events on fuzznet, and a
# third does not (project.md 10.730). fuzznet's own test and 10.729's had one
# account; here a user namespace with subordinate ids gives real uids, judged by
# SO_PEERCRED like any other. `make test` runs it; where a machine has no
# subordinate ids for this user it says so and passes, having looked at nothing.
#
# HOW IT STOPS: the namespace's whole script is under `timeout 60`, the daemon
# under its own `timeout -k 2 30`, each client under `timeout`. The directory is
# mktemp's, checked by shape, removed at the end.
here=$(cd "$(dirname "$0")/.." && pwd)
R=$(mktemp -d /tmp/ncf.XXXXXX) || exit 1
case "$R" in /tmp/ncf.?*) ;; *) echo "node_second_user: odd scratch $R"; exit 1;; esac
trap 'unshare --map-auto --map-root-user rm -rf "$R" 2>/dev/null; rm -rf "$R"' EXIT
if ! unshare --map-auto --map-root-user --net true 2>/dev/null ||
	! command -v setpriv > /dev/null; then
	echo "node_second_user: no subordinate ids here, so one user is all there is: not looked at"
	exit 0
fi
chmod 755 "$R"
cp "$here/netcfgd" "$R/netcfgd"
ln -s netcfgd "$R/ncfg"
mkdir -p "$R/a" "$R/run" "$R/conf"
chmod 700 "$R/a"
printf 'global {\n\tcontrol {\n\t\tobserve = "user:daemon"\n\t}\n}\n' > "$R/conf/netcfgd.conf"
cat > "$R/inside.sh" <<'INSIDE'
R=$1
timeout -k 2 30 "$R/netcfgd" --run-dir "$R/run" --config-dir "$R/conf" --no-apply-on-start \
	--fuzznet-dir "$R/a" --fuzznet-arg --no-log-file > "$R/log" 2>&1 &
pid=$!
n=0
until [ -S "$R/run/fuzznet.sock" ] || [ $n -gt 20 ]; do sleep 0.5; n=$((n + 1)); done
sleep 2
chmod 755 "$R/run"
mv "$R/run/netcfgd.sock" "$R/run/hidden.sock"
as() { # $1 uid, then the command
	u=$1
	shift
	setpriv --reuid="$u" --regid="$u" --clear-groups "$@"
}
as 1 timeout 7 "$R/ncfg" monitor --json --run-dir "$R/run" > "$R/held" 2>&1 &
sleep 1
"$R/ncfg" reload --run-dir "$R/run" > /dev/null 2>&1
as 2 timeout 4 "$R/ncfg" monitor --json --run-dir "$R/run" > "$R/refused" 2>&1
echo $? > "$R/refused.status"
mkdir -p "$R/h1" "$R/h2"
chmod 777 "$R/h1" "$R/h2"
HOME=$R/h1 XDG_RUNTIME_DIR=$R/h1 as 1 timeout 4 "$R/ncfg" hosts --run-dir "$R/run" > "$R/hosts1" 2>&1
echo $? > "$R/hosts1.status"
HOME=$R/h2 XDG_RUNTIME_DIR=$R/h2 as 2 timeout 4 "$R/ncfg" hosts --run-dir "$R/run" > "$R/hosts2" 2>&1
echo $? > "$R/hosts2.status"
wait %2 2>/dev/null
sleep 1
kill -TERM $pid 2>/dev/null
wait $pid 2>/dev/null
# `any` has no read to grant, so with the control socket gone a user is read to.
printf 'global {\n\tcontrol {\n\t\tobserve = "any"\n\t}\n}\n' > "$R/conf/netcfgd.conf"
rm -f "$R/run/hidden.sock"
timeout -k 2 16 "$R/netcfgd" --run-dir "$R/run" --config-dir "$R/conf" --no-apply-on-start \
	--fuzznet-dir "$R/a" --fuzznet-arg --no-log-file > "$R/log2" 2>&1 &
pid=$!
n=0
until [ -S "$R/run/netcfgd.sock" ] || [ $n -gt 20 ]; do sleep 0.5; n=$((n + 1)); done
sleep 2
chmod 755 "$R/run"
mv "$R/run/netcfgd.sock" "$R/run/hidden.sock"
as 2 timeout 8 "$R/ncfg" monitor --json --run-dir "$R/run" > "$R/any" 2>&1 &
sleep 1
"$R/ncfg" reload --run-dir "$R/run" > /dev/null 2>&1
wait $!
kill -TERM $pid 2>/dev/null
wait $pid 2>/dev/null
INSIDE
timeout 60 unshare --map-auto --map-root-user --net sh "$R/inside.sh" "$R"
failed=0
check() { # $1 0 for ok, $2 what
	if [ "$1" -eq 0 ]; then printf '%-72s ok\n' "$2"; else printf '%-72s FAILED\n' "$2"; failed=1; fi
}
grep -q '"event":"reloaded"' "$R/held"
check $? "the user \`observe\` names holds the stream ($(head -c 40 "$R/held"))"
[ "$(cat "$R/refused.status")" != 0 ] && grep -q 'would not hold' "$R/refused"
check $? "another user is refused it ($(head -c 70 "$R/refused"))"
[ "$(cat "$R/hosts1.status")" = 0 ]
check $? "that user reads the estate's hosts from root ($(head -c 50 "$R/hosts1"))"
[ "$(cat "$R/hosts2.status")" != 0 ]
check $? "another user does not ($(head -c 70 "$R/hosts2"))"
grep -q '"event":"reloaded"' "$R/any"
check $? "under \`any\`, with no socket, a user hears it by eventlog ($(head -c 60 "$R/any"))"
[ "$failed" -eq 0 ] && echo "node_second_user: all checks passed"
exit "$failed"
