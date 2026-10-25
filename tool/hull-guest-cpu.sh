#!/bin/sh
# Sample a hull machine's guest-side cpu while a rig run is in flight, so that
# a run which fails says whether the guest was alive.
#
#     sh tool/hull-guest-cpu.sh <machine-name-pattern> <verdict-file>
#
# WHAT IT IS FOR
#   netcfgd's hull rigs end in timing checks, and a timing check that fails
#   cannot say by itself whether the machine was wedged or merely slow. That
#   cost a day once: when the rigs' images became `hull build` ones the guest
#   root became plain 9p, a build path measured 14 times slower, and two roam
#   checks failed on an image whose packages were identical to the working
#   one's. The failure looked like netcfgd's.
#
# IT ASKS hull FOR THE RATE RATHER THAN COMPUTING ONE
#   `hull stats --guest --over S ID` takes two readings S seconds apart on the
#   monotonic clock and prints cpu as a percentage of one cpu. The first
#   version of this file took two one-shot readings and compared them itself,
#   which is that arithmetic reimplemented worse -- untimed, and against a
#   clock that can step. Needs hull `d0582b6` for `--guest`; an older binary
#   says so rather than failing.
#
# WHY GUEST-WIDE CPU IS READ THE OPPOSITE WAY FROM A PROCESS'S
#   A live kernel always accrues busy time, so **a flat guest-wide figure means
#   wedged and a rising one means little**. That is the mirror image of a single
#   process, where rising proves work and flat proves nothing, an idle daemon
#   waiting on a socket being indistinguishable from a stuck one --
#   `tests/live/hwsim.sh` says the same at its own `say_if_busy`, which is the
#   inside-the-guest half of this. The two are complementary in the opposite
#   directions to the obvious one, and reading either the other way round turns
#   a diagnosis into a wrong accusation.
#
# WHAT MAKES IT STOP, since nothing should outlive the run it watches
#   Three bounds, any one of which ends it: the machine leaves `hull ps`, the
#   sample cap is reached, or the caller kills it. It takes no pid and greps no
#   pattern of its own -- `running-code.md` records 38 orphaned watchers on this
#   machine from a `pgrep -f` that matched its own command line, and `hull ps`
#   cannot match this script at all.
#
#   It rewrites the verdict file after every sample, so the file is readable
#   whenever the caller wants it rather than only at exit: a watcher that
#   reports when it finishes has nothing to say when the run it watched was
#   killed, which is the case it exists for.
#
#   **Nothing here fails the caller.** Every unhappy path writes a sentence and
#   exits 0, because a sampler that can fail a rig run is a new way for the rig
#   to go red that has nothing to do with netcfgd.
set -u

pattern=${1:?usage: hull-guest-cpu.sh <machine-pattern> <verdict-file>}
verdict=${2:?usage: hull-guest-cpu.sh <machine-pattern> <verdict-file>}
hull=${HULL:-$HOME/src/hull/build/hull}
window=${HULL_SAMPLE_WINDOW:-2}
idle=${HULL_SAMPLE_IDLE:-18}
# A little longer than the rig's own timeout, so the sampler is never the thing
# that ends first: a watcher expiring before its run makes its silence
# ambiguous.
cap=${HULL_SAMPLE_CAP:-120}

say() { printf '%s\n' "$*" > "$verdict"; }

say "guest cpu: no sample taken yet"
command -v "$hull" >/dev/null 2>&1 || {
	say "guest cpu: $hull is not runnable, so nothing was sampled"
	exit 0
}

# `hull ps` prints a header, so rows start at line 2 and the id is the first
# column.
machine_ids() { "$hull" ps 2>/dev/null | awk 'NR > 1 { print $1 }'; }

id=
waited=0
while [ -z "$id" ]; do
	id=$("$hull" ps 2>/dev/null | awk 'NR > 1 && $0 ~ pat { print $1; exit }' pat="$pattern")
	[ -n "$id" ] && break
	waited=$((waited + 1))
	if [ "$waited" -ge 30 ]; then
		say "guest cpu: no machine matching '$pattern' appeared in \`hull ps\`"
		exit 0
	fi
	sleep 2
done
say "guest cpu: watching $id, no reading yet"

samples=0
while [ "$samples" -lt "$cap" ]; do
	# The machine going is the ordinary end, and it is checked before reading so
	# that a stats call failing against a machine that has already finished is
	# never reported as a machine that would not answer.
	machine_ids | grep -qx "$id" || {
		say "guest cpu: $id finished, which is the ordinary end of this watch"
		exit 0
	}
	# **The padding is part of the format.** hull prints `cpu     3.4 %` with
	# the value in a column, so a pattern written for a single space matches
	# nothing and every reading reads as a refusal -- which is how a sampler
	# invents a wedged machine. Read from the source, not guessed.
	out=$("$hull" stats --guest --over "$window" "$id" 2>&1)
	rate=$(printf '%s\n' "$out" |
		sed -n 's/^cpu[[:space:]]\{1,\}\([0-9][0-9.]*\)[[:space:]]*%$/\1/p')
	case "$rate" in
	'')
		# A refusal and a silence are different things and are said
		# differently. hull refuses `--guest` on an engine with no inside,
		# which is a property of the spec rather than a fault.
		case "$out" in
		*"no view of a machine from inside"*)
			say "guest cpu: $id's engine has no inside, so this says nothing about it"
			exit 0
			;;
		*"is not running"*)
			# **A state read a moment ago is not a state.** The loop asks
			# `hull ps` before reading, so a machine that exits between the
			# two reported "did not answer" -- which is the measured end of
			# the first control run of this file: 27 checks passed and the
			# last line of the verdict accused the guest of silence. The
			# ordinary end has two spellings and this is the second.
			say "guest cpu: $id finished between the listing and the reading, \
which is the ordinary end of this watch"
			exit 0
			;;
		*)
			say "guest cpu: $id did not answer: $(printf '%s' "$out" | head -1)"
			;;
		esac
		;;
	0 | 0.0 | 0.00)
		say "guest cpu: $id looks WEDGED -- no guest busy time at all over \
${window}s, and a live kernel always accrues some"
		;;
	*)
		say "guest cpu: $id is ALIVE -- guest cpu $rate% of one cpu over ${window}s"
		;;
	esac
	samples=$((samples + 1))
	sleep "$idle"
done
say "guest cpu: sample cap of $cap reached while $id was still up"
