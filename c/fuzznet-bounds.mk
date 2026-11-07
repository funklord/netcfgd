# fuzznet's static tables, as this tree links them. Here because two builds link
# fuzznet, `c/Makefile` for the daemon and `gui/Makefile` for the node riding in
# the phone's app, and a list kept twice drifts.
#
# fuzznet sizes these for a person's thousands of notes and shares, and a mapping
# larger than the machine is refused at exec: `__vm_enough_memory` at 128 MB, a
# segfault before main, and `ncfg` with it, being one program (project.md 10.740).
# They are the services both builds leave out, at fuzznet's own embedded values
# (its sec 922), so a node here gives up nothing it used. `FZND_PULL_TARGETS_MAX`
# and `FZND_SIBLING_TARGETS_MAX` stay at fuzznet's eight: those are the estate's
# rounds, which netcfgd does use. Some reach headers, so whatever is compiled
# against fuzznet takes them too.
FUZZNET_BOUNDS = -DFZN_NOTES_MAX=64u -DFZN_NODE_RECEIVED_MAX=2u -DFZN_NOTES_SHARES_MAX=16u \
		-DFZN_NODE_FILES_SHARES_MAX=16u -DFZND_GROUP_SHARES_MAX=2u \
		-DFZN_GROUP_MEMBERS_MAX=64u -DFZN_GROUP_HOSTS_MAX=128u
