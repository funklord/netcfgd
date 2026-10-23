# say-goal.mk -- print the default goal of the makefile this is loaded beside.
#
# Loaded as a SECOND `-f` after a directory's own `Makefile`, so that makefile's
# first target still decides `.DEFAULT_GOAL` and this one only reports it:
#
#     make -C <dir> --no-print-directory -f Makefile -f <this> ncfg-say-goal
#
# Naming the target on the command line is what keeps it side-effect free --
# nothing in the real build runs. `make default-goal` at the root is the gate
# that uses it, and project.md 10.535 is the morning that paid for it.
ncfg-say-goal:
	@echo $(.DEFAULT_GOAL)
