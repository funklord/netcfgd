# Copied from ~/.claude/tool/android.mk -- the source. Keep in sync;
# fix drift the moment you notice it.
# =============================================================================
# android.mk -- the shared Android vocabulary for private projects
#
# Spread verbatim into each project's tool/ from ~/.claude/tool/android.mk,
# the same model as style_gate.py and for the same reason: a copy in the
# repository is reachable by CI, which a file under ~/.claude is not.
#
# harmonization.md settled the names. This file is where they live, so that
# a habit learned in one project is correct in the next:
#
#   make android            debug build, installable on any device
#   make android-aab        the Play bundle; needs a keystore
#   make android-install    install the artifact on the attached device
#   make android-run        install and launch it
#   make android-log        follow this app's log, and only this app's
#   make android-uninstall  remove it
#   make android-check      everything the build needs, checked by name
#   make android-play-check what Play would refuse, read from the bundle
#   make android-screenshots  the store screenshots, from this build
#   make android-store-screenshots  the same, on the shared store emulator
#
# `apk` is deliberately NOT a target name. netcfgd's `apk` is Alpine's
# packaging command, and one word meaning two things across sibling trees is
# how somebody eventually runs the wrong one.
#
#
# INCLUDE THIS AFTER YOUR DEFAULT GOAL, OR SET ONE.
#
# `include` is where make first sees a target, so pulling this fragment in
# ahead of a project's `all` makes android-check the default goal: a plain
# `make` then runs the preflight, fails for want of QT_ANDROID_ROOT, and
# builds nothing. bbq-predictor did this and did not notice for four
# sessions. Either include it below `all`, or say so explicitly:
#
#   .DEFAULT_GOAL := all
#
# The fragment cannot fix this for you -- it has no way to know what your
# default goal is meant to be.
#
# WHAT THE PROJECT SUPPLIES
#   APP_ID              reverse-DNS id; the package and the launcher use it
#   VERSION             the one place a version is stated
#   ANDROID_BUILD_DIR   where the Qt build tree goes
#   ANDROID_ARTIFACT    the path the build rule leaves the APK at
#   android-build       a rule that produces the APK, however this project
#                       builds; qmake and CMake differ and neither belongs here
#
# NOTHING HERE DEFAULTS A VARIABLE TO EMPTY, and that is deliberate.
#
# `X ?=` with nothing after it still DEFINES X, so a project writing its
# own `X ?= value` below the include finds X already set and keeps the
# empty one: no error, and the setting silently does nothing. beerssh met
# it 2026-10-22 with ANDROID_AAB, and seven variables here had the shape.
# An unset variable expands to empty anyway, so the line bought nothing.
# The variables with real defaults still take `?=`; to override one of
# those, set it above the include or with a plain `=`.
#
# WHAT THIS FILE SUPPLIES
#   The variable names, the preflight, the versionCode, the adb plumbing,
#   and the signature check that beerssh learned the hard way.
# =============================================================================

ANDROID_SDK_ROOT ?= $(HOME)/Android/Sdk

# The OLDEST Android the app runs on -- its minSdk, not its target.
#
# It does not set minSdk; Qt does, and this must be kept equal to what Qt
# declares. Read it back from a built package rather than trusting either
# side:
#
#     aapt2 dump badging <apk> | grep minSdkVersion
#
# EXPORTED, because tool/build-openssl-android.sh reads it and gets the
# direction of the risk wrong if it disagrees. A dependency cross-compiled
# for a HIGHER API than the app resolves symbols at build time that are
# absent at run time on the oldest device the app claims to support -- so
# the failure lands on somebody else's old phone, not on the desk. That
# script defaulted to 28 while the package declared 26, and said in a
# comment that the two matched.
#
# 26 is a FLOOR BENEATH EVERY ADOPTER, which is the only thing it can
# safely be. It used to say "26 is Qt's own floor: the kit's generated
# gradle.properties says qtMinSdkVersion=26", and that cited the wrong
# number for the wrong reason.
#
# ANDROID_API and qtMinSdkVersion are different quantities. This one is
# the NDK level DEPENDENCIES are cross-compiled against; qtMinSdkVersion
# is what the APP declares, which Qt writes per build. They do not track
# each other: measured 2026-09-01, hydra sets nothing here, takes this
# default of 26, and ships an app declaring 28.
#
# Nor is qtMinSdkVersion a property of the kit. The same Qt 6.12.0
# generates 26 for beerssh and bbq-predictor and 28 for hydra and
# fuzzypickles. So "track what Qt declares" names no single number, and
# raising this default to 28 would cross-compile dependencies at 28 for
# two trees whose apps declare 26 -- exactly the failure the paragraph
# above describes, introduced by the fix for it.
#
# So the default belongs at or below the LOWEST minimum any adopter
# declares, and it is checked against the artifact rather than against a
# comment: `aapt2 dump badging <apk> | grep minSdkVersion`. RAISE IT
# PROJECT-SIDE, above the include,
# when this project's own code needs a later libc -- `ANDROID_API = 28`
# and the ?= below yields. bionic marks getrandom __INTRODUCED_IN(28), so
# a tree calling it compiled against 26 fails inside its own entropy
# source, naming neither this variable nor the floor it wanted; that cost
# one adopter a debugging session on a clean rebuild. If a compile fails
# on a libc symbol that exists on your desktop, this is the knob.
ANDROID_API      ?= 26
export ANDROID_API

# 36, and the floor is Qt's rather than this project's.
#
# It was 33, and Qt 6.12 will not build against it. Qt pulls androidx.core
# transitively, and each release of that library raises the compileSdk it
# demands of anything depending on it: 1.16 wanted 35, 1.17 wants 36. Gradle
# refuses in AAR-metadata terms rather than in SDK terms --
#
#     3 issues were found when checking AAR metadata:
#     1.  Dependency 'androidx.core:core:1.17.0' requires libraries and
#         applications that depend on it to compile against version 36 or
#         later of the Android APIs.
#
# -- which names a library nobody wrote down and never mentions this
# variable, so the connection back to here has to be made from memory.
#
# NOT a check, deliberately. Which androidx versions a given Qt release
# resolves is not something a Makefile can know without asking Gradle, and a
# guess would go stale silently -- worse than the real error, which at least
# names the version it wants. The number is raised when a build says so.
ANDROID_TARGET_API ?= 36

# EXPORTED, not merely set, and this is load-bearing.
#
# androiddeployqt reads the SDK location out of the deployment-settings JSON,
# which qmake writes from the ENVIRONMENT rather than from any make variable.
# Leave these unexported and qmake falls back to whatever path was baked into
# the Qt installation -- /opt/android/sdk on the machine this was found on --
# so the build compiles every source, links the shared object, and only then
# fails at packaging with "Directory /opt/android/sdk/platforms does not
# exist": a path nobody configured, named by nothing the project can see.
export ANDROID_SDK_ROOT

# The NDK is found, not asked for, matching what the help in every adopter
# already promises. sdkmanager installs NDKs under $(ANDROID_SDK_ROOT)/ndk/
# one directory per version, so the newest by version sort is the default
# and an explicit ANDROID_NDK_ROOT still wins. Before this, the variable
# was exported and never defaulted: android-check failed on a machine with
# the NDK in the standard place, in all four adopters at once, and only a
# session that happened to carry the variable in its environment could
# build -- which reads as "works for whoever set it up" and is exactly the
# per-machine friction the fragment exists to remove.
ANDROID_NDK_ROOT ?= $(lastword $(sort $(wildcard $(ANDROID_SDK_ROOT)/ndk/*)))
export ANDROID_NDK_ROOT

# Which platform Gradle compiles against, named rather than guessed.
#
# androiddeployqt's default is "the highest available", and its idea of
# highest is wrong when the SDK holds an extension platform: with android-36
# installed beside android-33-ext5 it chose the latter, and Gradle then
# refused the build because Qt's own AndroidX dependencies require at least
# 34. The failure names neither the platform it picked nor where it picked it
# from, so naming it here removes a heuristic that is demonstrably wrong on a
# perfectly ordinary SDK.
ANDROID_PLATFORM ?= android-$(ANDROID_TARGET_API)

# Find the kit if nobody named one. hydra's, taken here because it removes
# the single most tedious thing about this build.
#
# Without it every android target needs QT_ANDROID_ROOT spelled out on the
# command line, which is a path with a version number in it that changes
# under you at every Qt update. hydra's default named 6.11.1 -- a version
# that machine did not have -- so the default was one that had to be
# overridden every time, which is no default at all.
#
# ANDROID_ABI is the input here and the kit is the answer, which is the
# reverse of the derivation below. The two do not fight: this runs only when
# QT_ANDROID_ROOT is unset, and whatever it finds is then read back by the
# ABI derivation and cross-checked by android-check, so a kit found here
# that disagrees with an explicit ANDROID_ABI is still refused by name.
#
# `sort -V`, because a lexical sort puts 6.3.2 above 6.10.0 and would pick
# the older kit for as long as nobody noticed. `ifndef` rather than `?=` so
# the search runs once instead of at every reference.
QT_ROOT ?= $(HOME)/Qt
QT_KIT_arm64-v8a   = android_arm64_v8a
QT_KIT_armeabi-v7a = android_armv7
QT_KIT_x86_64      = android_x86_64
QT_KIT_x86         = android_x86

ifndef QT_ANDROID_ROOT
ifneq ($(ANDROID_ABI),)
QT_ANDROID_ROOT := $(shell ls -d \
        $(QT_ROOT)/*/$(QT_KIT_$(ANDROID_ABI)) 2>/dev/null | sort -V | tail -1)
else
# No ABI named either, so prefer arm64-v8a over whatever sorts last.
#
# Sorting the kit names and taking the last gives android_x86_64, which is
# an emulator build. That installs on no phone anybody owns, and it is the
# worst kind of wrong default: everything succeeds, the APK is real, and it
# is discovered by `adb install` refusing it. Every physical device this
# would be built for is arm64.
QT_ANDROID_ROOT := $(shell \
        ls -d $(QT_ROOT)/*/android_arm64_v8a 2>/dev/null | sort -V | tail -1 \
        || true)
ifeq ($(QT_ANDROID_ROOT),)
QT_ANDROID_ROOT := $(shell ls -d $(QT_ROOT)/*/android_* 2>/dev/null \
                            | sort -V | tail -1)
endif
endif
endif

# The host-side deploy tool, asked for rather than assumed. Qt puts it with
# the HOST tools, not in the Android kit, and the directory is named
# differently per platform -- qmake knows where it is.
ifdef QT_ANDROID_ROOT
ANDROID_HOST_BINS := $(shell $(QT_ANDROID_ROOT)/bin/qmake -query QT_HOST_BINS 2>/dev/null)
endif

ANDROID_DEPLOY_QT ?= $(ANDROID_HOST_BINS)/androiddeployqt

# The JDK, resolved and EXPORTED rather than left to Gradle to find.
#
# Gradle picks its own toolchain and will happily choose a JRE: on the
# machine this was written for it took java-21-openjdk, which ships no
# compiler, and failed with "does not provide the required capabilities:
# [JAVA_COMPILER]" while a perfectly good JDK 17 sat on PATH. The preflight
# had passed, honestly and uselessly -- it checked one JVM and the build used
# another, which is a check verifying something other than what it protects.
#
# Resolving JAVA_HOME from javac and exporting it makes the two the same JVM,
# so the preflight now guarantees the compiler Gradle actually runs.
ifeq ($(origin JAVA_HOME), undefined)
JAVA_HOME := $(patsubst %/bin/javac,%,$(realpath $(shell command -v javac 2>/dev/null)))
endif

export JAVA_HOME

ANDROID_ADB       = $(ANDROID_SDK_ROOT)/platform-tools/adb

# The ABI is the Qt KIT's, read from it rather than chosen a second time.
#
# beerssh found what happens otherwise: building against the x86_64 kit with
# ANDROID_ABI left at arm64-v8a produced a package named for an ABI it did
# not contain, which installs on nothing it claims to target and cannot be
# told apart by looking at the file.
ifdef QT_ANDROID_ROOT
ANDROID_KIT_ABI := $(shell sed -n 's/^DEFAULT_ANDROID_ABIS *= *//p' \
                            $(QT_ANDROID_ROOT)/mkspecs/qdevice.pri 2>/dev/null)

ifeq ($(ANDROID_KIT_ABI),)
ANDROID_KIT_ABI := $(patsubst android_%,%,$(notdir $(patsubst %/,%,$(QT_ANDROID_ROOT))))
ANDROID_KIT_ABI := $(subst arm64_v8a,arm64-v8a,$(ANDROID_KIT_ABI))
ANDROID_KIT_ABI := $(subst armv7,armeabi-v7a,$(ANDROID_KIT_ABI))
ANDROID_KIT_ABI := $(filter arm64-v8a armeabi-v7a x86 x86_64,$(ANDROID_KIT_ABI))
endif
endif

ANDROID_ABI ?= $(ANDROID_KIT_ABI)

# Play refuses an upload whose versionCode does not exceed the last it took,
# so a hardcoded number allows exactly one upload and blocks every update
# after it. Derived as major*10000 + minor*100 + patch: 0.1.0 is 100.
#
# Override to re-upload the SAME version after a rejected release, which is
# the case that leaves you needing it.
ANDROID_VERSION_CODE ?= $(shell echo $(VERSION) | awk -F. \
        '{printf "%d", ($$1 * 10000) + ($$2 * 100) + $$3}')

# Signing comes from the environment and never from the tree.
#
# A keystore committed anywhere is a keystore that has to be replaced, and
# the upload key is the one thing a store account cannot regenerate for you.

# A project's own preflight runs as part of this one, not instead of it.
#
# Every adopter has something to check that is nobody else's business:
# beerssh needs libssh built for the ABI, fuzzypickles its vendored archives,
# hydra its kit selection. Left without somewhere to put those, a project
# redefines android-check -- and make takes the last definition it read,
# silently, so the shared preflight stops running the moment a project adds
# a check of its own. That is the worst possible failure for a preflight:
# the checks that were paid for in broken builds are the ones that vanish.
#
# So name a target and this one will depend on it:
#
#   ANDROID_CHECK_LOCAL = android-check-beerssh
#   android-check-beerssh:
#           @test -f deps/... || { echo "..." >&2; exit 1; }
#
# Unset, nothing extra runs and nothing is reported -- a project with no
# local preflight is not missing one.
# Set it wherever you like, including below this include. Make expands an
# explicit rule's prerequisites AS IT READS THE RULE, so a plain
# `android-check: $(ANDROID_CHECK_LOCAL)` would see the variable's value at
# this point in the file and nowhere else -- a project setting it further
# down would get an android-check with no local prerequisite, running the
# shared checks, printing nothing about the missing one and passing. That is
# the same silent retirement this hook exists to prevent, arriving by a
# different door. Measured on a fixture before it was written this way.
#
# It runs LAST, after the shared checks, and that ordering is the point.
#
# It was a prerequisite first -- `android-check: $$(ANDROID_CHECK_LOCAL)` --
# which make satisfies BEFORE the recipe, so the project's check went first
# and a failure in it meant the shared checks never ran. That is backwards,
# because a local check is almost always downstream of the shared ones.
# Measured in beerssh with `make android-check QT_ANDROID_ROOT=`: it reported
# "dependencies for  are not built" with an empty ABI and told the reader to
# run a script with no argument. The ABI was empty BECAUSE no kit was named,
# which is the shared check's message -- so the local check pre-empted the
# check that would have explained it, and offered its own symptom as the
# diagnosis.
#
# Invoked with $(MAKE) at the end of the recipe rather than ordered among
# prerequisites, because prerequisite order is not guaranteed under `make
# -j`. A recursive call is sequenced by construction.

# The activity `android-run` starts. Three of the four adopters declare Qt's
# own class in their manifests and never touch this; hydra subclasses it and
# declares se.vibes.hydra.HydraActivity, so with the name hardcoded here the
# only way to launch it was to define android-run again -- which make accepts
# in silence, retires the shared recipe, and announces on every build of that
# project as "overriding recipe for target". The fragment's own history has a
# version of that bug shipping, which is why ANDROID_CHECK_LOCAL is a hook
# rather than an invitation to redefine android-check.
#
# A default-valued variable is the smaller form of the same answer: the three
# that declare Qt's class notice nothing, and the one that does not sets a
# line instead of a recipe.
ANDROID_ACTIVITY ?= org.qtproject.qt.android.bindings.QtActivity

# A check on the built artifact, run before it is installed. Empty by
# default, invoked the same recursive way as ANDROID_CHECK_LOCAL.
#
# It exists because an Android build can exit 0 having quietly not packaged
# something. androiddeployqt scans a library's dependencies under names it
# builds by appending the ABI, so a kit shipping its FFmpeg libraries
# unsuffixed makes the scan fail while the copy, which uses the real names,
# succeeds: fifteen llvm-readobj errors, exit 0, a working APK. **A build
# that dropped a library looks exactly the same from outside** -- same log
# shape, same status -- and nothing short of reading the artifact separates
# them. harmonization.md already asks shared tooling to verify the
# artifact's SIGNATURE rather than trust a build that reported success,
# after signing flags were silently dropped by Qt's generated Makefile.
# What gets packaged is decided by a step whose failures are warnings, so
# it is the same shape and the fragment checked one and not the other.
#
# Attached to android-install rather than to a build, because the fragment
# does not own the build -- each project has its own `android` rule -- and
# a hook declared here that nothing here invokes would be a check that
# cannot run, which reads exactly like a clean tree. android-install is the
# fragment's own target, depends on `android`, and knows ANDROID_ARTIFACT,
# so a project that sets this cannot install an APK that failed it. A
# project wanting it earlier can invoke the same target from its own rule.
#
# What to check is the project's to decide, and so is whether an adopter
# without QtMultimedia wants the cost at all: fuzzypickles carries
# tool/check_apk_libs.py, which walks every .so in the APK and reports any
# NEEDED entry neither packaged nor provided by the platform, DERIVING the
# platform set from the NDK sysroot at the declared API rather than listing
# it -- an allowlist of what Android provides is a waiver list, and goes
# stale silently when ANDROID_API moves. The fragment supplies the place to
# attach, not the policy.

android-check:
	@# ANDROID_API must not exceed what the app declares.
	@#
	@# The invariant the comment on ANDROID_API states, checked rather
	@# than asserted -- it was written 2026-09-01 with nothing enforcing
	@# it, and an adopter whose app drops below the default would break
	@# it silently. Dependencies cross-compiled ABOVE the app's declared
	@# minimum resolve symbols that are absent on the oldest device the
	@# app claims to support, so the failure lands on somebody else's
	@# phone. Below is the safe side and equal is fine.
	@#
	@# It reads the generated gradle.properties, which is the file the
	@# old comment cited as ANDROID_API's own justification -- it is not
	@# that, but it IS where the app's declared minimum can be read
	@# without a device or aapt2.
	@#
	@# **This cannot check a first build**, because that file does not
	@# exist until Qt has generated it. It says which of the two happened
	@# rather than passing identically either way: a check whose skip is
	@# indistinguishable from its pass is one a later reader quotes as
	@# "android-check is green" without knowing what was compared, which
	@# is the shape `evidence.md` refuses. Measured by hydra against a
	@# real build -- three lines of output whether it verified or not --
	@# and the line below is what closes it.
	@decl="$(ANDROID_BUILD_DIR)/android-build/gradle.properties"; \
	if [ -f "$$decl" ]; then \
		want=`sed -n 's/^qtMinSdkVersion=\([0-9][0-9]*\)$$/\1/p' "$$decl"`; \
		if [ -z "$$want" ]; then \
			echo "android:   api $(ANDROID_API), app declares nothing readable -- NOT checked"; \
		elif [ "$(ANDROID_API)" -gt "$$want" ]; then \
			echo "android: ANDROID_API is $(ANDROID_API), the app declares minSdk $$want." >&2; \
			echo "android:   Dependencies would be cross-compiled against a later" >&2; \
			echo "android:   libc than the oldest device this app admits to, and" >&2; \
			echo "android:   the failure lands there rather than here." >&2; \
			echo "android:   Lower ANDROID_API, or raise what the app declares." >&2; \
			exit 1; \
		else \
			echo "android:   api $(ANDROID_API), app declares $$want -- at or below, as required"; \
		fi; \
	else \
		echo "android:   api $(ANDROID_API), app declares nothing yet -- NOT checked"; \
	fi
	@if [ -z "$(QT_ANDROID_ROOT)" ]; then \
		echo "android: QT_ANDROID_ROOT is not set." >&2; \
		echo "android:   point it at a Qt-for-Android kit, e.g." >&2; \
		echo "android:   make android QT_ANDROID_ROOT=\$$HOME/Qt/<version>/android_arm64_v8a" >&2; \
		exit 1; \
	fi
	@if [ -z "$(ANDROID_ABI)" ]; then \
		echo "android: cannot tell which ABI this kit builds." >&2; \
		echo "android:   neither $(QT_ANDROID_ROOT)/mkspecs/qdevice.pri nor the" >&2; \
		echo "android:   kit's directory name says. Name it yourself:" >&2; \
		echo "android:   make android ANDROID_ABI=arm64-v8a" >&2; \
		exit 1; \
	fi
	@if [ -n "$(ANDROID_KIT_ABI)" ] && [ "$(ANDROID_ABI)" != "$(ANDROID_KIT_ABI)" ]; then \
		echo "android: ANDROID_ABI is $(ANDROID_ABI), the kit builds $(ANDROID_KIT_ABI)." >&2; \
		echo "android:   qmake follows the kit, so building on would name the" >&2; \
		echo "android:   artifact after an ABI it does not contain." >&2; \
		exit 1; \
	fi
	@# The kit's own library name, which is the ABI the LINKER will use.
	@#
	@# hydra's, and it is better evidence than either source above:
	@# qdevice.pri is a text file describing intent and the directory name is
	@# Qt's to change, while libQt6Core_<abi>.so is the artifact that gets
	@# linked. `qmake -query QT_ARCH` was the obvious source and was tried
	@# first -- all four kits on the machine this was written for answer
	@# `**Unknown**`, so it cannot tell them apart at all.
	@#
	@# A kit that will not say what it is FAILS here rather than passing. An
	@# unconfirmed ABI is the state this check exists to refuse, and the cost
	@# of guessing is a package named after an architecture it does not
	@# contain -- which installs on nothing and cannot be told by looking.
	@core=$$(ls $(QT_ANDROID_ROOT)/lib/libQt6Core_*.so 2>/dev/null | head -1); \
	if [ -z "$$core" ]; then \
		echo "android: $(QT_ANDROID_ROOT) ships no libQt6Core_<abi>.so," >&2; \
		echo "android:   so its ABI cannot be confirmed; refusing to guess." >&2; \
		exit 1; \
	fi; \
	kit=$${core##*/libQt6Core_}; kit=$${kit%.so}; \
	if [ "$$kit" != "$(ANDROID_ABI)" ]; then \
		echo "android: ABI mismatch. ANDROID_ABI is $(ANDROID_ABI), but that" >&2; \
		echo "android:   kit links $$kit -- read from its own libQt6Core." >&2; \
		echo "android:   kit: $(QT_ANDROID_ROOT)" >&2; \
		exit 1; \
	fi
	@if [ -z "$(ANDROID_NDK_ROOT)" ] || [ ! -d "$(ANDROID_NDK_ROOT)" ]; then \
		echo "android: ANDROID_NDK_ROOT is not set or does not exist." >&2; \
		echo "android:   the kit above was built against a particular NDK; a" >&2; \
		echo "android:   different one may fail in ways that name neither." >&2; \
		exit 1; \
	fi
	@if [ ! -d "$(ANDROID_SDK_ROOT)/platform-tools" ]; then \
		echo "android: no Android SDK at $(ANDROID_SDK_ROOT)." >&2; \
		echo "android:   the SDK is SEPARATE from the NDK -- Gradle needs" >&2; \
		echo "android:   platform-tools, a platform and build-tools." >&2; \
		exit 1; \
	fi
	@# build-tools, checked because the message above already promises it
	@# and because apksigner lives there. Verifying a signature is the one
	@# packaging check that cannot be done by looking at the file, so the
	@# absent case belongs HERE -- named once, early, with the fix in the
	@# sentence -- rather than at the point of verification, where it used
	@# to exit 0 and let an unchecked signature read as a pass.
	@if [ -z "$$(ls $(ANDROID_SDK_ROOT)/build-tools/*/apksigner 2>/dev/null)" ]; then \
		echo "android: no apksigner under $(ANDROID_SDK_ROOT)/build-tools." >&2; \
		echo "android:   Install build-tools with the SDK manager. Gradle" >&2; \
		echo "android:   needs them to package, and this build needs" >&2; \
		echo "android:   apksigner to say who signed the result." >&2; \
		exit 1; \
	fi
	@if [ -z "$(JAVA_HOME)" ] && ! command -v javac >/dev/null 2>&1; then \
		echo "android: no javac on PATH and JAVA_HOME is unset." >&2; \
		echo "android:   Gradle needs a JDK; a JRE alone will not do, and it" >&2; \
		echo "android:   says so only as a toolchain capability error." >&2; \
		exit 1; \
	fi
	@if [ ! -d "$(JAVA_HOME)" ]; then \
		echo "android: JAVA_HOME=$(JAVA_HOME) is not a directory." >&2; \
		echo "android:   Nothing was inspected, so whether a JDK is present" >&2; \
		echo "android:   is unknown -- a stale or mistyped export reaches" >&2; \
		echo "android:   here unchanged, because JAVA_HOME is only derived" >&2; \
		echo "android:   from javac when its origin is undefined." >&2; \
		exit 1; \
	fi
	@if [ ! -x "$(JAVA_HOME)/bin/javac" ]; then \
		echo "android: JAVA_HOME=$(JAVA_HOME) exists and has no bin/javac." >&2; \
		echo "android:   That is a JRE. Gradle reports it as a toolchain" >&2; \
		echo "android:   lacking JAVA_COMPILER, naming the JVM but not the" >&2; \
		echo "android:   reason." >&2; \
		exit 1; \
	fi
	@kit_ndk=$$(sed -n 's/.*android-ndk-r\([0-9]*\).*/\1/p' \
	                 "$(QT_ANDROID_ROOT)/mkspecs/qdevice.pri" 2>/dev/null | head -1); \
	used_ndk=$$(sed -n 's/^Pkg.Revision *= *\([0-9]*\).*/\1/p' \
	                 "$(ANDROID_NDK_ROOT)/source.properties" 2>/dev/null | head -1); \
	if [ -n "$$kit_ndk" ] && [ -n "$$used_ndk" ] && [ "$$kit_ndk" != "$$used_ndk" ]; then \
		echo "android: NDK $$used_ndk, but this Qt kit was built against r$$kit_ndk." >&2; \
		echo "android:   That mismatch is not a build error. It compiles, links," >&2; \
		echo "android:   packages, signs and installs, and then dlopen refuses the" >&2; \
		echo "android:   Qt libraries on the device for a missing libc++ symbol." >&2; \
		echo "android:   Install the matching NDK, or set ANDROID_NDK_MISMATCH_OK=1" >&2; \
		echo "android:   if you have a reason." >&2; \
		[ -n "$(ANDROID_NDK_MISMATCH_OK)" ] || exit 1; \
	fi
	@echo "android:   jdk $(JAVA_HOME)"
	@echo "android: kit $(QT_ANDROID_ROOT)"
	@echo "android:   abi $(ANDROID_ABI), versionCode $(ANDROID_VERSION_CODE)"
	@# Last, so the shared checks above have already explained anything they
	@# would have explained. Guarded on the variable being set, since a bare
	@# `$(MAKE)` with no target would run the default goal.
	$(if $(ANDROID_CHECK_LOCAL),@$(MAKE) --no-print-directory $(ANDROID_CHECK_LOCAL))

# Whoever signed it, read from the artifact rather than announced.
#
# The pattern has to cope with more than one apksigner output format. It read
# only "Signer #1 certificate DN:", and build-tools 37 prints "V2 Signer:
# certificate DN:" instead -- so the check matched nothing, announced "signed
# by " with an empty name, and the debug-key guard below could never fire. The
# check written to stop a debug-signed release had been quietly disabled by a
# tool update, which is the same failure one layer up. An unreadable signature
# is now an error rather than a blank.
#
# beerssh shipped a "release build" signed with the Android debug key, and
# the only reason anybody noticed is that somebody ran apksigner by hand:
# flags passed to Qt's GENERATED Makefile are dropped silently, so the build
# reports success and produces a debug-signed package under a message saying
# otherwise. Signed with the debug key is the one packaging mistake that
# cannot be caught by looking at the file.
define android_verify_signature
	@signer=$$(ls $(ANDROID_SDK_ROOT)/build-tools/*/apksigner 2>/dev/null | tail -1); \
	if [ -z "$$signer" ]; then \
		echo "android: no apksigner under $(ANDROID_SDK_ROOT)/build-tools," >&2; \
		echo "android:   so who signed $(1) is UNCHECKED. That is the same" >&2; \
		echo "android:   end state as an unreadable signature below, and it" >&2; \
		echo "android:   gets the same answer: it must not read as a pass." >&2; \
		echo "android:   Install build-tools; \`make android-check' says so" >&2; \
		echo "android:   earlier and more clearly." >&2; \
		exit 1; \
	fi; \
	dn=$$($$signer verify --print-certs "$(1)" 2>/dev/null \
	      | sed -n -e 's/^Signer #1 certificate DN: //p' \
	               -e 's/^V[0-9]* Signer: certificate DN: //p' \
	      | head -1); \
	if [ -z "$$dn" ]; then \
		echo "android: cannot read the signature of $(1)." >&2; \
		echo "android:   apksigner ran and printed nothing this recognises," >&2; \
		echo "android:   so the signer is UNKNOWN. That must not read as a" >&2; \
		echo "android:   pass: it is how a debug-signed release ships." >&2; \
		exit 1; \
	fi; \
	echo "android: signed by $$dn"; \
	if [ -n "$(ANDROID_KEYSTORE)" ] && echo "$$dn" | grep -q "Android Debug"; then \
		echo "android: a keystore was given but the artifact is DEBUG-signed" >&2; \
		exit 1; \
	fi
endef

# What Play will refuse, read from the bundle itself before uploading it.
#
# The android-aab rules in the four adopters each refuse to run without a
# keystore, and none of them reads the result: whether the bundle came out
# signed, by which key, at which targetSdk and versionCode, and with which
# page alignment is announced by the build or assumed. Each is something
# Play checks on upload, a day later and one rejection at a time. So this
# reads all four from the file, and says which it could not read rather
# than passing over it.
#
#   ANDROID_AAB              the bundle; the project's android-aab knows it
#   ANDROID_PLAY_TARGET_API  Play's targetSdk floor for new apps and updates.
#                            36 since 2026-08-31, per
#                            developer.android.com/google/play/requirements/target-sdk
#                            -- dated, because Play raises it every year
#   ANDROID_PLAY_ALLOW_4K    set to 1 to let 4 KB-aligned libraries through
#
# The signer is read with keytool rather than apksigner, which does not
# read a bundle: an AAB is jar-signed. "Not a signed jar file" and a DN of
# Android Debug both fail, since Play takes neither.
#
# targetSdk and versionCode come from the bundle's manifest, which is in
# protobuf rather than binary XML. aapt2 refuses the bundle itself ("could
# not identify format of APK"), and reads the same manifest once it is
# re-zipped at the root of an archive of its own -- measured 2026-10-22
# against a bundle made from beerssh's APK, which read back targetSdk 35.
# The versionCode is compared with what this tree's VERSION derives, so a
# bundle left over from an earlier version is caught rather than uploaded.
#
# Page alignment: Play requires 16 KB support for apps targeting 35 and up
# that carry native code, and refuses updates without it from 2027-02-01.
# Only the 64-bit ABIs are read, which is what the requirement covers.
# Every LOAD segment of every library must be aligned to at least 0x4000.
# Qt's own libraries are; measured 2026-10-22, bbq-predictor's
# cross-compiled OpenSSL was 0x1000, because NDK r27 links at 4 KB unless
# told -Wl,-z,max-page-size=16384. A library that is not aligned also fails
# to load on a 16 KB device, which is why this is an error and not advice.
ANDROID_PLAY_TARGET_API ?= 36

android-play-check:
	@aab="$(ANDROID_AAB)"; \
	if [ -z "$$aab" ]; then \
		echo "play: ANDROID_AAB is not set; the project names its bundle." >&2; \
		exit 1; \
	fi; \
	if [ ! -f "$$aab" ]; then \
		echo "play: no bundle at $$aab -- run make android-aab first." >&2; \
		exit 1; \
	fi; \
	aapt2=$$(ls $(ANDROID_SDK_ROOT)/build-tools/*/aapt2 2>/dev/null | sort -V | tail -1); \
	for t in keytool zip unzip readelf "$$aapt2"; do \
		if [ -z "$$t" ] || ! command -v "$$t" >/dev/null 2>&1; then \
			echo "play: missing $${t:-aapt2 under build-tools}; nothing was checked." >&2; \
			exit 1; \
		fi; \
	done; \
	tmp=$$(mktemp -d) || exit 1; \
	trap 'rm -rf "$$tmp"' EXIT; \
	fail=0; \
	owner=$$(keytool -printcert -jarfile "$$aab" 2>/dev/null \
	         | sed -n 's/^Owner: //p' | head -1); \
	if [ -z "$$owner" ]; then \
		echo "play: $$aab is UNSIGNED. Play takes only a bundle signed" >&2; \
		echo "play:   with the upload key." >&2; \
		fail=1; \
	elif echo "$$owner" | grep -q "Android Debug"; then \
		echo "play: $$aab is signed with the DEBUG key: $$owner" >&2; \
		fail=1; \
	else \
		echo "play:   signed by $$owner"; \
	fi; \
	mkdir "$$tmp/m"; \
	if unzip -q -j "$$aab" base/manifest/AndroidManifest.xml -d "$$tmp/m" 2>/dev/null \
	   && (cd "$$tmp/m" && zip -q ../m.zip AndroidManifest.xml); then \
		tree=$$("$$aapt2" dump xmltree --file AndroidManifest.xml "$$tmp/m.zip" 2>/dev/null); \
	else \
		tree=''; \
	fi; \
	target=$$(echo "$$tree" | sed -n 's/.*:targetSdkVersion([^)]*)=\([0-9][0-9]*\).*/\1/p' | head -1); \
	code=$$(echo "$$tree" | sed -n 's/.*:versionCode([^)]*)=\([0-9][0-9]*\).*/\1/p' | head -1); \
	if [ -z "$$target" ] || [ -z "$$code" ]; then \
		echo "play: cannot read targetSdk and versionCode from the bundle's" >&2; \
		echo "play:   manifest, so neither is CHECKED." >&2; \
		fail=1; \
	else \
		if [ "$$target" -lt "$(ANDROID_PLAY_TARGET_API)" ]; then \
			echo "play: targetSdk $$target, Play requires $(ANDROID_PLAY_TARGET_API) or higher." >&2; \
			fail=1; \
		else \
			echo "play:   targetSdk $$target, floor $(ANDROID_PLAY_TARGET_API)"; \
		fi; \
		if [ "$$code" != "$(ANDROID_VERSION_CODE)" ]; then \
			echo "play: versionCode $$code, but VERSION $(VERSION) derives" >&2; \
			echo "play:   $(ANDROID_VERSION_CODE) -- a stale bundle, or an override." >&2; \
			fail=1; \
		else \
			echo "play:   versionCode $$code, from VERSION $(VERSION)"; \
		fi; \
	fi; \
	libs=$$(unzip -Z1 "$$aab" 2>/dev/null \
	        | grep -E '^base/lib/(arm64-v8a|x86_64)/[^/]*\.so$$'); \
	n=0; bad=''; \
	for so in $$libs; do \
		unzip -p "$$aab" "$$so" > "$$tmp/l.so"; \
		low=$$(readelf -lW "$$tmp/l.so" 2>/dev/null | awk '$$1=="LOAD"{print $$NF}' \
		       | while read a; do echo $$((a)); done | sort -n | head -1); \
		n=$$((n + 1)); \
		if [ -z "$$low" ] || [ "$$low" -lt 16384 ]; then \
			bad="$$bad $${so##*/}($${low:-unreadable})"; \
		fi; \
	done; \
	if [ "$$n" -eq 0 ]; then \
		echo "play:   no 64-bit native libraries, so no page alignment to check"; \
	elif [ -n "$$bad" ]; then \
		echo "play: not 16 KB aligned, of $$n 64-bit libraries:$$bad" >&2; \
		echo "play:   link with -Wl,-z,max-page-size=16384 on NDK r27 and older." >&2; \
		[ "$(ANDROID_PLAY_ALLOW_4K)" = 1 ] || fail=1; \
	else \
		echo "play:   $$n 64-bit libraries, all 16 KB aligned"; \
	fi; \
	if [ "$$fail" -ne 0 ]; then \
		echo "play: $$aab would be refused." >&2; \
		exit 1; \
	fi; \
	echo "play: $$aab passes what this can read; the listing and the"; \
	echo "play:   declarations are the console's, and are not checked here."

android-install: android
	$(if $(ANDROID_ARTIFACT_CHECK),@$(MAKE) --no-print-directory $(ANDROID_ARTIFACT_CHECK))
	$(ANDROID_ADB) install -r $(ANDROID_ARTIFACT)

android-run: android-install
	$(ANDROID_ADB) shell am start -n \
	        $(APP_ID)/$(ANDROID_ACTIVITY)

# This app's log and nothing else. `adb logcat` unfiltered is every process
# on the device, which is how a real message gets lost rather than read.
android-log:
	@if [ ! -x "$(ANDROID_ADB)" ] && ! command -v adb >/dev/null 2>&1; then \
		echo "android-log: no adb at $(ANDROID_ADB) and none on PATH." >&2; \
		echo "android-log:   Nothing was asked, so whether $(APP_ID) is" >&2; \
		echo "android-log:   running is unknown. Install platform-tools." >&2; \
		exit 1; \
	fi; \
	n=$$($(ANDROID_ADB) devices 2>/dev/null | grep -cw device); \
	if [ "$$n" -eq 0 ]; then \
		echo "android-log: adb reports no attached device." >&2; \
		echo "android-log:   Nothing was asked, so whether $(APP_ID) is" >&2; \
		echo "android-log:   running is unknown." >&2; \
		exit 1; \
	fi; \
	pid=$$($(ANDROID_ADB) shell pidof -s $(APP_ID) 2>/dev/null); \
	if [ -z "$$pid" ]; then \
		echo "android-log: $(APP_ID) is not running on the device" >&2; \
		exit 1; \
	fi; \
	$(ANDROID_ADB) logcat --pid=$$pid

android-uninstall:
	$(ANDROID_ADB) uninstall $(APP_ID)

# Store screenshots of named views, taken from the build just installed.
#
# Asked for by the holder 2026-10-22: screenshots made automatically from
# the current version, of views chosen in advance, so the listing never
# shows a release older than the one it describes. It depends on
# android-install, so what is photographed is what this tree builds.
#
#   STORE_VIEWS          the views, in listing order; the project's. Play
#                        wants 2 to 8 per device type
#   STORE_SCREEN_SIZE    the display is switched to this for the capture
#   STORE_SHOT_DIR       where they land, per VERSION; build output, not
#                        source, since every build can regenerate them
#   STORE_READY_TIMEOUT  seconds to wait for a view to say it is drawn
#
# THE APP'S HALF, which this cannot supply. It is started as
#
#   am start -S -W -n $(APP_ID)/$(ANDROID_ACTIVITY) --es store_view <name>
#
# and must open that view with demo content -- never the user's real
# hosts, keys or history, which would then be published -- and log a line
# containing `store-view-ready <name>` once it is drawn. The capture waits
# for that line rather than sleeping, because a fixed sleep photographs a
# half-laid-out window on a slow device and wastes time on a fast one.
#
# 1080x1920 because Play refuses a screenshot whose long side exceeds twice
# its short side, and a 20:9 phone at native size is 2.2 -- every capture
# from a current phone would be refused. `wm size` is set for the run and
# put back by the trap, whatever the outcome; an override already present
# is restored rather than reset.
#
# The status bar is asked into SystemUI demo mode -- a fixed clock, a
# full battery, no notifications -- and out of it on exit. ASKED, not
# put: on a Galaxy Z Fold3 (One UI, Android 15) the broadcasts raised no
# error and changed nothing, and every capture showed the live clock,
# battery and charging icon (hydra, 2026-10-22). So an app that must not
# publish the device's status bar hides it itself in a store_view run,
# as beerssh does.
#
# Before each capture the focused window must be this app's. A locked
# phone photographs as black, which has cost two rounds before (the
# android-build skill's instrument note), and a focus check is what
# separates the app from the lock screen without a person looking.
#
# Waited for, up to ten seconds, and on failure the focus line is
# printed rather than guessed at. beerssh's first emulator run,
# 2026-10-22, stopped here under a message saying "locked?", and the
# phone was not locked: System UI had an ANR dialog up after a cold
# boot, which a capture would have photographed. On the passing run
# Android's "viewing full screen" hint held focus for a moment before
# clearing by itself. So a transient window gets time to go, and a
# window that stays is named.
#
# Every display's focus line is read, not the first. A Galaxy Z Fold3,
# folded, prints mCurrentFocus once per display and the first is always
# `null`, so `grep -m1` refused an app that was in front -- hydra's first
# run on a phone, 2026-10-22, failed twice that way after the view had
# logged ready. What screencap captures is the default display, and
# which display that is on a folding phone is unmeasured; on failure the
# mTopFocusedDisplayId line is printed with the focus lines, to say so.
#
# The screen is kept on for the run and woken at its start: with the
# phone's stay-awake setting off it locked between runs, and the target
# then failed at the first view (fuzzypickles, Fold3, 2026-10-23). The
# setting is put back on exit. It holds only while the phone is on
# power, which a USB cable is and wireless adb is not. Waking cannot get
# past a PIN or pattern,
# so a locked phone still needs its person, and the focus check names
# the lock screen when it is in front.
#
# The app is force-stopped on exit as well. The last view's process
# otherwise stays alive, and a plain launch or a tap on the icon only
# brings it forward: fuzzypickles' Fold run, 2026-10-22, left the phone
# showing its demo contacts with no daemon behind them until an
# `am start -S`. For an app whose demo replaces its data, that is the
# user's own app impersonated by its demo until the process dies.
#
# Each PNG's size is read back from its header and held to Play's rules:
# 320 to 3840 px a side, long side at most twice the short.
STORE_SCREEN_SIZE   ?= 1080x1920
STORE_SHOT_DIR      ?= $(ANDROID_BUILD_DIR)/store/$(VERSION)
STORE_READY_TIMEOUT ?= 30

android-screenshots: android-install
	@adb="$(ANDROID_ADB)"; views="$(STORE_VIEWS)"; \
	set -- $$views; \
	if [ $$# -lt 2 ] || [ $$# -gt 8 ]; then \
		echo "screenshots: STORE_VIEWS names $$# views; Play wants 2 to 8." >&2; \
		exit 1; \
	fi; \
	n=$$($$adb devices | grep -cw device); \
	if [ "$$n" -ne 1 ] && [ -z "$$ANDROID_SERIAL" ]; then \
		echo "screenshots: $$n devices attached; attach one or set ANDROID_SERIAL." >&2; \
		exit 1; \
	fi; \
	out="$(STORE_SHOT_DIR)"; \
	case "$$out" in ''|/) echo "screenshots: STORE_SHOT_DIR is '$$out'." >&2; exit 1;; esac; \
	mkdir -p "$$out" || exit 1; \
	old_size=$$($$adb shell wm size | sed -n 's/^Override size: //p' | tr -d '\r'); \
	old_demo=$$($$adb shell settings get global sysui_demo_allowed | tr -d '\r'); \
	old_awake=$$($$adb shell settings get global stay_on_while_plugged_in | tr -d '\r'); \
	restore() { \
		$$adb shell am force-stop $(APP_ID); \
		case "$$old_awake" in null|'') $$adb shell settings delete global stay_on_while_plugged_in >/dev/null 2>&1;; \
			*) $$adb shell settings put global stay_on_while_plugged_in "$$old_awake" >/dev/null 2>&1;; esac; \
		$$adb shell am broadcast -a com.android.systemui.demo -e command exit >/dev/null 2>&1; \
		case "$$old_demo" in 1) ;; null|'') $$adb shell settings delete global sysui_demo_allowed >/dev/null 2>&1;; \
			*) $$adb shell settings put global sysui_demo_allowed "$$old_demo" >/dev/null 2>&1;; esac; \
		if [ -n "$$old_size" ]; then $$adb shell wm size "$$old_size"; else $$adb shell wm size reset; fi; \
		$$adb shell rm -f /sdcard/store-shot.png; \
	}; \
	trap restore EXIT; trap 'exit 1' INT TERM; \
	$$adb shell wm size $(STORE_SCREEN_SIZE) || exit 1; \
	$$adb shell settings put global stay_on_while_plugged_in 7; \
	$$adb shell input keyevent KEYCODE_WAKEUP; \
	$$adb shell settings put global sysui_demo_allowed 1; \
	demo() { $$adb shell am broadcast -a com.android.systemui.demo -e command "$$@" >/dev/null; }; \
	demo enter; demo clock -e hhmm 1200; \
	demo battery -e level 100 -e plugged false; \
	demo network -e wifi show -e level 4 -e mobile show -e level 4; \
	demo notifications -e visible false; \
	i=0; fail=0; \
	for v in $$views; do \
		i=$$((i + 1)); f=$$(printf '%s/%02d-%s.png' "$$out" $$i "$$v"); \
		$$adb logcat -c; \
		$$adb shell am start -S -W -n $(APP_ID)/$(ANDROID_ACTIVITY) \
			--es store_view "$$v" >/dev/null || { fail=1; break; }; \
		t=0; \
		until $$adb logcat -d | grep -qF "store-view-ready $$v"; do \
			t=$$((t + 1)); \
			if [ $$t -ge $(STORE_READY_TIMEOUT) ]; then \
				echo "screenshots: $$v never logged store-view-ready in $(STORE_READY_TIMEOUT)s." >&2; \
				$$adb logcat -d > "$$out/$$v.logcat" 2>&1; \
				echo "screenshots:   the device log is in $$out/$$v.logcat" >&2; \
				echo "screenshots:   the app's half is missing or failed; see the comment" >&2; \
				echo "screenshots:   above android-screenshots in tool/android.mk." >&2; \
				fail=1; break 2; \
			fi; \
			sleep 1; \
		done; \
		t=0; \
		while focus=$$($$adb shell dumpsys window | grep -E 'mCurrentFocus|mTopFocusedDisplayId' | tr -d '\r'); \
		      ! echo "$$focus" | grep mCurrentFocus | grep -qF "$(APP_ID)"; do \
			t=$$((t + 1)); \
			if [ $$t -ge 10 ]; then \
				echo "screenshots: $$v: after 10s no display's focus is $(APP_ID):" >&2; \
				echo "$$focus" | sed 's/^/screenshots:  /' >&2; \
				fail=1; break 2; \
			fi; \
			sleep 1; \
		done; \
		$$adb shell screencap -p /sdcard/store-shot.png && \
		$$adb pull -q /sdcard/store-shot.png "$$f" >/dev/null || { fail=1; break; }; \
		set -- $$(od -An -tu1 -j16 -N8 "$$f"); \
		w=$$(( ($$1 << 24) | ($$2 << 16) | ($$3 << 8) | $$4 )); \
		h=$$(( ($$5 << 24) | ($$6 << 16) | ($$7 << 8) | $$8 )); \
		lo=$$w; hi=$$h; [ $$w -gt $$h ] && { lo=$$h; hi=$$w; }; \
		if [ $$lo -lt 320 ] || [ $$hi -gt 3840 ] || [ $$hi -gt $$((lo * 2)) ]; then \
			echo "screenshots: $$f is $${w}x$${h}, which Play refuses." >&2; \
			fail=1; \
		else \
			echo "screenshots: $$f  $${w}x$${h}"; \
		fi; \
	done; \
	[ $$fail -eq 0 ]

# The same screenshots, on an emulator this starts and stops, rather than
# on whatever phone is attached. Set by the holder 2026-10-23, after the
# Fold3 brought a lock screen and PIN, a camera-cutout band, One UI
# ignoring demo mode, and the owner's real app restarted under them. An
# emulator has none of those, so every run gives the same pictures.
#
# Taken from beerssh's tool/store-screenshots.sh (0334c62), where each
# step below was measured on this machine first.
#
#   STORE_AVD            ONE AVD shared by every app, `store`, by the
#                        holder's choice: create it with
#                          avdmanager create avd -n store \
#                            -k 'system-images;android-34;google_apis;x86_64' \
#                            -d 'Nexus 5X'
#                        A device with NO display cutout, by the holder's
#                        choice: pixel_6 declares a camera hole, and the
#                        apps kept a 102 px band clear under it in every
#                        capture. The Nexus 5X has none, and its 1080x1920
#                        panel is the capture size, so nothing is scaled.
#   STORE_EMULATOR_PORT  its port, refused if adb already sees it: an
#                        emulator on that serial is somebody else's
#   STORE_ABI            the AVD's ABI, x86_64; the build is for it
#   STORE_QT_ANDROID_ROOT  the kit for that ABI, found like the default
#                        one and PASSED on the command line, so a phone's
#                        arm64 kit set anywhere cannot win
#
# What stops it: every wait has a ceiling (300s to boot, 2400s for the
# capture), and the EXIT trap asks the emulator to quit, waits 30s, then
# SIGKILLs its process GROUP. `emulator` execs into qemu-system, which
# starts a netsimd child in its group, so it is started under setsid and
# the group is what dies; killing the pid alone orphaned netsimd.
# The group kill is spelled `kill -9 -PGID`, the one form dash accepts:
# `kill -9 -- -PGID` and `kill -s KILL -PGID` are both refused there
# (measured 2026-10-23), and the refusal fell through to killing qemu
# alone. The pid is checked to be a number above 1 first, because a
# negative 1 is every process the user owns.
#
# Liveness is read from /proc rather than `kill -0`, because the emulator
# is this shell's own child and stays a zombie until reaped.
#
# Data is wiped every run (-wipe-data, no snapshot), so the shared AVD
# carries nothing from another app's run and every run starts the same.
# The ready wait is 120s rather than the phone's 30: under software
# rendering at a load of 175 on 24 cores, views took longer than 30s to
# report drawn, a different view each run (2026-10-23).
#
# The cleanup ignores INT and TERM once it starts. Measured 2026-10-23: a
# TERM to the process group reaches the recipe's shell twice, directly and
# again from make passing it on, and the second fired `exit` inside the
# cleanup and cut it short -- leaving the emulator and its netsimd up with
# the trap having run. beerssh's version runs as a script, not under make,
# and never saw the second signal.
#
# Two runs cannot share the AVD: the port check refuses the second, and
# the emulator refuses an AVD already in use. Whoever counts leftovers:
# hull's machines are qemu-system-x86_64 too, so match on `-avd store`.
STORE_AVD             ?= store
STORE_EMULATOR_PORT   ?= 5584
STORE_ABI             ?= x86_64
STORE_EMULATOR_READY_TIMEOUT ?= 120
ifndef STORE_QT_ANDROID_ROOT
STORE_QT_ANDROID_ROOT := $(shell ls -d $(QT_ROOT)/*/$(QT_KIT_$(STORE_ABI)) \
                                 2>/dev/null | sort -V | tail -1)
endif

android-store-screenshots:
	@adb="$(ANDROID_ADB)"; emu="$(ANDROID_SDK_ROOT)/emulator/emulator"; \
	avd="$(STORE_AVD)"; serial="emulator-$(STORE_EMULATOR_PORT)"; \
	for t in "$$adb" "$$emu"; do \
		[ -x "$$t" ] || { echo "store: $$t is not there; set ANDROID_SDK_ROOT." >&2; exit 1; }; \
	done; \
	if ! "$$emu" -list-avds 2>/dev/null | grep -qx "$$avd"; then \
		echo "store: no AVD named $$avd; see the comment above android-store-screenshots." >&2; \
		exit 1; \
	fi; \
	if [ -z "$(STORE_QT_ANDROID_ROOT)" ]; then \
		echo "store: no Qt kit for $(STORE_ABI) under $(QT_ROOT); set STORE_QT_ANDROID_ROOT." >&2; \
		exit 1; \
	fi; \
	if "$$adb" devices | grep -q "^$$serial[[:space:]]"; then \
		echo "store: $$serial is already running, and is not this run's; stop it or set STORE_EMULATOR_PORT." >&2; \
		exit 1; \
	fi; \
	log=$$(mktemp) || exit 1; pid=''; \
	alive() { [ -n "$$1" ] && [ -r "/proc/$$1/status" ] && ! grep -q '^State:[[:space:]]*Z' "/proc/$$1/status"; }; \
	stop() { \
		trap '' INT TERM; \
		if alive "$$pid"; then \
			timeout 20 "$$adb" -s "$$serial" emu kill >/dev/null 2>&1; \
			w=0; while alive "$$pid" && [ $$w -lt 30 ]; do sleep 1; w=$$((w + 1)); done; \
			if alive "$$pid"; then \
				echo "store: the emulator did not quit; killing its group" >&2; \
				case "$$pid" in ''|*[!0-9]*|0|1) ;; *) kill -9 "-$$pid" 2>/dev/null || kill -9 "$$pid" 2>/dev/null;; esac; \
			fi; \
		fi; \
		rm -f "$$log"; \
	}; \
	trap stop EXIT; trap 'exit 130' INT TERM; \
	echo "store: starting $$avd headless on $$serial"; \
	setsid "$$emu" -avd "$$avd" -port $(STORE_EMULATOR_PORT) -no-window -no-audio \
		-no-boot-anim -no-snapshot -wipe-data -gpu swiftshader_indirect > "$$log" 2>&1 & \
	pid=$$!; \
	w=0; \
	until [ "$$(timeout 5 "$$adb" -s "$$serial" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ]; do \
		if ! alive "$$pid"; then \
			echo "store: the emulator exited while booting:" >&2; tail -5 "$$log" >&2; exit 1; \
		fi; \
		if [ $$w -ge 300 ]; then echo "store: $$avd did not boot in 300s" >&2; exit 1; fi; \
		sleep 5; w=$$((w + 5)); \
	done; \
	echo "store: booted in about $${w}s"; \
	sleep 20; \
	"$$adb" -s "$$serial" shell am broadcast -a android.intent.action.CLOSE_SYSTEM_DIALOGS >/dev/null 2>&1; \
	"$$adb" -s "$$serial" shell input keyevent KEYCODE_HOME >/dev/null 2>&1; \
	ANDROID_SERIAL="$$serial" timeout 2400 $(MAKE) --no-print-directory android-screenshots \
		ANDROID_ABI=$(STORE_ABI) QT_ANDROID_ROOT="$(STORE_QT_ANDROID_ROOT)" \
		STORE_READY_TIMEOUT=$(STORE_EMULATOR_READY_TIMEOUT); \
	rc=$$?; exit $$rc

.PHONY: android-check android-play-check android-screenshots android-store-screenshots android-install android-run android-log android-uninstall
