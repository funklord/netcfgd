/*
 * access_elevator.cpp -- which thing gets asked for root, and when nothing is.
 *
 * project.md calls the elevator unverified, and half of that is true: whether
 * pkexec's prompt behaves on a real desktop wants a real desktop. But *which*
 * of them is chosen does not. `QStandardPaths::findExecutable` reads PATH, so
 * PATH is the whole harness, and the choice is a table nobody had pinned.
 *
 * The case that matters is the last one. `sudo` without an askpass helper
 * wants a terminal, and a GUI has none -- so it would sit there forever with
 * nothing on screen, which is worse than saying it cannot help. That guard is
 * one `&&` and is the only thing standing between this client and a hang.
 */

#include "../src/access_view.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QTemporaryDir>

#include <cstdio>
#include <cstdlib>

static int failures;

static void check(bool condition, const char *what)
{
	fprintf(stderr, "access_elevator: %-50s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

static void put(const QDir &dir, const char *name)
{
	const QString path = dir.filePath(QString::fromLatin1(name));
	QFile file(path);
	file.open(QIODevice::WriteOnly);
	file.write("#!/bin/sh\nexit 0\n");
	file.close();
	QFile::setPermissions(path, QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner);
}

static void clear(const QDir &dir)
{
	for (const QString &name : dir.entryList(QDir::Files)) {
		QFile::remove(dir.filePath(name));
	}
}

int main(int argc, char **argv)
{
	QCoreApplication application(argc, argv);

	QTemporaryDir temporary;
	if (!temporary.isValid()) {
		fprintf(stderr, "access_elevator: no temporary directory -- not a pass\n");
		return 1;
	}
	const QDir bin(temporary.path());
	qputenv("PATH", temporary.path().toUtf8());

	/* Nothing on PATH at all. A machine with no way to raise privilege is a
	 * real machine -- a minimal image, a container -- and the client prints
	 * the command instead of half-attempting one. */
	clear(bin);
	qunsetenv("SUDO_ASKPASS");
	check(ncfg_access_view::elevator().isEmpty(), "nothing installed: no elevator");

	/* sudo alone is NOT an elevator. This is the guard, and it is the whole
	 * reason this file exists: sudo would ask for a password on a terminal
	 * this process does not have, and wait for it forever. */
	put(bin, "sudo");
	check(ncfg_access_view::elevator().isEmpty(),
	    "sudo without SUDO_ASKPASS is refused");

	/* With one configured it becomes usable. */
	qputenv("SUDO_ASKPASS", "/usr/bin/ssh-askpass");
	check(ncfg_access_view::elevator() == QStringLiteral("sudo"),
	    "sudo with SUDO_ASKPASS is taken");

	/* kdesu outranks sudo: 0118's pattern is KDE's, and it prompts on a
	 * graphical session rather than needing a helper configured. */
	put(bin, "kdesu");
	check(ncfg_access_view::elevator() == QStringLiteral("kdesu"), "kdesu beats sudo");

	/* And pkexec outranks everything, being the one a desktop is most likely
	 * to have wired to a real authentication agent. */
	put(bin, "pkexec");
	check(ncfg_access_view::elevator() == QStringLiteral("pkexec"), "pkexec beats kdesu");

	/* The order is a preference and not an accident of what exists: with
	 * pkexec gone but kdesu still there, the answer moves down one rather
	 * than falling to nothing or back to sudo. */
	QFile::remove(bin.filePath(QStringLiteral("pkexec")));
	check(ncfg_access_view::elevator() == QStringLiteral("kdesu"),
	    "removing pkexec falls back to kdesu");

	fprintf(stderr, "access_elevator: the order is pkexec, kdesu, then sudo -A\n");
	return failures ? 1 : 0;
}
