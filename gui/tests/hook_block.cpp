/*
 * hook_block.cpp -- the hook block the interface editor writes.
 *
 * WHY THIS EXISTS
 *   A hook body is the one place in this configuration language where the
 *   bytes are kept exactly as written, and two things follow that a screenshot
 *   cannot show. The body must not be indented -- the materialiser prepends
 *   `#!/bin/sh` to a body that does not start with one, so an indented shebang
 *   is not a shebang and every save adds another line to the script netcfgd
 *   runs. And the five event phases are spelled `on carrier`, not `carrier`;
 *   the parser takes the other six bare, and a block that got it wrong would
 *   be read as an assignment.
 */
#include "../src/hook_dialog.h"

#include <QCoreApplication>
#include <QString>
#include <QStringList>
#include <cstdio>

static int failures;

static void check(bool condition, const char *what)
{
	fprintf(stderr, "hook_block: %-58s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

/* What the materialiser does with a body, so the round trip can be asserted
 * without a daemon: a body that does not start with a shebang gets one. */
static QString materialised(const QString &body)
{
	return body.startsWith(QStringLiteral("#!")) ? body
	                                             : QStringLiteral("#!/bin/sh\n") + body;
}

/* The body back out of a block, by the rule the lexer uses: everything after
 * the head line, up to the first line that is nothing but a closing brace. */
static QString body_of(const QString &block)
{
	const QStringList lines = block.split(QLatin1Char('\n'));
	QStringList body;
	for (int i = 1; i < lines.size(); i++) {
		if (lines.at(i).trimmed() == QLatin1String("}")) {
			break;
		}
		body << lines.at(i);
	}
	return body.join(QStringLiteral("\n")) + QStringLiteral("\n");
}

int main(int argc, char **argv)
{
	QCoreApplication app(argc, argv);

	{
		const QString block = ncfg_hook_block(QStringLiteral("post_up"),
		    QStringLiteral("#!/bin/sh\nlogger -t netcfgd up\n"));
		check(block.startsWith(QStringLiteral("\tpost_up {")),
		    "a lifecycle phase is written bare");
		check(block.contains(QStringLiteral("\n#!/bin/sh\n")),
		    "and the body starts at column zero, where a shebang is a shebang");
		check(block.endsWith(QStringLiteral("\n\t}")),
		    "and the block ends on a line that is nothing but a brace");
	}

	{
		const QString block = ncfg_hook_block(QStringLiteral("carrier"),
		    QStringLiteral("#!/bin/sh\necho carrier\n"));
		check(block.startsWith(QStringLiteral("\ton carrier {")),
		    "an event phase is written with `on`, which the parser requires");
	}

	/* **The round trip, which is the whole reason the body is not indented.**
	 * Write it, materialise it, load it back, write it again: the script
	 * netcfgd runs has to be the same both times. Indented, the shebang stops
	 * being recognised and a line is added on every save. */
	{
		const QString typed = QStringLiteral("#!/bin/sh\nlogger -t netcfgd hello\n");
		const QString first = materialised(body_of(ncfg_hook_block(
		    QStringLiteral("post_up"), typed)));
		const QString second = materialised(body_of(ncfg_hook_block(
		    QStringLiteral("post_up"), first)));
		check(first == typed, "what is materialised is what was typed");
		check(second == first, "and saving what was loaded changes nothing");
		check(!second.contains(QStringLiteral("#!/bin/sh\n#!/bin/sh")),
		    "in particular the shebang is not stacked on every save");
	}

	/* The rule that makes a hook body irregular, said before the daemon has to
	 * say it in words about a line the operator wrote shell on. */
	{
		check(ncfg_hook_body_terminates_early(
		          QStringLiteral("#!/bin/sh\ngreet() {\n\techo hi\n}\ngreet\n")),
		    "a shell function over three lines ends the hook early");
		check(!ncfg_hook_body_terminates_early(
		          QStringLiteral("#!/bin/sh\ngreet() { echo hi; }\ngreet\n")),
		    "and the one-line form does not");
		/* Indented, and still the terminator: the lexer trims the line before
		 * comparing, so a tab in front of it changes nothing. */
		check(ncfg_hook_body_terminates_early(QStringLiteral("case $1 in\n\t}\nesac\n")),
		    "an indented lone brace ends it too, because the rule trims first");
	}

	if (failures == 0) {
		fprintf(stderr, "hook_block: all checks passed\n");
	} else {
		fprintf(stderr, "hook_block: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
