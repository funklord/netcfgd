/*
 * rule_block.cpp -- the configuration the rule editor writes.
 *
 * WHY THIS EXISTS
 *   A rule is selectors and an action, and both halves have a way of going
 *   wrong that a screenshot cannot show: a selector dropped widens the rule to
 *   traffic it was never meant to catch, and a zero written as an absence
 *   changes what it matches. `fwmark 0` and `suppress_prefixlength 0` are both
 *   legal and both mean something.
 */
#include "../src/rule_dialog.h"

#include <QCoreApplication>
#include <QString>
#include <cstdio>

static int failures;

static void check(bool condition, const char *what)
{
	fprintf(stderr, "rule_block: %-56s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

int main(int argc, char **argv)
{
	QCoreApplication app(argc, argv);

	{
		ncfg_rule_row vpn;
		vpn.id = QStringLiteral("vpn");
		vpn.priority = 100;
		vpn.family = QStringLiteral("inet");
		vpn.from = QStringLiteral("10.9.0.0/24");
		vpn.iif = QStringLiteral("wg0");
		vpn.action = QStringLiteral("lookup");
		vpn.table = QStringLiteral("42");
		const QString block = ncfg_rule_block(vpn);

		check(block.contains(QStringLiteral("rule \"vpn\" {")), "the block is named");
		check(block.contains(QStringLiteral("priority = 100")),
		    "and carries the priority, which is its identity to the kernel");
		check(block.contains(QStringLiteral("from = \"10.9.0.0/24\"")) &&
		        block.contains(QStringLiteral("iif = \"wg0\"")),
		    "and every selector that was set");
		check(!block.contains(QStringLiteral("to =")) &&
		        !block.contains(QStringLiteral("oif =")),
		    "and none that was not");
		check(block.contains(QStringLiteral("lookup = 42")),
		    "a lookup names the table it consults");
		/* The family is written both ways rather than only for IPv6: it is not
		 * inferable from the selectors, so leaving it out would make IPv4 a
		 * choice by omission. */
		check(block.contains(QStringLiteral("family = \"inet\"")),
		    "and the family is stated rather than left to the default");
	}

	/* The three actions that consult nothing. A table beside one of them would
	 * be a number the kernel ignores and a reader has to explain away. */
	{
		ncfg_rule_row drop;
		drop.id = QStringLiteral("drop6");
		drop.priority = 200;
		drop.family = QStringLiteral("inet6");
		drop.to = QStringLiteral("2001:db8::/32");
		drop.action = QStringLiteral("blackhole");
		drop.table = QStringLiteral("100");
		const QString block = ncfg_rule_block(drop);
		check(block.contains(QStringLiteral("action = \"blackhole\"")),
		    "an action that stops there says so");
		check(!block.contains(QStringLiteral("lookup")),
		    "and names no table, which it would not consult");
	}

	/* **Zero is a value, and `none` is not zero.** Both of these are legal and
	 * both mean something: a rule on `fwmark 0`, and the suppression that
	 * drops a table's default route. */
	{
		ncfg_rule_row marked;
		marked.id = QStringLiteral("marked");
		marked.priority = 300;
		marked.family = QStringLiteral("inet");
		marked.action = QStringLiteral("lookup");
		marked.table = QStringLiteral("7");
		marked.fwmark = 0;
		marked.suppress_prefixlength = 0;
		const QString block = ncfg_rule_block(marked);
		check(block.contains(QStringLiteral("fwmark = 0")),
		    "a firewall mark of zero is written, because zero is a mark");
		check(block.contains(QStringLiteral("suppress_prefixlength = 0")),
		    "and so is a suppression of zero, which drops a default route");

		marked.fwmark = -1;
		marked.suppress_prefixlength = -1;
		const QString bare = ncfg_rule_block(marked);
		check(!bare.contains(QStringLiteral("fwmark")) &&
		        !bare.contains(QStringLiteral("suppress_prefixlength")),
		    "while absent is absent and writes neither");
	}

	/* A VRF rule, which matches on membership rather than on an address. */
	{
		ncfg_rule_row vrf;
		vrf.id = QStringLiteral("vrf");
		vrf.priority = 400;
		vrf.family = QStringLiteral("inet");
		vrf.action = QStringLiteral("lookup");
		vrf.table = QStringLiteral("254");
		vrf.l3mdev = true;
		check(ncfg_rule_block(vrf).contains(QStringLiteral("l3mdev = true")),
		    "a rule can match packets belonging to a VRF master");
	}

	if (failures == 0) {
		fprintf(stderr, "rule_block: all checks passed\n");
	} else {
		fprintf(stderr, "rule_block: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
