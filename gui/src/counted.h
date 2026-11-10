/*
 * counted.h -- "1 rule", "2 rules" (10.781).
 *
 * Every view's status line said `%1 rules`, so a machine with one said "1
 * rules". English only, as every other string in this program is; header-only
 * so that each view and probe has it without a source file to add.
 */
#ifndef NCFG_COUNTED_H
#define NCFG_COUNTED_H

#include <QString>

inline QString ncfg_counted(qsizetype count, const char *one, const char *many)
{
	return QStringLiteral("%1 %2").arg(count).arg(QString::fromLatin1(count == 1 ? one : many));
}

#endif
