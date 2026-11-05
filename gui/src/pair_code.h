/*
 * pair_code.h -- the code `ncfg pair` draws, as a picture (project.md 10.724).
 *
 * The desktop's window shows the code by reading what `ncfg pair` printed, half
 * blocks and all: `ncfg` is what can reach the node's verbs, as root, and this way
 * the window needs no encoder of its own and cannot show a code other than the one
 * issued.
 */
#ifndef NCFG_GUI_PAIR_CODE_H
#define NCFG_GUI_PAIR_CODE_H

#include <QByteArray>
#include <QImage>

/* The modules in `drawn`, `ncfg pair`'s output up to its first plain line, as a
 * black on white image of `scale` pixels a module. Null where there are none. */
QImage ncfg_pair_code_image(const QByteArray &drawn, int scale);

#endif
