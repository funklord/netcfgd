/*
 * phone_node.h -- the phone's fuzznet node: a fuzznetd the app starts
 * (project.md 10.720).
 *
 * WHY THE APP STARTS IT
 *   The client reaches another host through this user's own node, by
 *   `call ask at HOST` on its socket. A desktop has one running. A phone has
 *   no place for a long-lived program but an app, so the app carries one, as
 *   `libfuzznetd.so`: Android extracts and marks executable only `lib*.so`.
 *   It stays a separate process, so everything above the socket is the
 *   desktop's code.
 *
 * WHY NO SERVICE
 *   fuzzypickles keeps its node up with the app gone, because messages arrive.
 *   Nothing arrives for this one: a person opens the app to look at a network.
 *   So the node is a child that goes with the app.
 *
 * XDG_RUNTIME_DIR
 *   Set here to a directory in the app's own storage, which is what makes
 *   `ncfg_fuzznet_user_socket` name this node for every caller in the process.
 */
#ifndef NCFG_GUI_PHONE_NODE_H
#define NCFG_GUI_PHONE_NODE_H

#include <QString>

class QObject;

/* Under `base`: the store, and the run directory, both made 0700 and the
 * latter put in XDG_RUNTIME_DIR. A node already answering is the node: Android
 * brings an activity back into a process it kept. The start is bounded; false
 * with a sentence in `why` where no node answered within it. */
bool ncfg_phone_node_start(const QString &program, const QString &base, QObject *owner,
                           QString *why);

#endif
