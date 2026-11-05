#include "phone_node.h"

extern "C" {
#include "ncfg_fuzznet.h"
}

#include <QDir>
#include <QFile>
#include <QProcess>
#include <QThread>

#include <sys/stat.h>

/* The peer port. The phone starts every conversation, so nothing has to find
 * it here: it is fixed only because fuzznetd asks for one. */
static const int phone_udp_port = 48090;

/* Two hundred looks, 50 ms apart: ten seconds. A first start makes keys. */
static const int start_looks = 200;

static bool private_directory(const QString &path)
{
	return QDir().mkpath(path) && chmod(QFile::encodeName(path).constData(), 0700) == 0;
}

static bool node_answers(const char *socket)
{
	char reply[256];
	char why[256];
	int  silent = 0;

	return ncfg_fuzznet_ask(socket, "status", reply, sizeof(reply), 1000, &silent, why,
	                        sizeof(why)) != 0;
}

bool ncfg_phone_node_start(const QString &program, const QString &base, QObject *owner,
                           QString *why)
{
	const QString store = base + QStringLiteral("/node");
	const QString run = base + QStringLiteral("/run");
	char          socket[1100];

	if (!private_directory(store) || !private_directory(run)) {
		if (why) {
			*why = QStringLiteral("could not make the node's directories under %1").arg(base);
		}
		return false;
	}
	qputenv("XDG_RUNTIME_DIR", QFile::encodeName(run));
	if (!ncfg_fuzznet_user_socket(socket, sizeof(socket))) {
		if (why) {
			*why = QStringLiteral("the node's socket path is too long");
		}
		return false;
	}
	if (node_answers(socket)) {
		return true;
	}

	/* A child of `owner`, so it goes with the app. Its output is dropped, not
	 * kept: a log nobody rotates in a phone's storage has no bound, and what
	 * the client needs of the node it asks on the socket. */
	QProcess *node = new QProcess(owner);

	node->setProgram(program);
	node->setArguments({QStringLiteral("--fuzznet-dir=%1").arg(store),
	                    QStringLiteral("--no-log-file"),
	                    QStringLiteral("--udp-port=%1").arg(phone_udp_port),
	                    QStringLiteral("--fuzznet-service=%1").arg(NCFG_FUZZNET_SERVICE),
	                    QStringLiteral("--fuzznet-product=%1").arg(NCFG_FUZZNET_PRODUCT)});
	node->setStandardOutputFile(QProcess::nullDevice());
	node->setStandardErrorFile(QProcess::nullDevice());
	node->start();
	if (!node->waitForStarted(5000)) {
		if (why) {
			*why = QStringLiteral("the node would not start: %1").arg(node->errorString());
		}
		return false;
	}
	for (int look = 0; look < start_looks; look++) {
		if (node_answers(socket)) {
			return true;
		}
		if (node->state() == QProcess::NotRunning) {
			break;
		}
		QThread::msleep(50);
	}
	if (why) {
		*why = QStringLiteral("the node started and never answered");
	}
	return false;
}

bool ncfg_phone_node_forget(const QString &base, QObject *owner, QString *why)
{
	for (QProcess *node : owner->findChildren<QProcess *>(Qt::FindDirectChildrenOnly)) {
		node->kill();
		node->waitForFinished(3000);
		delete node;
	}
	/* A node kept from before this process, which it holds no handle on, is
	 * stopped by the app's own process going; the store is what matters here. */
	QDir store(base + QStringLiteral("/node"));

	if (store.exists() && !store.removeRecursively()) {
		if (why) {
			*why = QStringLiteral("the node's store would not go: %1").arg(store.path());
		}
		return false;
	}
	return true;
}
