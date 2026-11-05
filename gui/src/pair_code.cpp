#include "pair_code.h"

#include <QList>
#include <QPainter>

/* What `ncfg_cli_pair_draw` starts a line with, and its three glyphs in UTF-8. */
static const char line_start[] = "\033[30;47m";

QImage ncfg_pair_code_image(const QByteArray &drawn, int scale)
{
	QList<QList<bool>> rows;

	for (const QByteArray &line : drawn.split('\n')) {
		if (!line.startsWith(line_start)) {
			if (rows.isEmpty()) {
				continue;
			}
			break;
		}
		const QString text = QString::fromUtf8(line.mid((int)sizeof(line_start) - 1));
		QList<bool>   top;
		QList<bool>   bottom;

		for (const QChar c : text) {
			if (c == QChar(0x1b)) {
				break;
			}
			top << (c == QChar(0x2588) || c == QChar(0x2580));
			bottom << (c == QChar(0x2588) || c == QChar(0x2584));
		}
		rows << top << bottom;
	}
	if (rows.isEmpty() || rows.first().isEmpty() || scale < 1) {
		return QImage();
	}
	const int width = (int)rows.first().size();
	QImage    image(width * scale, (int)rows.size() * scale, QImage::Format_RGB32);
	QPainter  painter(&image);

	image.fill(Qt::white);
	for (int y = 0; y < (int)rows.size(); y++) {
		for (int x = 0; x < width && x < (int)rows[y].size(); x++) {
			if (rows[y][x]) {
				painter.fillRect(x * scale, y * scale, scale, scale, Qt::black);
			}
		}
	}
	return image;
}
