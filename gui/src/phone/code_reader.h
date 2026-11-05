/*
 * code_reader.h -- a pairing code read off a camera (project.md 10.720).
 *
 * On a phone the first thing a person does is point it at a host's screen, so
 * this is the app's front door. Qt Multimedia gives the frames and quirc reads
 * them. No preview: a preview is a second render path, and what keeps this from
 * looking hung is saying how many frames it has looked at, so "not aimed yet" is
 * told apart from "not working". fuzzypickles' `card_scanner` found that shape.
 *
 * `read_image` is the whole recogniser and needs no camera, so a probe can hold
 * it to a code this project drew. The camera half is Android's alone: a desktop
 * joins by the typed code.
 */
#ifndef NCFG_GUI_CODE_READER_H
#define NCFG_GUI_CODE_READER_H

#include <QByteArray>
#include <QImage>
#include <QObject>
#include <QString>

class QCamera;
class QMediaCaptureSession;
class QTimer;
class QVideoSink;

class ncfg_code_reader : public QObject {
	Q_OBJECT

public:
	explicit ncfg_code_reader(QObject *parent = nullptr);
	~ncfg_code_reader() override;

	bool running() const;

	/* The text of the first code in `image`, or empty. */
	static QByteArray read_image(const QImage &image);

public slots:
	void start();
	/* Idempotent, and the one path that lets the camera go: one left open is
	 * no use to any other app until this one exits. */
	void stop(const QString &why = QString());

signals:
	void code_read(const QByteArray &code);
	void status(const QString &sentence);
	void running_changed(bool running);

private:
	void look(const QImage &frame);
	void tick();

	QTimer               *timer = nullptr;
	QCamera              *camera = nullptr;
	QMediaCaptureSession *capture = nullptr;
	QVideoSink           *sink = nullptr;
	qint64                last_look = 0;
	int                   frames = 0;
	int                   ticks = 0;
};

#endif
