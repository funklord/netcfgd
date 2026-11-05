#include "code_reader.h"

#include <QElapsedTimer>
#include <QGuiApplication>
#include <QTimer>

#ifdef Q_OS_ANDROID
#include <QCamera>
#include <QCameraDevice>
#include <QMediaCaptureSession>
#include <QMediaDevices>
#include <QPermissions>
#include <QVideoFrame>
#include <QVideoSink>
#endif

#include <cstring>

extern "C" {
#include "quirc.h"
}

/* A phone's camera gives far more pixels than a code needs, and recognition
 * costs in proportion to them. */
static const int widest_frame = 960;

/* A look at most this often, in ms: the frames arrive on the GUI thread. */
static const int look_every = 80;

/* Ticks of 100 ms: long enough to aim, short enough that a phone left on a
 * table does not hold the camera. */
static const int ticks_max = 300;

QByteArray ncfg_code_reader::read_image(const QImage &image)
{
	if (image.isNull()) {
		return QByteArray();
	}
	QImage grey = image.convertToFormat(QImage::Format_Grayscale8);

	if (grey.width() > widest_frame) {
		grey = grey.scaledToWidth(widest_frame, Qt::SmoothTransformation);
	}
	struct quirc *reader = quirc_new();
	QByteArray    found;

	if (!reader || quirc_resize(reader, grey.width(), grey.height()) < 0) {
		quirc_destroy(reader);
		return found;
	}
	int      width = 0;
	int      height = 0;
	uint8_t *pixels = quirc_begin(reader, &width, &height);

	/* Row by row: a QImage row is padded to 32 bits and quirc's is not. */
	for (int y = 0; y < height; y++) {
		memcpy(pixels + (size_t)y * (size_t)width, grey.constScanLine(y), (size_t)width);
	}
	quirc_end(reader);
	for (int at = 0; at < quirc_count(reader) && found.isEmpty(); at++) {
		static struct quirc_code code;
		static struct quirc_data data;

		quirc_extract(reader, at, &code);
		if (quirc_decode(&code, &data) == QUIRC_SUCCESS) {
			found = QByteArray(reinterpret_cast<const char *>(data.payload), data.payload_len);
		}
	}
	quirc_destroy(reader);
	return found;
}

ncfg_code_reader::ncfg_code_reader(QObject *parent) : QObject(parent)
{
	timer = new QTimer(this);
	timer->setInterval(100);
	connect(timer, &QTimer::timeout, this, &ncfg_code_reader::tick);
	connect(qGuiApp, &QGuiApplication::applicationStateChanged, this,
	        [this](Qt::ApplicationState state) {
		        if (state != Qt::ApplicationActive && running()) {
			        stop(QStringLiteral("Stopped: the app went to the background."));
		        }
	        });
}

ncfg_code_reader::~ncfg_code_reader()
{
	stop();
}

bool ncfg_code_reader::running() const
{
	return camera != nullptr;
}

void ncfg_code_reader::look(const QImage &frame)
{
	const QByteArray code = read_image(frame);

	frames++;
	if (!code.isEmpty()) {
		stop(QStringLiteral("Code read."));
		emit code_read(code);
	}
}

void ncfg_code_reader::tick()
{
	ticks++;
	if (ticks % 10 == 0) {
		emit status(QStringLiteral("Looked at %1 frames.").arg(frames));
	}
	if (ticks > ticks_max) {
		stop(QStringLiteral("No code found. Move closer, and press Scan again."));
	}
}

void ncfg_code_reader::start()
{
#ifdef Q_OS_ANDROID
	if (running()) {
		return;
	}
	QCameraPermission permission;

	/* Asked at the press, so the question arrives with its reason in view. A
	 * refusal leaves the typed code. */
	switch (qApp->checkPermission(permission)) {
	case Qt::PermissionStatus::Undetermined:
		qApp->requestPermission(permission, this, [this](const QPermission &answer) {
			if (answer.status() == Qt::PermissionStatus::Granted) {
				start();
			} else {
				emit status(QStringLiteral("No camera allowed. Type the code below instead."));
			}
		});
		return;
	case Qt::PermissionStatus::Denied:
		emit status(QStringLiteral("The camera is off for this app. Allow it in the phone's "
		                           "settings, or type the code below."));
		return;
	case Qt::PermissionStatus::Granted:
		break;
	}
	QCameraDevice device = QMediaDevices::defaultVideoInput();

	/* The back camera: the one a person points at a screen. */
	for (const QCameraDevice &candidate : QMediaDevices::videoInputs()) {
		if (candidate.position() == QCameraDevice::BackFace) {
			device = candidate;
			break;
		}
	}
	if (device.isNull()) {
		emit status(QStringLiteral("This phone has no camera. Type the code below."));
		return;
	}
	camera = new QCamera(device, this);
	capture = new QMediaCaptureSession(this);
	sink = new QVideoSink(this);
	capture->setCamera(camera);
	capture->setVideoSink(sink);
	last_look = 0;
	connect(sink, &QVideoSink::videoFrameChanged, this, [this](const QVideoFrame &frame) {
		static QElapsedTimer clock;

		if (!clock.isValid()) {
			clock.start();
		}
		if (!camera || clock.elapsed() - last_look < look_every) {
			return;
		}
		last_look = clock.elapsed();
		look(frame.toImage());
	});
	frames = 0;
	ticks = 0;
	camera->start();
	timer->start();
	emit running_changed(true);
	emit status(QStringLiteral("Hold the phone up to the code."));
#else
	emit status(QStringLiteral("This build reads no camera. Type the code below."));
#endif
}

void ncfg_code_reader::stop(const QString &why)
{
	const bool was = running();

	timer->stop();
#ifdef Q_OS_ANDROID
	if (camera) {
		camera->stop();
		camera->deleteLater();
		camera = nullptr;
	}
	if (capture) {
		capture->deleteLater();
		capture = nullptr;
	}
	if (sink) {
		sink->disconnect(this);
		sink->deleteLater();
		sink = nullptr;
	}
#endif
	if (was) {
		emit running_changed(false);
	}
	if (!why.isEmpty()) {
		emit status(why);
	}
}
