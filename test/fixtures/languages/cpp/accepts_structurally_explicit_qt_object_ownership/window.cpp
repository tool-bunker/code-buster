notifier = new QSocketNotifier(fd, QSocketNotifier::Read, this);
QAction *action = new QAction(parent);
QCheckBox *sendReport = new QCheckBox("Send report");
dialog.setCheckBox(sendReport);
QImage *image = new QImage();
Worker *worker = new Worker(parent);
QWidget *orphan = new QWidget();
