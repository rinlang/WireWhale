#include <QApplication>
#include <QPushButton>
#include "main_window.h"


int main(int argc, char *argv[]) {
    QApplication a(argc, argv);
    MainWindow w;
    w.show();
    return QApplication::exec();
}
