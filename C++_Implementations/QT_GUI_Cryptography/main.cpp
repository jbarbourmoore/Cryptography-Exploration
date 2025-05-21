#include "mainwindow.h"
#include "RSAKeyGeneration.hpp"

#include <QApplication>

int main(int argc, char *argv[])
{

    RSAKeyGeneration key_gen = RSAKeyGeneration(2048);
    QApplication a(argc, argv);
    MainWindow w;
    w.show();
    return a.exec();
}
