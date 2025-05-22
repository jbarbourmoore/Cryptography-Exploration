#include "mainwindow.h"
#include <QStyle>
#include <QApplication>
#include <QFile>

int main(int argc, char *argv[])
{

    RSAKeyGeneration key_gen = RSAKeyGeneration(2048);
    QApplication a(argc, argv);
    QFile styleFile( ":/style.qss" );
    styleFile.open( QFile::ReadOnly );

    // Apply the loaded stylesheet
    QString style( styleFile.readAll() );
    a.setStyleSheet(style);
    MainWindow w;
    w.showNormal();
    return a.exec();
}
