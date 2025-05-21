#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "RSAKeyGeneration.hpp"
#include <QMainWindow>

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_generate_button_clicked();
    void on_encrypt_button_clicked();
    void on_decrypt_button_clicked();
    void on_hash_button_clicked();

private:
    RSAKeyGeneration key_gen_;
    Ui::MainWindow *ui;
};
#endif // MAINWINDOW_H
