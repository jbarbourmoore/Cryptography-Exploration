#include "mainwindow.h"
#include "./ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    connect(ui->rsa_key_gen_button, SIGNAL(clicked()), this, SLOT(on_generate_button_clicked()));
    connect(ui->rsa_encrypt_button, SIGNAL(clicked()), this, SLOT(on_encrypt_button_clicked()));
    connect(ui->rsa_decrypt_button, SIGNAL(clicked()), this, SLOT(on_decrypt_button_clicked()));
    connect(ui->hash_button, SIGNAL(clicked()), this, SLOT(on_hash_button_clicked()));
}

MainWindow::~MainWindow()
{
    delete ui;
}
void MainWindow::on_generate_button_clicked(){
    int key_length_selected = ui->rsa_nlen_select->currentIndex();
    int key_length = 2048;
    bool use_quint_form = false;
    int key_form_selected = ui->rsa_key_type_select->currentIndex();
    if(key_form_selected == 1){
        use_quint_form = true;
    }
    switch(key_length_selected){
        case 0:{
            key_length = 2048;
            break;
        }
        case 1 : {
            key_length = 3072;
            break;
        }
        case 2 : {
            key_length = 7680;
            break;
        }
        case 3 :{
            key_length = 15360;
            break;
        }
    }
    
    RSAKeyGenerationResult rsa_keys = key_gen_.generateRSAKeysUsingProbablePrimes();
    ui->n_text->setPlainText(rsa_keys.private_key_.getHexN());
    ui->d_text->setPlainText(rsa_keys.private_key_.getHexD());
    ui->e_text->setPlainText(rsa_keys.public_key_.getHexE());
}

void MainWindow::on_encrypt_button_clicked(){

}
void MainWindow::on_decrypt_button_clicked(){

}
void MainWindow::on_hash_button_clicked(){

}