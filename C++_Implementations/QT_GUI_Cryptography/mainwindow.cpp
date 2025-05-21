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
    key_gen_.freeKeyGeneration();
    rsa_keys_.private_key_.freeKey();
    rsa_keys_.public_key_.freeKey();
    delete ui;
}

void MainWindow::updateKeyLength(){
    int key_length_selected = ui->rsa_nlen_select->currentIndex();
    int key_length = 2048;
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
    if (key_gen_.getKeyLength() != key_length){
        key_gen_.setKeyLength(key_length);
    }
}
void MainWindow::on_generate_button_clicked(){
    
    bool use_quint_form = false;
    int key_form_selected = ui->rsa_key_type_select->currentIndex();
    if(key_form_selected == 1){
        use_quint_form = true;
    }
    updateKeyLength();

    rsa_keys_.private_key_.freeKey();
    rsa_keys_.public_key_.freeKey();
    rsa_keys_ = key_gen_.generateRSAKeysUsingProbablePrimes(-1,-1,use_quint_form);
    ui->n_text->setPlainText(rsa_keys_.private_key_.getHexN());
    ui->d_text->setPlainText(rsa_keys_.private_key_.getHexD());
    ui->e_text->setPlainText(rsa_keys_.public_key_.getHexE());
    if(use_quint_form){
        ui->text_p->setPlainText(rsa_keys_.private_key_.getHexP());
        ui->text_q->setPlainText(rsa_keys_.private_key_.getHexQ());
        ui->text_dP->setPlainText(rsa_keys_.private_key_.getHexdP());
        ui->text_dQ->setPlainText(rsa_keys_.private_key_.getHexdQ());
        ui->text_qInv->setPlainText(rsa_keys_.private_key_.getHexqInv());
    } else{
        ui->text_p->setPlainText("'p' is only part of private keys when using the quintuple form");
        ui->text_q->setPlainText("'q' is only part of private keys when using the quintuple form");
        ui->text_dP->setPlainText("'dP' is only part of private keys when using the quintuple form");
        ui->text_dQ->setPlainText("'dQ' is only part of private keys when using the quintuple form");
        ui->text_qInv->setPlainText("'qInv' is only part of private keys when using the quintuple form");
    }
}

void MainWindow::on_encrypt_button_clicked(){
    if(rsa_keys_.success_ == false){
        ui->rsa_out_text->setPlainText("You must generate RSA Keys to begin");
    }else{
        QString input_qstring = ui->rsa_in_text->toPlainText();
        if(input_qstring.isEmpty()){
            ui->rsa_out_text->setPlainText("Please enter a hexdecimal value to encrypt");
        }
        char *encrypted_message = rsa_keys_.public_key_.encryptionPrimitive(input_qstring.toStdString().c_str());
        ui->rsa_out_text->setPlainText(encrypted_message);
    }
}
void MainWindow::on_decrypt_button_clicked(){
    if(rsa_keys_.success_ == false){
        ui->rsa_out_text->setPlainText("You must generate RSA Keys to begin");
    }else{
        QString input_qstring = ui->rsa_in_text->toPlainText();
        if(input_qstring.isEmpty()){
            ui->rsa_out_text->setPlainText("Please enter a hexdecimal value to decrypt");
        }
        char *decrypted_message = rsa_keys_.private_key_.decryptionPrimitive(input_qstring.toStdString().c_str());
        ui->rsa_out_text->setPlainText(decrypted_message);
    }
}
void MainWindow::on_hash_button_clicked(){

}