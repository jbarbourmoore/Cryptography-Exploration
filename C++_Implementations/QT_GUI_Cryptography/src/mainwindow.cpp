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
    connect(ui->rsa_swap_out_button, SIGNAL(clicked()), this, SLOT(on_rsa_swap_output_button_clicked()));
    connect(ui->hash_button, SIGNAL(clicked()), this, SLOT(on_hash_button_clicked()));
    connect(ui->aes_key_gen_button, SIGNAL(clicked()), this, SLOT(on_aes_key_gen_clicked()));
    connect(ui->aes_iv_gen_button, SIGNAL(clicked()), this, SLOT(on_aes_iv_gen_clicked()));
    connect(ui->aes_swap_out_button, SIGNAL(clicked()), this, SLOT(on_aes_swap_output_button_clicked()));
    connect(ui->aes_encrypt_button, SIGNAL(clicked()), this, SLOT(on_aes_encrypt_clicked()));
    connect(ui->aes_decrypt_button, SIGNAL(clicked()), this, SLOT(on_aes_decrypt_clicked()));

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

double MainWindow::generateKeys(bool use_key_quintuple_form){

    int generation_type = ui->rsa_key_type_select->currentIndex();

    auto start = std::chrono::high_resolution_clock::now();
    if ( generation_type == 3){
        rsa_keys_ = key_gen_.generateRSAKeysUsingProvablePrimes(use_key_quintuple_form);
    } else if ( generation_type == 4){
        rsa_keys_ = key_gen_.generateRSAKeysUsingProvablePrimesWithAuxPrimes(200, 200, 200, 200, use_key_quintuple_form);
    } else if ( generation_type == 0){
        rsa_keys_ = key_gen_.generateRSAKeysUsingProbablePrimes(-1,-1,use_key_quintuple_form);
    } else if ( generation_type == 2){
        rsa_keys_ = key_gen_.generateRSAKeysUsingProbablePrimesWithProvableAux(-1,-1, 200, 200, 200, 200, use_key_quintuple_form);
    } else if ( generation_type == 1){
        rsa_keys_ = key_gen_.generateRSAKeysUsingProbablePrimesWithProbableAux(-1,-1, 200, 200, 200, 200, use_key_quintuple_form);
    } else {
        throw exception();
    }
    auto stop = std::chrono::high_resolution_clock::now();

    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
    int duration_in_nanoseconds = std::chrono::duration_cast<std::chrono::microseconds>(duration).count();
    double generation_seconds = abs( duration_in_nanoseconds / 1000000.0);
    return generation_seconds;
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
    double generation_seconds = generateKeys(use_quint_form);
    char buffer[35];
    sprintf(buffer, "Duration: %10.5lf seconds", generation_seconds);
    std::string result_string(buffer);
    ui->last_dur_label->setText(result_string.c_str());
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
    QString input_qstring = ui->hash_in_text->toPlainText();
    if(input_qstring.isEmpty()){
        const char *input = "Please enter a string to hash";
        ui->sha1_digest_text->setPlainText(input);
    }
    else{
        std::string hash_digest = "";
        hash_digest = CreateHashDigest::fromString(input_qstring.toStdString(),HashType::SHA1_DIGEST);
        ui->sha1_digest_text->setPlainText(hash_digest.c_str());
        hash_digest = CreateHashDigest::fromString(input_qstring.toStdString(),HashType::SHA224_DIGEST);
        ui->sha224_digest_text->setPlainText(hash_digest.c_str());
        hash_digest = CreateHashDigest::fromString(input_qstring.toStdString(),HashType::SHA256_DIGEST);
        ui->sha256_digest_text->setPlainText(hash_digest.c_str());
        hash_digest = CreateHashDigest::fromString(input_qstring.toStdString(),HashType::SHA384_DIGEST);
        ui->sha382_digest_text->setPlainText(hash_digest.c_str());
        hash_digest = CreateHashDigest::fromString(input_qstring.toStdString(),HashType::SHA512_DIGEST);
        ui->sha512_digest_text->setPlainText(hash_digest.c_str());
        hash_digest = CreateHashDigest::fromString(input_qstring.toStdString(),HashType::SHA512_224_DIGEST);
        ui->sha512_224_digest_text->setPlainText(hash_digest.c_str());
        hash_digest = CreateHashDigest::fromString(input_qstring.toStdString(),HashType::SHA512_256_DIGEST);
        ui->sha512_256_digest_text->setPlainText(hash_digest.c_str());
    }
}

void MainWindow::on_rsa_swap_output_button_clicked(){
    QString input_qstring = ui->rsa_out_text->toPlainText();
    ui->rsa_in_text->setPlainText(input_qstring);
}

void MainWindow::on_aes_swap_output_button_clicked(){
    QString input_qstring = ui->aes_out_text->toPlainText();
    ui->aes_in_text->setPlainText(input_qstring);
}

string MainWindow::getRandom(int bits){
    BIGNUM *new_rand = BN_new();
    BN_rand(new_rand, bits, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
    char *output = BN_bn2hex(new_rand);
    string random = string(output);
    BN_clear_free(new_rand);
    return random;
}

void MainWindow::on_aes_key_gen_clicked(){
    int bits = getSelectedBits();
    string new_key = getRandom(bits);
    ui->aes_key_text->setText(new_key.c_str());
}

void MainWindow::on_aes_iv_gen_clicked(){
    int bits = 128;
    string new_iv = getRandom(bits);
    ui->aes_iv_text->setText(new_iv.c_str());
}

int MainWindow::getSelectedBits(){
    int bits = 128;
    int key_length_selected = ui->aes_key_length_select->currentIndex();
    if(key_length_selected == 1){
        bits = 192;
    }else if(key_length_selected == 2){
        bits = 256;
    }
    return bits;
}

void MainWindow::on_aes_encrypt_clicked(){
    int bits = getSelectedBits();
    QString aes_key = ui->aes_key_text->text();
    QString aes_in = ui->aes_in_text->toPlainText();
    QString aes_iv = ui->aes_iv_text->text();
    int aes_mode = ui->aes_mode_select->currentIndex();
    string result ="Error";
    if (bits == 128){
        if(aes_mode == 0){
            if(aes_key.size() != 32){
                result = "Please enter appropriate length values for key";
            } else{
                vector<AESDataBlock> datablock = AES_ECB::AES128Cypher(aes_in.toStdString(), aes_key.toStdString());
                result = AESDataBlock::hexStringFromDataBlocks(datablock);
            }
        } else if (aes_mode == 1){
            if(aes_key.size() != 32 || aes_iv.size() != 32){
                result = "Please enter appropriate length values for key and initialization vector";
            } else{
                vector<AESDataBlock> datablock = AES_CBC::AES128Cypher(aes_in.toStdString(), aes_key.toStdString(), aes_iv.toStdString());
                result = AESDataBlock::hexStringFromDataBlocks(datablock);

            }
        }
    }else if (bits == 192){
        if(aes_mode == 0){
            if(aes_key.size() != 48 ){
                result = "Please enter appropriate length values for key";
            } else{
                vector<AESDataBlock> datablock = AES_ECB::AES192Cypher(aes_in.toStdString(), aes_key.toStdString());
                result = AESDataBlock::hexStringFromDataBlocks(datablock);

            }
        } else if (aes_mode == 1){
            if(aes_key.size() != 48 || aes_iv.size() != 32){
                result = "Please enter appropriate length values for key and initialization vector";
            } else{
                vector<AESDataBlock> datablock = AES_CBC::AES192Cypher(aes_in.toStdString(), aes_key.toStdString(), aes_iv.toStdString());
                result = AESDataBlock::hexStringFromDataBlocks(datablock);

            }
        }
    } else{
        if(aes_mode == 0){
            if(aes_key.size() != 64){
                result = "Please enter appropriate length values for key";
            } else{
                vector<AESDataBlock> datablock = AES_ECB::AES256Cypher(aes_in.toStdString(), aes_key.toStdString());
                result = AESDataBlock::hexStringFromDataBlocks(datablock);

            }
        } else if (aes_mode == 1){
            if(aes_key.size() != 64 || aes_iv.size() != 32){
                result = "Please enter appropriate length values for key and initialization vector";
            } else{
                vector<AESDataBlock> datablock = AES_CBC::AES256Cypher(aes_in.toStdString(), aes_key.toStdString(), aes_iv.toStdString());
                result = AESDataBlock::hexStringFromDataBlocks(datablock);
            }
        }
    }
    ui->aes_out_text->setPlainText(result.c_str());
}

void MainWindow::on_aes_decrypt_clicked(){
    int bits = getSelectedBits();
    QString aes_key = ui->aes_key_text->text();
    QString aes_in = ui->aes_in_text->toPlainText();
    QString aes_iv = ui->aes_iv_text->text();
    int aes_mode = ui->aes_mode_select->currentIndex();
    string result ="";
    if (bits == 128){
        if(aes_mode == 0){
            if(aes_key.size() != 32){
                result = "Please enter appropriate length values for key";
            } else{
                vector<AESDataBlock> datablock = AES_ECB::AES128InvCypher(aes_in.toStdString(), aes_key.toStdString());
                result = AESDataBlock::hexStringFromDataBlocks(datablock);
            }
        } else if (aes_mode == 1){
            if(aes_key.size() != 32 || aes_iv.size() != 32){
                result = "Please enter appropriate length values for key and initialization vector";
            } else{
                vector<AESDataBlock> datablock = AES_CBC::AES128InvCypher(aes_in.toStdString(), aes_key.toStdString(), aes_iv.toStdString());
                result = AESDataBlock::hexStringFromDataBlocks(datablock);

            }
        }
    }else if (bits == 192){
        if(aes_mode == 0){
            if(aes_key.size() != 48 ){
                result = "Please enter appropriate length values for key";
            } else{
                vector<AESDataBlock> datablock = AES_ECB::AES192InvCypher(aes_in.toStdString(), aes_key.toStdString());
                result = AESDataBlock::hexStringFromDataBlocks(datablock);

            }
        } else if (aes_mode == 1){
            if(aes_key.size() != 48 || aes_iv.size() != 32){
                result = "Please enter appropriate length values for key and initialization vector";
            } else{
                vector<AESDataBlock> datablock = AES_CBC::AES192InvCypher(aes_in.toStdString(), aes_key.toStdString(), aes_iv.toStdString());
                result = AESDataBlock::hexStringFromDataBlocks(datablock);

            }
        }
    } else{
        if(aes_mode == 0){
            if(aes_key.size() != 64){
                result = "Please enter appropriate length values for key";
            } else{
                vector<AESDataBlock> datablock = AES_ECB::AES256InvCypher(aes_in.toStdString(), aes_key.toStdString());
                result = AESDataBlock::hexStringFromDataBlocks(datablock);

            }
        } else if (aes_mode == 1){
            if(aes_key.size() != 64 || aes_iv.size() != 32){
                result = "Please enter appropriate length values for key and initialization vector";
            } else{
                vector<AESDataBlock> datablock = AES_CBC::AES256InvCypher(aes_in.toStdString(), aes_key.toStdString(), aes_iv.toStdString());
                result = AESDataBlock::hexStringFromDataBlocks(datablock);

            }
        }
    }
    ui->aes_out_text->setPlainText(result.c_str());
}