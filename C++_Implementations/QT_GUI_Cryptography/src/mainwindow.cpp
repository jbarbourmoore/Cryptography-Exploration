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

        hash_digest = SHA3_224::hashAsHex(input_qstring.toStdString());
        hash_digest = addSpacing(hash_digest);

        ui->sha3_224_digest_text->setPlainText(hash_digest.c_str());
        hash_digest = SHA3_256::hashAsHex(input_qstring.toStdString());
        hash_digest = addSpacing(hash_digest);

        ui->sha3_256_digest_text->setPlainText(hash_digest.c_str());
        hash_digest = SHA3_384::hashAsHex(input_qstring.toStdString());
        hash_digest = addSpacing(hash_digest);

        ui->sha3_384_digest_text->setPlainText(hash_digest.c_str());
        hash_digest = SHA3_512::hashAsHex(input_qstring.toStdString());
        hash_digest = addSpacing(hash_digest);
        ui->sha3_512_digest_text->setPlainText(hash_digest.c_str());

    }
}

std::string MainWindow::addSpacing(std::string input){
    int segments = input.size()/16;
    std::string output = "";
    int segment_length = 16;
    for (int i = 0 ; i < segments ; i++) {
        if(input.size() - i * 16 < 16){
            segment_length = input.size() - i * 16;
        }
        output.append(input.substr(i * 16, segment_length));
        output.append(" ");
    }
    return output;
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

QString MainWindow::getInputAndPad(){
    QString aes_in = ui->aes_in_text->toPlainText();
    if (aes_in.size() % 32 != 0){
        aes_is_padded = true;
        aes_in.append("8");
        int to_add = 32 - (aes_in.size() % 32);
        for (int i = 0; i < to_add; i ++){
            aes_in.append("0");
        }
    } else {
        aes_is_padded = false;
    }
    // ui->aes_in_text->setPlainText(aes_in);
    return aes_in;
}

QString MainWindow::removePadding(QString aes_out){
    if (aes_is_padded){
        int end_index = aes_out.lastIndexOf("8");
        int pad_length = aes_out.size()-end_index;
        aes_out.remove(end_index, pad_length);
    }
    return aes_out;
}

void MainWindow::on_aes_encrypt_clicked(){
    int bits = getSelectedBits();
    QString aes_key = ui->aes_key_text->text();
    QString aes_in = getInputAndPad();
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
        } else {
            if(aes_key.size() != 32 || aes_iv.size() != 32){
                result = "Please enter appropriate length values for key and initialization vector";
            } else{
                vector<AESDataBlock> datablock;
                if (aes_mode == 1){
                    datablock = AES_CBC::AES128Cypher(aes_in.toStdString(), aes_key.toStdString(), aes_iv.toStdString());
                } else if (aes_mode == 2){
                    datablock = AES_CFB::AES128Cypher(aes_in.toStdString(), aes_key.toStdString(), aes_iv.toStdString(), 1);
                } else if (aes_mode == 3){
                    datablock = AES_CFB::AES128Cypher(aes_in.toStdString(), aes_key.toStdString(), aes_iv.toStdString(), 8);
                } else if (aes_mode == 4){
                    datablock = AES_CFB::AES128Cypher(aes_in.toStdString(), aes_key.toStdString(), aes_iv.toStdString(), 128);
                } else if (aes_mode == 5){
                    datablock = AES_OFB::AES128Cypher(aes_in.toStdString(), aes_key.toStdString(), aes_iv.toStdString());
                } else if (aes_mode == 6){
                    datablock = AES_CTR::AES128Cypher(aes_in.toStdString(), aes_key.toStdString(), aes_iv.toStdString());
                } else if (aes_mode == 7){
                    GCM_EncyptionResult gcmresult = AES_GCM::authenticatedEncryption(aes_in.toStdString(), AES_KEY_128, aes_key.toStdString(), 32, aes_iv.toStdString(),"");
                    result = gcmresult.cipher_text_;
                    ui->aes_gcm_tag_edit->setText(gcmresult.tag_.c_str());
                } 
                if(aes_mode != 7){
                    result = AESDataBlock::hexStringFromDataBlocks(datablock);
                }
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
        } else {
            if(aes_key.size() != 48 || aes_iv.size() != 32){
                result = "Please enter appropriate length values for key and initialization vector";
            } else{
                vector<AESDataBlock> datablock;
                if (aes_mode == 1){
                    datablock = AES_CBC::AES192Cypher(aes_in.toStdString(), aes_key.toStdString(), aes_iv.toStdString());
                } else if (aes_mode == 2){
                    datablock = AES_CFB::AES192Cypher(aes_in.toStdString(), aes_key.toStdString(), aes_iv.toStdString(), 1);
                } else if (aes_mode == 3){
                    datablock = AES_CFB::AES192Cypher(aes_in.toStdString(), aes_key.toStdString(), aes_iv.toStdString(), 8);
                } else if (aes_mode == 4){
                    datablock = AES_CFB::AES192Cypher(aes_in.toStdString(), aes_key.toStdString(), aes_iv.toStdString(), 128);
                } else if (aes_mode == 5){
                    datablock = AES_OFB::AES192Cypher(aes_in.toStdString(), aes_key.toStdString(), aes_iv.toStdString());
                } else if (aes_mode == 6){
                    datablock = AES_CTR::AES192Cypher(aes_in.toStdString(), aes_key.toStdString(), aes_iv.toStdString());
                } else if (aes_mode == 7){
                    GCM_EncyptionResult gcmresult = AES_GCM::authenticatedEncryption(aes_in.toStdString(), AES_KEY_192, aes_key.toStdString(), 32, aes_iv.toStdString(),"");
                    result = gcmresult.cipher_text_;
                    ui->aes_gcm_tag_edit->setText(gcmresult.tag_.c_str());
                } 
                if(aes_mode != 7){
                    result = AESDataBlock::hexStringFromDataBlocks(datablock);
                }
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
        } else {
            if(aes_key.size() != 64 || aes_iv.size() != 32){
                result = "Please enter appropriate length values for key and initialization vector";
            } else{
                vector<AESDataBlock> datablock;
                if (aes_mode == 1){
                    datablock = AES_CBC::AES256Cypher(aes_in.toStdString(), aes_key.toStdString(), aes_iv.toStdString());
                } else if (aes_mode == 2){
                    datablock = AES_CFB::AES256Cypher(aes_in.toStdString(), aes_key.toStdString(), aes_iv.toStdString(), 1);
                } else if (aes_mode == 3){
                    datablock = AES_CFB::AES256Cypher(aes_in.toStdString(), aes_key.toStdString(), aes_iv.toStdString(), 8);
                } else if (aes_mode == 4){
                    datablock = AES_CFB::AES256Cypher(aes_in.toStdString(), aes_key.toStdString(), aes_iv.toStdString(), 128);
                } else if (aes_mode == 5){
                    datablock = AES_OFB::AES256Cypher(aes_in.toStdString(), aes_key.toStdString(), aes_iv.toStdString());
                } else if (aes_mode == 6){
                    datablock = AES_CTR::AES256Cypher(aes_in.toStdString(), aes_key.toStdString(), aes_iv.toStdString());
                } else if (aes_mode == 7){
                    GCM_EncyptionResult gcmresult = AES_GCM::authenticatedEncryption(aes_in.toStdString(), AES_KEY_256, aes_key.toStdString(), 32, aes_iv.toStdString(),"");
                    result = gcmresult.cipher_text_;
                    ui->aes_gcm_tag_edit->setText(gcmresult.tag_.c_str());
                } 
                if(aes_mode != 7){
                    result = AESDataBlock::hexStringFromDataBlocks(datablock);
                }
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
        } else {
            if(aes_key.size() != 32 || aes_iv.size() != 32){
                result = "Please enter appropriate length values for key and initialization vector";
            } else{
                vector<AESDataBlock> datablock;
                if (aes_mode == 1){
                    datablock = AES_CBC::AES128InvCypher(aes_in.toStdString(), aes_key.toStdString(), aes_iv.toStdString());
                } else if (aes_mode == 2){
                    datablock = AES_CFB::AES128InvCypher(aes_in.toStdString(), aes_key.toStdString(), aes_iv.toStdString(), 1);
                } else if (aes_mode == 3){
                    datablock = AES_CFB::AES128InvCypher(aes_in.toStdString(), aes_key.toStdString(), aes_iv.toStdString(), 8);
                } else if (aes_mode == 4){
                    datablock = AES_CFB::AES128InvCypher(aes_in.toStdString(), aes_key.toStdString(), aes_iv.toStdString(), 128);
                } else if (aes_mode == 5){
                    datablock = AES_OFB::AES128InvCypher(aes_in.toStdString(), aes_key.toStdString(), aes_iv.toStdString());
                } else if (aes_mode == 6){
                    datablock = AES_CTR::AES128InvCypher(aes_in.toStdString(), aes_key.toStdString(), aes_iv.toStdString());
                } else if (aes_mode == 7){
                    QString aes_gcm_tag = ui->aes_gcm_tag_edit->text();
                    GCM_DecryptionResult gcmresult = AES_GCM::authenticatedDecryption(aes_in.toStdString(), AES_KEY_128, aes_key.toStdString(), aes_gcm_tag.toStdString(), 32, aes_iv.toStdString(),"");
                    if (gcmresult.status_ == true){
                        result = gcmresult.plain_text_;
                    } else {
                        result = std::string("The encrypted message was unable to be authenticated");
                    }
                } 
                if(aes_mode != 7){
                    result = AESDataBlock::hexStringFromDataBlocks(datablock);
                }
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
        } else {
            if(aes_key.size() != 48 || aes_iv.size() != 32){
                result = "Please enter appropriate length values for key and initialization vector";
            } else{
                vector<AESDataBlock> datablock;
                if (aes_mode == 1){
                    datablock = AES_CBC::AES192InvCypher(aes_in.toStdString(), aes_key.toStdString(), aes_iv.toStdString());
                } else if (aes_mode == 2){
                    datablock = AES_CFB::AES192InvCypher(aes_in.toStdString(), aes_key.toStdString(), aes_iv.toStdString(), 1);
                } else if (aes_mode == 3){
                    datablock = AES_CFB::AES192InvCypher(aes_in.toStdString(), aes_key.toStdString(), aes_iv.toStdString(), 8);
                } else if (aes_mode == 4){
                    datablock = AES_CFB::AES192InvCypher(aes_in.toStdString(), aes_key.toStdString(), aes_iv.toStdString(), 128);
                } else if (aes_mode == 5){
                    datablock = AES_OFB::AES192InvCypher(aes_in.toStdString(), aes_key.toStdString(), aes_iv.toStdString());
                } else if (aes_mode == 5){
                    datablock = AES_CTR::AES192InvCypher(aes_in.toStdString(), aes_key.toStdString(), aes_iv.toStdString());
                } else if (aes_mode == 7){
                    QString aes_gcm_tag = ui->aes_gcm_tag_edit->text();
                    GCM_DecryptionResult gcmresult = AES_GCM::authenticatedDecryption(aes_in.toStdString(), AES_KEY_192, aes_key.toStdString(), aes_gcm_tag.toStdString(), 32, aes_iv.toStdString(),"");
                    if (gcmresult.status_ == true){
                        result = gcmresult.plain_text_;
                    } else {
                        result = std::string("The encrypted message was unable to be authenticated");
                    }
                }
                if(aes_mode != 7) {
                    result = AESDataBlock::hexStringFromDataBlocks(datablock);
                }
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
        } else {
            if(aes_key.size() != 64 || aes_iv.size() != 32){
                result = "Please enter appropriate length values for key and initialization vector";
            } else{
                vector<AESDataBlock> datablock;
                if (aes_mode == 1){
                    datablock = AES_CBC::AES256InvCypher(aes_in.toStdString(), aes_key.toStdString(), aes_iv.toStdString());
                } else if (aes_mode == 2){
                    datablock = AES_CFB::AES256InvCypher(aes_in.toStdString(), aes_key.toStdString(), aes_iv.toStdString(), 1);
                } else if (aes_mode == 3){
                    datablock = AES_CFB::AES256InvCypher(aes_in.toStdString(), aes_key.toStdString(), aes_iv.toStdString(), 8);
                } else if (aes_mode == 4){
                    datablock = AES_CFB::AES256InvCypher(aes_in.toStdString(), aes_key.toStdString(), aes_iv.toStdString(), 128);
                } else if (aes_mode == 5){
                    datablock = AES_OFB::AES256InvCypher(aes_in.toStdString(), aes_key.toStdString(), aes_iv.toStdString());
                } else if (aes_mode == 6){
                    datablock = AES_CTR::AES256InvCypher(aes_in.toStdString(), aes_key.toStdString(), aes_iv.toStdString());
                } else if (aes_mode == 7){
                    QString aes_gcm_tag = ui->aes_gcm_tag_edit->text();
                    GCM_DecryptionResult gcmresult = AES_GCM::authenticatedDecryption(aes_in.toStdString(), AES_KEY_256, aes_key.toStdString(), aes_gcm_tag.toStdString(), 32, aes_iv.toStdString(),"");
                    if (gcmresult.status_ == true){
                        result = gcmresult.plain_text_;
                    } else {
                        result = std::string("The encrypted message was unable to be authenticated");
                    }
                } 
                if(aes_mode != 7){
                    result = AESDataBlock::hexStringFromDataBlocks(datablock);
                }
            }
        }
    }

    QString result_qstring = removePadding(QString(result.c_str()));
    ui->aes_out_text->setPlainText(result_qstring);
}