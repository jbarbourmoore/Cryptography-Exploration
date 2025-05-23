#include "AESKey.hpp"

std::vector<AESWord> AESKey::keyExpansion(unsigned char *key, AESKeyTypes key_type){
    int Nk = getNk(key_type);
    int Nr = getNr(key_type);
    int w_length = 4 * Nr + 3;
    std::vector<AESWord> w;
    int i = 0;
    while (i < Nk) {
        w.push_back(AESWord(key[i*4],key[i*4+1],key[i*4+2],key[i*4+3]));
        w.at(i).print();
        i++;
    }
    while (i < Nr * 4 + 4){
        AESWord temp = AESWord(w.at(i-1));
        // printf("temp : ");
        // temp.print();
        if(i % Nk == 0){
            temp.rotWord();
            // printf("rotated : ");
            // temp.print();
            temp.subWord();
            // printf("substituted : ");
            // temp.print();
            AESWord rcon = AESWord(AESConstants::RCON[i/Nk - 1][0],AESConstants::RCON[i/Nk - 1][1],AESConstants::RCON[i/Nk - 1][2], AESConstants::RCON[i/Nk - 1][3]);
            // printf("rcon : ");
            // rcon.print();
            temp.xorWord(rcon);
            // printf("xored : ");
            // temp.print();
        } else if (Nk > 6 && i % Nk == 4){
            temp.subWord();
        }
        temp.xorWord(w.at(i - Nk));
        w.push_back(temp);
        printf("%d :",i);
        temp.print();
        i++;
    }
    return w;
}

AESWord::AESWord(){
    for (int i = 0; i < 4; i++){
        word[i] = 0;
    }
}

AESWord::AESWord(AESWord *input){
    for (int i = 0; i  < 4; i++){
        word[i] = input->word[i];
    }
}

unsigned char AESWord::getByte(int index){
    return word[index];
}

AESWord::AESWord(unsigned char* input){
    for (int i = 0; i < 4; i++){
        word[i] = input[i];
    }
}

AESWord::AESWord(unsigned char first, unsigned char second, unsigned char third, unsigned char fourth){
    word[0] = first;
    word[1] = second;
    word[2] = third;
    word[3] = fourth;
}

void AESWord::xorWord(AESWord other){
    for(int i = 0; i < 4; i ++){
        word[i] = word[i] ^ other.getByte(i);
    }
}

void AESWord::rotWord(){
    unsigned char temp[4];
    for (int i = 0; i < 4; i ++){
        temp[i] = word[(i + 1) % 4];
    }

    for (int i = 0; i < 4; i ++){
        word[i] = temp[i];
    }
}

void AESWord::subWord(){
    for (int i = 0; i < 4; i ++){
        word[i] = AESConstants::SBOX[word[i]];
    }
}

void AESWord::print(){
    for(int i = 0; i < 4; i++){
        printf("%.2x", word[i]);
    }
    printf("\n");
}

int AESKey::getKeyLength(AESKeyTypes key_type){
    int key_length = 192;
    if(key_type == AESKeyTypes::AES_KEY_192){
        key_length = 224;
    } else if (key_type == AESKeyTypes::AES_KEY_256){
        key_length = 256;
    }
    return key_length;
}

int AESKey::getNk(AESKeyTypes key_type){
    int Nk = 4;
    if(key_type == AESKeyTypes::AES_KEY_192){
        Nk = 6;
    } else if (key_type == AESKeyTypes::AES_KEY_256){
        Nk = 8;
    }
    return Nk;
}

int AESKey::getNr(AESKeyTypes key_type){
    int Nr = 10;
    if(key_type == AESKeyTypes::AES_KEY_192){
        Nr = 12;
    } else if (key_type == AESKeyTypes::AES_KEY_256){
        Nr = 14;
    }
    return Nr;
}

int AESKey::getNb(){
    return 4;
}

int AESKey::getBlockSize(){
    return 128;
}
