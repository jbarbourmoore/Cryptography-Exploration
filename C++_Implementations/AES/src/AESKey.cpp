#include "AESKey.hpp"

std::vector<AESWord> AESKey::keyExpansion(unsigned char *key, AESKeyTypes key_type){
    int Nk = getNk(key_type);
    int Nr = getNr(key_type);
    int w_length = 4 * Nr + 3;
    std::vector<AESWord> w;
    int i = 0;
    while (i < Nk) {
        w.push_back(AESWord(key[i*4],key[i*4+1],key[i*4+2],key[i*4+3]));
        // w.at(i).print();
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
        // printf("%d :",i);
        // temp.print();
        i++;
    }
    return w;
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