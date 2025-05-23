#include "AESWord.hpp"

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

unsigned char AESWord::getByte(int index) const{
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

void AESWord::print() const{
    for(int i = 0; i < 4; i++){
        printf("0x%.2x, ", word[i]);
        // printf("%.2x", word[i]);
    }
    printf("\n");
}

bool AESWord::operator==(const AESWord &other) const{
    bool is_equal = true;
    for (int i = 0; i < 4; i++){
        if (getByte(i) != other.getByte(i)){
            is_equal = false;
        }
    }
    return is_equal;
}
