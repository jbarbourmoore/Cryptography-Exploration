#include "AESDataBlock.hpp"

AESDataBlock::AESDataBlock(){
    for (int i = 0; i < byte_length; i ++){
        data_block[i] = 0;
    }
}

AESDataBlock::AESDataBlock(const AESDataBlock &input){
    for (int i = 0; i < byte_length; i ++){
        data_block[i] = input.getByte(i);
    }
}

AESDataBlock::AESDataBlock(unsigned char* input){
    for (int i = 0; i < byte_length; i ++){
        data_block[i] = input[i];
    }
}

void AESDataBlock::print() const{
    for(int i = 0; i < byte_length; i ++){
        printf("0x%.2X", data_block[i]);
        if(i < byte_length - 1){
            printf(", ");
        }
    }
}

unsigned char AESDataBlock::getByte(int index) const{
    return data_block[index];
}

void AESDataBlock::setByte(int index, unsigned char byte_to_set){
    data_block[index] = byte_to_set;
}

bool AESDataBlock::operator==(const AESDataBlock &other) const{
    bool is_equal = true;
    for (int i = 0; i < byte_length; i++){
        if (getByte(i) != other.getByte(i)){
            is_equal = false;
        }
    }
    return is_equal;
}