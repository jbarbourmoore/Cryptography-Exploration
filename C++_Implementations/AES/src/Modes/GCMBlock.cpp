#include "GCMBlock.hpp"

GCMBlock::GCMBlock(){
    block = 0;
}

GCMBlock::GCMBlock(GCMBlock const &input){
    block = input.block;
}

GCMBlock::GCMBlock(AESDataBlock input){
    block = 0;
    unsigned __int128 temp = 0;
    int bit_shift = 8 * 15;
    for (int i = 0; i < 16; i ++){
        temp = input.getByte(i);
        block += (temp << bit_shift);
        bit_shift -=8;
    }
}

GCMBlock::GCMBlock(std::string input){
    if(input.size()%2!=0){
        input.insert(0, "0");
    }
    int length = input.size();
    int byte_count = length/2;
    
    block = 0;
    unsigned __int128 temp = 0;
    int bit_shift = 8 * (byte_count - 1);
    for (int i = 0; i < byte_count; i ++){
        temp = std::stoul(input.substr(i*2,2), nullptr, 16);
        block += (temp << bit_shift);
        bit_shift -= 8;
    }
}

GCMBlock::GCMBlock(unsigned __int128 input){
    block = input;
}

void GCMBlock::print() const{
    printf("%s\n",getHexString().c_str());
}

std::string GCMBlock::getHexString() const{
    char buffer[34];
    sprintf(buffer, "%016" PRIX64 "%016" PRIX64,(u_int64_t)(block>>64),(u_int64_t)block);
    return std::string(buffer);
}

GCMBlock GCMBlock::galoisMultiplication(GCMBlock const &X, GCMBlock const &Y){
    GCMBlock R = GCMBlock("E1000000000000000000000000000000");
    GCMBlock Z = GCMBlock();
    GCMBlock V = GCMBlock(X);
    for(int i = 0; i <= 127; i++){
        if(Y.checkBit(i)){
            Z = Z ^ V;
        }
        if(!V.checkBit(127)){
            V >> 1;
        } else {
            V >> 1;
            V = V ^ R;
        }
    }
    return Z;
}

bool GCMBlock::checkBit(int index) const{
    return (block >> (127 - index)) & 1;
}

GCMBlock GCMBlock::operator^(GCMBlock const &other) const{
    unsigned __int128 xor_int = block ^ other.block;
    return GCMBlock(xor_int);
}

void GCMBlock::operator>>(int shift_bits){
    block = block >> shift_bits;
}

void GCMBlock::operator<<(int shift_bits){
    block = block << shift_bits;
}

bool GCMBlock::operator==(GCMBlock const &other) const{
    return block == other.block;
}