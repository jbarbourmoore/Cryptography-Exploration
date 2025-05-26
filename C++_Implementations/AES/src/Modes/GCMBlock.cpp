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
        bit_shift -= i;
    }
}

GCMBlock::GCMBlock(std::string input){
    int length = input.size();
    int byte_count = length/2;
    if( length % 2 == 1){
        byte_count+=1;
    }
    block = 0;
    unsigned __int128 temp = 0;
    int bit_shift = 8 * (byte_count - 1);
    for (int i = 0; i < byte_count; i ++){
        temp = std::stoul(input.substr(i*2,2), nullptr, 16);
        block += (temp << bit_shift);
        bit_shift -= 8;
    }
}

void GCMBlock::print() const{
    printf("\n%s\n",getHexString().c_str());
}

std::string GCMBlock::getHexString() const{
    unsigned __int128 block_cp = block;
    char buffer[3];
    u_int temp = 0;
    std::string output = "";
    for (int i = 0; i < 16; i ++){
        temp = block_cp & 0xFF;
        sprintf(buffer, "%X", temp);
        output.insert(0, buffer);
        block_cp = block_cp >> 8;
    }
    return output;
}