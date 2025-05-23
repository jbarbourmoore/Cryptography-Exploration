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

void AESDataBlock::xorBlock(AESDataBlock other){
    for(int i = 0; i < byte_length; i ++){
        data_block[i] = data_block[i] ^ other.getByte(i);
    }
}


AESDataBlock::AESDataBlock(std::string input, bool is_hex){
    if (is_hex){
        for (int i = 0; i < byte_length; i ++){
            data_block[i] = std::stoul(input.substr(i*2,2), nullptr, 16);
        }
    }
}

void AESDataBlock::print(bool with_char_formatting) const{
    for(int i = 0; i < byte_length; i ++){
        if (with_char_formatting) {
            printf("0x%.2X", data_block[i]);
            if(i < byte_length - 1){
                printf(", ");
            }
        } else {
            printf("%.2X", data_block[i]);
        }
    }
    printf("\n");
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

std::vector<AESDataBlock> AESDataBlock::dataBlocksFromHexString(std::string input){
    int block_size_hex = 32;
    int num_blocks = input.size() / block_size_hex;
    std::vector<AESDataBlock> data_blocks;

    for (int i = 0; i < num_blocks; i++){
        data_blocks.push_back(AESDataBlock(input.substr(i * block_size_hex, block_size_hex)));
    }
    return data_blocks;
}

std::string AESDataBlock::getString() const{
    std::string result = "";
    for(int i = 0; i < byte_length; i ++){
        char buffer[3];
        sprintf(buffer, "%.2x", data_block[i]);
        result.append(buffer);
    }
    return result;
}

std::string AESDataBlock::hexStringFromDataBlocks(std::vector<AESDataBlock> input){
    std::string output = "";
    for (int i = 0; i < input.size(); i++){
        output.append(input.at(i).getString());
    }
    return output;
}