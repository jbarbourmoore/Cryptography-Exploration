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
        sprintf(buffer, "%.2X", data_block[i]);
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

void AESDataBlock::operator>>(int shift_bits){
    int character_shift = shift_bits / 8;
    int bit_shift = shift_bits % 8;
    // printf("total:%d char:%d bit:%d\n", shift_bits, character_shift, bit_shift);
    if (character_shift!=0){
        AESDataBlock temp = AESDataBlock();
        for (int i = 15; i >= character_shift; i --){
            temp.setByte(i, data_block[i - character_shift]);
        }
        for (int i = 0; i < 16; i++){
            data_block[i] = temp.getByte(i);
        }
    }
    if(bit_shift != 0){
    unsigned char temp_bits = 0;
        for (int i = 0; i < 16; i++){
            unsigned char cur_block = getByte(i);
            unsigned char left_over = cur_block << (8 - bit_shift);
            // printf("current block : %u temp bits : %u left_over : %u\n", cur_block, temp_bits, left_over);
            data_block[i] = cur_block >> bit_shift;
            // printf("current block : %u \n", data_block[i]);
            data_block[i] = data_block[i] ^ temp_bits;
            temp_bits = left_over;
        }
    }
}

void AESDataBlock::operator<<(int shift_bits){
    int character_shift = shift_bits / 8;
    int bit_shift = shift_bits % 8;
    // printf("total:%d char:%d bit:%d\n", shift_bits, character_shift, bit_shift);
    if (character_shift!=0){
        AESDataBlock temp = AESDataBlock();
        for (int i = 0; i < (16 - character_shift); i ++){
            temp.setByte(i, data_block[i + character_shift]);
        }
        for (int i = 0; i < 16; i++){
            data_block[i] = temp.getByte(i);
        }
    }
    if(bit_shift != 0){
        unsigned char temp_bits = 0;
        for (int i = 15; i >= 0; i --){
            unsigned char cur_block = getByte(i);
            unsigned char left_over = cur_block >> (8 - bit_shift);
            // printf("current block : %u temp bits : %u left_over : %u\n", cur_block, temp_bits, left_over);
            data_block[i] = cur_block << bit_shift;
            // printf("current block : %u \n", data_block[i]);
            data_block[i] = data_block[i] ^ temp_bits;
            temp_bits = left_over;
        }
    }
}

AESDataBlock AESDataBlock::getSegment(int start_bit, int size_bits){
    // print();
    AESDataBlock segment = AESDataBlock(data_block);\
    // segment.print();
    segment << (start_bit);
    // segment.print();
    segment >> (128 - size_bits);
    // segment.print();
    return segment;
}

void AESDataBlock::addSegment(AESDataBlock segment, int start_bit, int size_bits){
        int distance = 128 - start_bit - size_bits;
        // printf("distance %d\n", distance);
        segment << (128 - start_bit - size_bits);
        // segment.print();
        xorBlock(segment);
}

void AESDataBlock::increment(int inc_amount){
    int index = 15;
    while (inc_amount > 0 && index >= 0){
        unsigned char temp = getByte(index);
        setByte(index, temp + inc_amount);
        int inc_total = inc_amount + temp;
        if (inc_total >= 256){
            inc_amount = inc_total / 256;
            index --;
        } else {
            inc_amount = 0;
        }
    }
}

AESDataBlock::~AESDataBlock(){
    
}