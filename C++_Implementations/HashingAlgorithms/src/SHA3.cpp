#include "SHA3.hpp"

std::vector<std::bitset<1600>> SHA3::padBitMessage(std::vector<bool> bit_message){
    int input_bit_length = bit_message.size();
    int j = SHA3_State::mod(-1 * input_bit_length - 2, block_bit_size_);
    bit_message.push_back(true);
    for (int i = 0 ; i < j ; i ++){
        bit_message.push_back(false);
    }
    bit_message.push_back(true);

    int block_count = bit_message.size() / block_bit_size_;

    std::vector<std::bitset<1600>> result = vector<std::bitset<1600>>();

    for ( int block = 0 ; block < block_count ; block ++){
        result.push_back(std::bitset<1600>());
        for (int bit = 0 ; bit < block_bit_size_ ; bit ++){
            result.at(block).set(bit, bit_message.at(block * block_bit_size_ + bit));
        }
    }

    return result;
}

std::vector<std::string> SHA3::padHexMessage(std::string hex_message){
    int input_hex_length = hex_message.size();
    int j = SHA3_State::mod(-1 * input_hex_length - 2, block_hex_size_);

    // as block size is divisible by 4 it is possible to add the padding in a hex form consisting of 8 0* 1 instead of 1 0* 1
    // hex 8 is equivalent to binary 1 0 0 0 
    hex_message.append("8");

    for (int i = 0 ; i < j ; i ++){
        hex_message.append("0");
    }
    // hex 1 is equivalent to binary 0 0 0 1
    hex_message.append("1");

    int block_count = hex_message.size() / block_hex_size_;

    std::vector<std::string> result = std::vector<std::string>();

    for ( int block = 0 ; block < block_count ; block ++){
        result.push_back(hex_message.substr(block * block_hex_size_, block_hex_size_));
    }

    return result;
}