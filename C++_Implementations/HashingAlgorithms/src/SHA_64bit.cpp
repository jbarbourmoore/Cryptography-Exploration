/// This file contains the methods for my SHA_64bit Experimentation in C++
///
/// Author        : Jamie Barbour-Moore
/// Created       : 05/20/25
#include "SHA_64bit.hpp"

word SHA_64bit::ROTR(word input, int shift){
    word result = (input >> shift) | (input << (WORD_SIZE - shift));
    return result;
}

word SHA_64bit::ROTL(word input, int shift){
    word result = (input << shift) | (input >> (WORD_SIZE - shift));
    return result;
}

word SHA_64bit::hexStringToWord(string input){
    int hex_char_per_word = WORD_SIZE / 4;
    assert(input.size() <= hex_char_per_word);
    word result = std::stoul(input, 0, 16);
    return result;
}

string SHA_64bit::wordToHexString(word input){
    int hex_char_per_word = WORD_SIZE / 4;
    string result = "";
    string hexvalues = "0123456789ABCDEF";
    while(input > 0){
        result = hexvalues[input % 16] + result;
        input = input / 16;
    }
    if(result.size() < hex_char_per_word){
        int missing_zeros = hex_char_per_word - result.size();
        for (int i = 0; i < missing_zeros; i++){
            result = "0" + result;
        }
    }
    return result;
}

word SHA_64bit::ch(word x, word y, word z){
    word result = (x & y) ^ ((~x) & z);
    return result;
}

word SHA_64bit::maj(word x, word y, word z){
    word result = (x & y) ^ (x & z) ^ (y & z);
    return result;
}

string SHA_64bit::messageToHexString(message input){
    // iterate through each word in each block in the message, adding them to the string
    string output = "";
    for (size_t i = 0; i < input.size(); i++){
        block current_block = input[i];
        for (size_t j = 0; j < current_block.size(); j ++){
            output += wordToHexString(current_block[j]);
            // add a space after each word in the block if there is another word
            if (j < current_block.size() - 1){
                output += " ";
            }
        }
        // add a new line after each block if there is another block
        if (i < input.size() - 1){
            output += "\n";
        }
    }
    return output;
}

message SHA_64bit::padStringToMessage(string input){

    string input_hex = "";

   for (__int128_t i = 0; i < input.size(); i++){
        char new_char[3];
        sprintf(new_char, "%02X", input[i]);
        input_hex = input_hex + new_char[0] + new_char[1];
   }

   return padHexStringToMessage(input_hex);
}

message SHA_64bit::padHexStringToMessage(string input_hex){

    // the initial length of the hex string
    __int128_t length = input_hex.length();

    // append bits 1,0,0,0
    input_hex += "8";

    // determine how much padding needs to be added
    __int128_t cur_length = input_hex.size();
    int block_size_hex = BLOCK_SIZE / 4;
    int final_block_capacity_hex = FINAL_BLOCK_CAPACITY / 4;

    // add the rest of the padding
    __int128_t k = mod(- cur_length + final_block_capacity_hex, block_size_hex);
    for (__int128_t i = 0; i < k; i ++){
        input_hex += "0";
    }

    // convert the initial bit length into hexadecimal with 128 bits and append it
    __int128_t input_bit_length = 4 * length;
    int hex_chars = 128 / 4;
    string size_label = "";
    string hexvalues = "0123456789ABCDEF";
    while(input_bit_length > 0){
        size_label = hexvalues[input_bit_length % 16] + size_label;
        input_bit_length = input_bit_length / 16;
    }
    if(size_label.size() < hex_chars){
        int missing_zeros = hex_chars - size_label.size();
        for (int i = 0; i < missing_zeros; i++){
            size_label = "0" + size_label;
        }
    }
    input_hex += size_label;

    // assemble the vector of blocks of the words for the message
    cur_length = input_hex.size();
    int blocks_in_message = cur_length / (BLOCK_SIZE/4);
    int words_in_block = BLOCK_SIZE / WORD_SIZE;
    message from_input = message();
    for (size_t block_num = 0; block_num < blocks_in_message; block_num ++){
        int block_start = block_num * BLOCK_SIZE/4;
        block new_block = block();
        for (size_t word_num = 0; word_num < words_in_block; word_num ++){
            int start_index = block_start + word_num * WORD_SIZE/4;
            new_block[word_num] = hexStringToWord(input_hex.substr(start_index, WORD_SIZE / 4));
        }
        from_input.push_back(new_block);
    }

    return from_input;
}

__int128_t SHA_64bit::mod(__int128_t value, __int128_t modulo){
    return (value % modulo + modulo) % modulo;
}

word SHA_64bit::bigEpsilonFromZero(word x){
    word result = ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39);
    return result;
}

word SHA_64bit::bigEpsilonFromOne(word x){
    word result = ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41);
    return result;
}

word SHA_64bit::smallEpsilonFromZero(word x){
    word result = ROTR(x, 1) ^ ROTR(x, 8) ^ (x >> 7);
    return result;
}

word SHA_64bit::smallEpsilonFromOne(word x){
    word result = ROTR(x, 19) ^ ROTR(x, 61) ^ (x >> 6);
    return result;
}