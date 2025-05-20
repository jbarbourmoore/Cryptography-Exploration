/// This file contains the methods for my SHA_32bit Experimentation in C++
///
/// Author        : Jamie Barbour-Moore
/// Created       : 05/20/25
#include "SHA_32bit.hpp"

word SHA_32bit::ROTR(word input, int shift){
    word result = (input >> shift) | (input << (WORD_SIZE - shift));
    return result;
}

word SHA_32bit::ROTL(word input, int shift){
    word result = (input << shift) | (input >> (WORD_SIZE - shift));
    return result;
}

word SHA_32bit::hexStringToWord(string input){
    int hex_char_per_word = WORD_SIZE / 4;
    assert(input.size() <= hex_char_per_word);
    word result = std::stoul(input, 0, 16);
    return result;
}

string SHA_32bit::wordToHexString(word input){
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

word SHA_32bit::ch(word x, word y, word z){
    word result = (x & y) ^ ((~x) & z);
    return result;
}

// word SHA_32bit::parity(word x, word y, word z){
//     word result = x ^ y ^ z;
//     return result;
// }

word SHA_32bit::maj(word x, word y, word z){
    word result = (x & y) ^ (x & z) ^ (y & z);
    return result;
}

string SHA_32bit::messageToHexString(message input){
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

message SHA_32bit::padStringToMessage(string input){
   int length = input.size();
   int i;
   string hex = "";

   for (i = 0; i < length; i++){
        char new_char[3];
        sprintf(new_char, "%02X", input[i]);
        hex = hex + new_char[0] + new_char[1];
   }

    // printf("hex : %s\n", hex.c_str());

    hex += "80";
    // printf("hex : %s\n", hex.c_str());

    int cur_length = hex.size();
    int block_size_hex = BLOCK_SIZE / 4;
    int final_block_capacity_hex = FINAL_BLOCK_CAPACITY / 4;

    u_int64_t k = mod(- cur_length + final_block_capacity_hex, block_size_hex);
    // printf("k = %lu\n",k);
    for (i = 0; i < k; i ++){
        hex += "0";
    }

    int input_bit_length = 8 * length;
    int hex_chars = 64 / 4;
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
    hex += size_label;

    cur_length = hex.size();
    int blocks_in_message = cur_length / (BLOCK_SIZE/4);
    int words_in_block = BLOCK_SIZE / WORD_SIZE;

    message from_input = message();
    for (size_t block_num = 0; block_num < blocks_in_message; block_num ++){
        int block_start = block_num * BLOCK_SIZE/4;
        block new_block = block();
        for (size_t word_num = 0; word_num < words_in_block; word_num ++){
            int start_index = block_start + word_num * WORD_SIZE/4;
            new_block[word_num] = hexStringToWord(hex.substr(start_index, WORD_SIZE / 4));
        }
        from_input.push_back(new_block);
    }

    return from_input;
}

u_int64_t SHA_32bit::mod(u_int64_t value, u_int64_t modulo){
    return (value % modulo + modulo) % modulo;
}
