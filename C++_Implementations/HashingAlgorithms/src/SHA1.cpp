/// This file contains the methods for my SHA1 Experimentation in C++
///
/// Author        : Jamie Barbour-Moore
/// Created       : 05/19/25

#include "SHA1.hpp"

const string SHA1::K[4] = {"5A827999", "6ED9EBA1", "8F1BBCDC", "CA62C1D6"};

word SHA1::ROTR(word input, int shift){
    word result = (input >> shift) | (input << (WORD_SIZE - shift));
    return result;
}

word SHA1::ROTL(word input, int shift){
    word result = (input << shift) | (input >> (WORD_SIZE - shift));
    return result;
}

word SHA1::hexStringToWord(string input){
    int hex_char_per_word = WORD_SIZE / 4;
    assert(input.size() <= hex_char_per_word);
    word result = std::stoul(input, 0, 16);
    return result;
}

string SHA1::wordToHexString(word input){
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

word SHA1::ch(word x, word y, word z){
    word result = (x & y) ^ (!x & z);
    return result;
}

word SHA1::parity(word x, word y, word z){
    word result = x ^ y ^ z;
    return result;
}

word SHA1::maj(word x, word y, word z){
    word result = (x & y) ^ (x & z) ^ (y & z);
    return result;
}

message SHA1::padVectorBoolInput(vector<bool> input){
    size_t l = input.size();
    size_t k = (FINAL_BLOCK_CAPACITY - 1 - l) % BLOCK_SIZE;
    // append a single 1
    input.push_back(true);

    // fill capacity with 0s
    for (size_t i = 0; i < k; i ++){
        input.push_back(false);
    }

    // add a 64 bit section of data with the value of message length
    int words_in_block = BLOCK_SIZE / WORD_SIZE;
    int size_block_size = BLOCK_SIZE - FINAL_BLOCK_CAPACITY;
    for (size_t bit = 0; bit < size_block_size; bit ++ ){
        size_t bit_value = pow(2, size_block_size - 1 - bit);
        if (l >= bit_value){
            input.push_back(true);
            l -= bit_value;
            
        }else{
            input.push_back(false);
        }
    }
    size_t length = input.size();
    int blocks_in_message = length / BLOCK_SIZE;

    // create the message structure of the output
    message from_input = message();
    for (size_t block_num = 0; block_num < blocks_in_message; block_num ++){
        int block_start = block_num * BLOCK_SIZE;
        block new_block = block();
        for (size_t word_num = 0; word_num < words_in_block; word_num ++){
            int start_index = block_start + word_num * WORD_SIZE;
            int value = 0;
            for (size_t bit = 0; bit < WORD_SIZE; bit++){
                value *= 2;
                if(input[start_index + bit]){
                    value += 1;
                }
            }
            new_block[word_num] = value;
        }
        from_input.push_back(new_block);
    }

    return from_input;
}

string SHA1::messageToHexString(message input){
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