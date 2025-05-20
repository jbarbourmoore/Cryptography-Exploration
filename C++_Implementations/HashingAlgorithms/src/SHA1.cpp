/// This file contains the methods for my SHA1 Experimentation in C++
///
/// Author        : Jamie Barbour-Moore
/// Created       : 05/19/25

#include "SHA1.hpp"

const word SHA1::K[4] = {0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6};

const word SHA1::H0[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};

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
    word result = (x & y) ^ ((~x) & z);
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
    size_t k = mod(FINAL_BLOCK_CAPACITY - 1 - l,  BLOCK_SIZE);
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

string SHA1::hashMessageToHex(message input){
    word H[5];
    H[0] = H0[0];
    H[1] = H0[1];
    H[2] = H0[2];
    H[3] = H0[3];
    H[4] = H0[4];

    for (size_t block_num = 0; block_num < input.size(); block_num ++){
        word a = H[0];
        word b = H[1];
        word c = H[2];
        word d = H[3];
        word e = H[4];
        block M = input[block_num];
        word W[80];
        for (size_t t = 0; t < 16; t ++){
            W[t] = M[t];
        }
        for (size_t t = 16; t < 80; t ++){
            W[t] = W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16];
            W[t] = ROTL(W[t], 1);
        }
        for (size_t t = 0; t < 80; t ++){
            word Kt;
            word f_bcd;
            if (t < 20){
                Kt = K[0];
                // printf("b = %s, c = %s, d= %s\n", wordToHexString(b).c_str(),wordToHexString(c).c_str(),wordToHexString(d).c_str());
                f_bcd = ch(b, c ,d);
            } else if (t < 40) {
                Kt = K[1];
                f_bcd = parity(b, c, d);
            } else if (t < 60) {
                Kt = K[2];
                f_bcd = maj(b, c, d);
            } else {
                Kt = K[3];
                f_bcd = parity(b, c, d);
            }
            // printf("f_bcd = %s\n", wordToHexString(f_bcd).c_str());
            word T = ROTL(a, 5);
            T = T + f_bcd + Kt + e + W[t];
            e = d;
            d = c;
            c = ROTL(b, 30);
            b = a;
            a = T;
            // printf("%ld -> a : %s",t, wordToHexString(a).c_str());
            // printf(", b : %s", wordToHexString(b).c_str());
            // printf(", c : %s", wordToHexString(c).c_str());
            // printf(", d : %s", wordToHexString(d).c_str());
            // printf(", e : %s\n", wordToHexString(e).c_str());
        }
        H[0] = H[0] + a;
        H[1] = H[1] + b;
        H[2] = H[2] + c;
        H[3] = H[3] + d;
        H[4] = H[4] + e;
        
    }

    string hash_digest = "";
    for ( int i = 0; i < 5; i ++){
        hash_digest += wordToHexString(H[i]);
        if (i < 4){
            hash_digest += " ";
        }
    }

    return hash_digest;
}


message SHA1::padStringToMessage(string input){
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

u_int64_t SHA1::mod(u_int64_t value, u_int64_t modulo){
    return (value % modulo + modulo) % modulo;
}