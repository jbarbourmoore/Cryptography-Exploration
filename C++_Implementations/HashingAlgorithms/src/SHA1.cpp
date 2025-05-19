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