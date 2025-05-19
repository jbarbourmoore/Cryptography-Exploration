/// This file contains the methods for my SHA1 Experimentation in C++
///
/// Author        : Jamie Barbour-Moore
/// Created       : 05/19/25

#include "SHA1.hpp"

word SHA1::ROTR(word input, int shift){
    word result = (input >> shift) | (input << (WORD_SIZE - shift));
    return result;
}

word SHA1::ROTL(word input, int shift){
    word result = (input << shift) | (input >> (WORD_SIZE - shift));
    return result;
}