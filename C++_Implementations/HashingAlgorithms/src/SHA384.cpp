/// This file contains the methods for my SHA384 Experimentation in C++
///
/// Author        : Jamie Barbour-Moore
/// Created       : 05/20/25

#include "SHA_64bit.hpp"

const word64 SHA384::H0_SHA384[8] = { 0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939, 
                                    0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4};

word64 SHA384::getH0(int index){
    return H0_SHA384[index];
}

word64 SHA384::getDigestSize(){
    return MESSAGE_DIGEST_SIZE;
}