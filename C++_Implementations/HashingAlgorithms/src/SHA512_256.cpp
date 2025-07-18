/// This file contains the methods for my SHA512/256 Experimentation in C++
///
/// Author        : Jamie Barbour-Moore
/// Created       : 05/20/25

#include "SHA_64bit.hpp"

const word64 SHA512_256::H0_SHA512_256[8] = { 0x22312194FC2BF72C, 0x9F555FA3C84C64C2, 0x2393B86B6F53B151, 0x963877195940EABD, 
                                            0x96283EE2A88EFFE3, 0xBE5E1E2553863992, 0x2B0199FC2C85B8AA, 0x0EB72DDC81C52CA2};

word64 SHA512_256::getH0(int index){
    return H0_SHA512_256[index];
}

word64 SHA512_256::getDigestSize(){
    return MESSAGE_DIGEST_SIZE;
}