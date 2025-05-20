/// This file contains the methods for my SHA512/224 Experimentation in C++
///
/// Author        : Jamie Barbour-Moore
/// Created       : 05/20/25

#include "SHA_64bit.hpp"

const word64 SHA512_224::H0_SHA512_224[8] = { 0x8C3D37C819544DA2, 0x73E1996689DCD4D6, 0x1DFAB7AE32FF9C82, 0x679DD514582F9FCF, 
                                            0x0F6D2B697BD44DA8, 0x77E36F7304C48942, 0x3F9D85A86A1D36C8, 0x1112E6AD91D692A1};

word64 SHA512_224::getH0(int index){
    return H0_SHA512_224[index];
}

word64 SHA512_224::getDigestSize(){
    return MESSAGE_DIGEST_SIZE;
}