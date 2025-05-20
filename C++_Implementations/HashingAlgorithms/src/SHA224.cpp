#include "SHA_32bit.hpp"

const word SHA224::H0_SHA224[8] = {0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4};

word SHA224::getH0(int index){
    return H0_SHA224[index];
}

word SHA224::getDigestSize(){
    return MESSAGE_DIGEST_SIZE;
}