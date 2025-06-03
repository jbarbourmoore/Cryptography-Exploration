#include "AES_GCM.hpp"

AESDataBlock AES_GCM::GHASH(AESDataBlock H, std::vector<AESDataBlock> X){
    AESDataBlock Y = AESDataBlock();
    int m = X.size();
    for(int i = 0; i < m; i ++){
        Y.xorBlock(X[i]);
        Y = AESDataBlock::galoisMultiplication(Y, H);
    }
    return Y;
}

std::string AES_GCM::GTCR(AESKeyTypes key_type, std::string key, AESDataBlock ICB, std::string hex_input){
    std::string result = "";
    return result;
}