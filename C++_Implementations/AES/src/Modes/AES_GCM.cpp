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

void AES_GCM::GTCR(){

}