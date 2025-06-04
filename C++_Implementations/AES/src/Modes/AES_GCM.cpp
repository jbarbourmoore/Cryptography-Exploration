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
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key);
    std::string result = "";
    int block_length = 128 / 4;
    if (result != ""){
        int input_length = hex_input.size();
        int n = input_length / block_length;
        if (input_length % block_length != 0){
            n ++;
        }
        AESDataBlock CB = AESDataBlock(ICB);
        for(int i = 1; i < n; i ++){
            AESDataBlock X = AESDataBlock(hex_input.substr(i * block_length, block_length));
            X.xorBlock(cipher(CB, key_type, expanded_key));
            
            CB.increment(1);
        }

    }

    return result;
}

AESDataBlock AES_GCM::cipher(AESDataBlock input, AESKeyTypes key_type, std::vector<AESWord> expanded_key){
    AESDataBlock cipher_text;
    switch(key_type){
        case AESKeyTypes::AES_KEY_128 : {
            cipher_text = AES::AES128Cypher(input, expanded_key);
        }
        case AESKeyTypes::AES_KEY_192 : {
            cipher_text = AES::AES192Cypher(input, expanded_key);
        }
        case AESKeyTypes::AES_KEY_256 : {
            cipher_text = AES::AES256Cypher(input, expanded_key);
        }
    }
    return cipher_text;
}