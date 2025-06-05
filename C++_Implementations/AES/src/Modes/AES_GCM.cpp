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
    std::string Y = "";
    int block_length = 128 / 4;
    if (hex_input != ""){
        int input_length = hex_input.size();
        int n = input_length / block_length;
        AESDataBlock CB = AESDataBlock(ICB);
        for(int i = 1; i < n; i ++){
            AESDataBlock X = AESDataBlock(hex_input.substr(i * block_length, block_length));
            AESDataBlock Y_i = cipher(CB, key_type, expanded_key);
            Y_i.xorBlock(X);
            CB.increment(1);
            Y.append(Y_i.getString());
        }
        if (input_length % block_length != 0){
            int final_block_length = input_length % block_length;
            AESDataBlock Y_n = cipher(CB, key_type, expanded_key);
            std::string final_hex = hex_input.substr(n * block_length, final_block_length);
            for (int i = 0; i < final_block_length; i ++){
                final_hex.append("0");
            }
            AESDataBlock X = AESDataBlock(final_hex);
            Y_n.xorBlock(X);
            std::string partial_out_string = Y_n.getString();
            Y.append(partial_out_string.substr(0, final_block_length));
        }
    }
    return Y;
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

std::string AES_GCM::authenticatedEncryption(AESDataBlock P, AESKeyTypes key_type, std::string K, int t, AESDataBlock IV, std::string A){

}