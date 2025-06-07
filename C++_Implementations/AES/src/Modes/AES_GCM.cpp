#include "AES_GCM.hpp"

AESDataBlock AES_GCM::GHASH(AESDataBlock H, std::vector<AESDataBlock> X){
    AESDataBlock Y = AESDataBlock();
    int m = X.size();
    for(int i = 0; i < m; i ++){
        printf("X_%d is %s\n", i, X[i].getString().c_str());
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
        for(int i = 0; i < n; i ++){
            AESDataBlock X = AESDataBlock(hex_input.substr(i * block_length, block_length));
            printf("X is %s\n",X.getString().c_str());
            AESDataBlock Y_i = cipher(CB, key_type, expanded_key);
            printf("Cipher is %s\n", Y_i.getString().c_str());
            Y_i.xorBlock(X);
            printf("Y_i is %s\n",Y_i.getString().c_str());
            printf("CB is %s\n", CB.getString().c_str());
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
            break;
        }
        case AESKeyTypes::AES_KEY_192 : {
            cipher_text = AES::AES192Cypher(input, expanded_key);
            break;
        }
        case AESKeyTypes::AES_KEY_256 : {
            cipher_text = AES::AES256Cypher(input, expanded_key);
            break;
        }
    }
    printf("Cipher is %s\n", cipher_text.getString().c_str());
    return cipher_text;
}

GCM_EncyptionResult AES_GCM::authenticatedEncryption(std::string P, AESKeyTypes key_type, std::string key, int t, std::string IV, std::string A){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key);
    int block_length_hex = 32;
    AESDataBlock H = cipher(AESDataBlock(), key_type, expanded_key);
    u_int64_t iv_length = IV.size();
    AESDataBlock J0;
    if (iv_length == 96 / 4){
        IV.append("00000001");
        J0 = AESDataBlock(IV);
    }else {
        int s = mod(iv_length, block_length_hex);
        for (int i = 0 ; i < s + 16; i ++){
            IV.append("0");
        }
        IV.append(getInt64AsString(iv_length * 4));
        J0 = GHASH(H, AESDataBlock::dataBlocksFromHexString(IV));
    }
    printf("J0 is %s\n",J0.getString().c_str());
    AESDataBlock inc_J0 = AESDataBlock(J0);
    inc_J0.increment(1);
    std::string C = GTCR(key_type, key, inc_J0, P);
    printf("C is %s\n",C.c_str());
    u_int64_t U = mod(C.size(), block_length_hex);
    u_int64_t V = mod(A.size(), block_length_hex);
    std::string S_input = "";
    S_input.append(A);
    for (int i = 0 ; i < V; i ++){
        S_input.append("0");
    }
    S_input.append(C);
    for (int i = 0 ; i < U; i ++){
        S_input.append("0");
    }
    S_input.append(getInt64AsString(A.size() * 4));
    S_input.append(getInt64AsString(C.size() * 4));
    AESDataBlock S = GHASH(H, AESDataBlock::dataBlocksFromHexString(S_input));
    std::string tag = GTCR(key_type, key, J0, S.getString());
    return GCM_EncyptionResult(C, tag);
}

std::string AES_GCM::getInt64AsString(u_int64_t input){
    char buffer[17];
    sprintf(buffer, "%016" PRIX64, (u_int64_t)input);
    printf("buffer is %s\n", buffer);
    return std::string(buffer);
}

u_int64_t AES_GCM::mod(u_int64_t input, int modulus){
    u_int64_t result = input / modulus;
    if (input % modulus != 0){
        result ++;
    }
    result = (result * modulus) - input;
    return result;
}

GCM_EncyptionResult::GCM_EncyptionResult(std::string cipher_text, std::string tag){
    cipher_text_ = cipher_text;
    tag_ = tag;
}