#include "AES_OFB.hpp"

std::vector<AESDataBlock> AES_OFB::AES128Cypher(std::string input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector){
    std::vector<AESDataBlock> input_blocks = AESDataBlock::dataBlocksFromHexString(input);
    std::vector<AESDataBlock> output_blocks = AES_OFB::AES128Cypher(input_blocks, expanded_key, initialization_vector);
    return output_blocks;
}

std::vector<AESDataBlock> AES_OFB::AES128Cypher(std::string input, std::string key, AESDataBlock initialization_vector){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key);
    return AES_OFB::AES128Cypher(input, expanded_key, initialization_vector);
}

std::vector<AESDataBlock> AES_OFB::AES128Cypher(std::string input, unsigned char *key, AESDataBlock initialization_vector){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key,AES_KEY_128);
    return AES_OFB::AES128Cypher(input, expanded_key, initialization_vector);
}

std::vector<AESDataBlock> AES_OFB::AES128InvCypher(std::string input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector){
    std::vector<AESDataBlock> input_blocks = AESDataBlock::dataBlocksFromHexString(input);
    std::vector<AESDataBlock> output_blocks = AES_OFB::AES128InvCypher(input_blocks, expanded_key, initialization_vector);
    return output_blocks;
}

std::vector<AESDataBlock> AES_OFB::AES128InvCypher(std::string input, std::string key, AESDataBlock initialization_vector){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key);
    return AES_OFB::AES128InvCypher(input, expanded_key, initialization_vector);
}

std::vector<AESDataBlock> AES_OFB::AES128InvCypher(std::string input, unsigned char *key, AESDataBlock initialization_vector){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key,AES_KEY_128);
    return AES_OFB::AES128InvCypher(input, expanded_key, initialization_vector);
}

std::vector<AESDataBlock> AES_OFB::AES128Cypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector){
    std::vector<AESDataBlock> output_blocks;
    AESDataBlock I = AESDataBlock(initialization_vector);
    for (int i = 0; i < input.size(); i ++){
        AESDataBlock P = AESDataBlock(input.at(i));
        AESDataBlock O = AES::AES128Cypher(I, expanded_key);
        AESDataBlock C = AESDataBlock(P);
        C.xorBlock(O);
        I = AESDataBlock(O);
        output_blocks.push_back(C);
    }
    return output_blocks;
}

std::vector<AESDataBlock> AES_OFB::AES128Cypher(std::vector<AESDataBlock> input, std::string key, AESDataBlock initialization_vector){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key);
    return AES_OFB::AES128Cypher(input, expanded_key, initialization_vector);
}

std::vector<AESDataBlock> AES_OFB::AES128Cypher(std::vector<AESDataBlock> input, unsigned char *key, AESDataBlock initialization_vector){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key,AES_KEY_128);
    return AES_OFB::AES128Cypher(input, expanded_key, initialization_vector);
}

std::vector<AESDataBlock> AES_OFB::AES128InvCypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector){
    return AES128Cypher(input, expanded_key, initialization_vector);
}

std::vector<AESDataBlock> AES_OFB::AES128InvCypher(std::vector<AESDataBlock> input, std::string key, AESDataBlock initialization_vector){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key);
    return AES_OFB::AES128InvCypher(input, expanded_key, initialization_vector);
}

std::vector<AESDataBlock> AES_OFB::AES128InvCypher(std::vector<AESDataBlock> input, unsigned char *key, AESDataBlock initialization_vector){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key,AES_KEY_128);
    return AES_OFB::AES128InvCypher(input, expanded_key, initialization_vector);
}
