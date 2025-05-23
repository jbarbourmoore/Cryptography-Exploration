#include "AES_ECB.hpp"

std::vector<AESDataBlock> AES_ECB::AES128Cypher(std::string input, std::vector<AESWord> expanded_key){
    std::vector<AESDataBlock> input_blocks = AESDataBlock::dataBlocksFromHexString(input);
    std::vector<AESDataBlock> output_blocks = AES_ECB::AES128Cypher(input_blocks, expanded_key);
    return output_blocks;
}

std::vector<AESDataBlock> AES_ECB::AES128Cypher(std::string input, std::string key){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key);
    return AES_ECB::AES128Cypher(input, expanded_key);
}

std::vector<AESDataBlock> AES_ECB::AES128Cypher(std::string input, unsigned char *key){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key,AES_KEY_128);
    return AES_ECB::AES128Cypher(input, expanded_key);
}

std::vector<AESDataBlock> AES_ECB::AES128InvCypher(std::string input, std::vector<AESWord> expanded_key){
    std::vector<AESDataBlock> input_blocks = AESDataBlock::dataBlocksFromHexString(input);
    std::vector<AESDataBlock> output_blocks = AES_ECB::AES128InvCypher(input_blocks, expanded_key);
    return output_blocks;
}

std::vector<AESDataBlock> AES_ECB::AES128InvCypher(std::string input, std::string key){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key);
    return AES_ECB::AES128InvCypher(input, expanded_key);
}

std::vector<AESDataBlock> AES_ECB::AES128InvCypher(std::string input, unsigned char *key){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key,AES_KEY_128);
    return AES_ECB::AES128InvCypher(input, expanded_key);
}

std::vector<AESDataBlock> AES_ECB::AES128Cypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key){
    std::vector<AESDataBlock> output_blocks;
    for (int i = 0; i < input.size(); i ++){
        AESDataBlock output_block = AES::AES128Cypher(input[i], expanded_key);
        output_blocks.push_back(output_block);
    }
    return output_blocks;
}

std::vector<AESDataBlock> AES_ECB::AES128Cypher(std::vector<AESDataBlock> input, std::string key){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key);
    return AES_ECB::AES128Cypher(input, expanded_key);
}

std::vector<AESDataBlock> AES_ECB::AES128Cypher(std::vector<AESDataBlock> input, unsigned char *key){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key,AES_KEY_128);
    return AES_ECB::AES128Cypher(input, expanded_key);
}

std::vector<AESDataBlock> AES_ECB::AES128InvCypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key){
    std::vector<AESDataBlock> output_blocks;
    for (int i = 0; i < input.size(); i ++){
        AESDataBlock output_block = AES::AES128InvCypher(input[i], expanded_key);
        output_blocks.push_back(output_block);
    }
    return output_blocks;
}

std::vector<AESDataBlock> AES_ECB::AES128InvCypher(std::vector<AESDataBlock> input, std::string key){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key);
    return AES_ECB::AES128InvCypher(input, expanded_key);
}

std::vector<AESDataBlock> AES_ECB::AES128InvCypher(std::vector<AESDataBlock> input, unsigned char *key){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key,AES_KEY_128);
    return AES_ECB::AES128InvCypher(input, expanded_key);
}

std::vector<AESDataBlock> AES_ECB::AES192Cypher(std::string input, std::vector<AESWord> expanded_key){
    std::vector<AESDataBlock> input_blocks = AESDataBlock::dataBlocksFromHexString(input);
    std::vector<AESDataBlock> output_blocks = AES_ECB::AES192Cypher(input_blocks, expanded_key);
    return output_blocks;
}

std::vector<AESDataBlock> AES_ECB::AES192Cypher(std::string input, std::string key){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key);
    return AES_ECB::AES192Cypher(input, expanded_key);
}

std::vector<AESDataBlock> AES_ECB::AES192Cypher(std::string input, unsigned char *key){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key,AES_KEY_192);
    return AES_ECB::AES192Cypher(input, expanded_key);
}

std::vector<AESDataBlock> AES_ECB::AES192InvCypher(std::string input, std::vector<AESWord> expanded_key){
    std::vector<AESDataBlock> input_blocks = AESDataBlock::dataBlocksFromHexString(input);
    std::vector<AESDataBlock> output_blocks = AES_ECB::AES192InvCypher(input_blocks, expanded_key);
    return output_blocks;
}

std::vector<AESDataBlock> AES_ECB::AES192InvCypher(std::string input, std::string key){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key);
    return AES_ECB::AES192InvCypher(input, expanded_key);
}

std::vector<AESDataBlock> AES_ECB::AES192InvCypher(std::string input, unsigned char *key){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key,AES_KEY_192);
    return AES_ECB::AES192InvCypher(input, expanded_key);
}

std::vector<AESDataBlock> AES_ECB::AES192Cypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key){
    std::vector<AESDataBlock> output_blocks;
    for (int i = 0; i < input.size(); i ++){
        AESDataBlock output_block = AES::AES192Cypher(input[i], expanded_key);
        output_blocks.push_back(output_block);
    }
    return output_blocks;
}

std::vector<AESDataBlock> AES_ECB::AES192Cypher(std::vector<AESDataBlock> input, std::string key){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key);
    return AES_ECB::AES192Cypher(input, expanded_key);
}

std::vector<AESDataBlock> AES_ECB::AES192Cypher(std::vector<AESDataBlock> input, unsigned char *key){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key,AES_KEY_192);
    return AES_ECB::AES192Cypher(input, expanded_key);
}

std::vector<AESDataBlock> AES_ECB::AES192InvCypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key){
    std::vector<AESDataBlock> output_blocks;
    for (int i = 0; i < input.size(); i ++){
        AESDataBlock output_block = AES::AES192InvCypher(input[i], expanded_key);
        output_blocks.push_back(output_block);
    }
    return output_blocks;
}

std::vector<AESDataBlock> AES_ECB::AES192InvCypher(std::vector<AESDataBlock> input, std::string key){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key);
    return AES_ECB::AES192InvCypher(input, expanded_key);
}

std::vector<AESDataBlock> AES_ECB::AES192InvCypher(std::vector<AESDataBlock> input, unsigned char *key){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key,AES_KEY_192);
    return AES_ECB::AES192InvCypher(input, expanded_key);
}

std::vector<AESDataBlock> AES_ECB::AES256Cypher(std::string input, std::vector<AESWord> expanded_key){
    std::vector<AESDataBlock> input_blocks = AESDataBlock::dataBlocksFromHexString(input);
    std::vector<AESDataBlock> output_blocks = AES_ECB::AES256Cypher(input_blocks, expanded_key);
    return output_blocks;
}

std::vector<AESDataBlock> AES_ECB::AES256Cypher(std::string input, std::string key){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key);
    return AES_ECB::AES256Cypher(input, expanded_key);
}

std::vector<AESDataBlock> AES_ECB::AES256Cypher(std::string input, unsigned char *key){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key,AES_KEY_256);
    return AES_ECB::AES256Cypher(input, expanded_key);
}

std::vector<AESDataBlock> AES_ECB::AES256InvCypher(std::string input, std::vector<AESWord> expanded_key){
    std::vector<AESDataBlock> input_blocks = AESDataBlock::dataBlocksFromHexString(input);
    std::vector<AESDataBlock> output_blocks = AES_ECB::AES256InvCypher(input_blocks, expanded_key);
    return output_blocks;
}

std::vector<AESDataBlock> AES_ECB::AES256InvCypher(std::string input, std::string key){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key);
    return AES_ECB::AES256InvCypher(input, expanded_key);
}

std::vector<AESDataBlock> AES_ECB::AES256InvCypher(std::string input, unsigned char *key){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key,AES_KEY_256);
    return AES_ECB::AES256InvCypher(input, expanded_key);
}

std::vector<AESDataBlock> AES_ECB::AES256Cypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key){
    std::vector<AESDataBlock> output_blocks;
    for (int i = 0; i < input.size(); i ++){
        AESDataBlock output_block = AES::AES256Cypher(input[i], expanded_key);
        output_blocks.push_back(output_block);
    }
    return output_blocks;
}

std::vector<AESDataBlock> AES_ECB::AES256Cypher(std::vector<AESDataBlock> input, std::string key){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key);
    return AES_ECB::AES256Cypher(input, expanded_key);
}

std::vector<AESDataBlock> AES_ECB::AES256Cypher(std::vector<AESDataBlock> input, unsigned char *key){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key,AES_KEY_256);
    return AES_ECB::AES256Cypher(input, expanded_key);
}

std::vector<AESDataBlock> AES_ECB::AES256InvCypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key){
    std::vector<AESDataBlock> output_blocks;
    for (int i = 0; i < input.size(); i ++){
        AESDataBlock output_block = AES::AES256InvCypher(input[i], expanded_key);
        output_blocks.push_back(output_block);
    }
    return output_blocks;
}

std::vector<AESDataBlock> AES_ECB::AES256InvCypher(std::vector<AESDataBlock> input, std::string key){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key);
    return AES_ECB::AES256InvCypher(input, expanded_key);
}

std::vector<AESDataBlock> AES_ECB::AES256InvCypher(std::vector<AESDataBlock> input, unsigned char *key){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key, AES_KEY_256);
    return AES_ECB::AES256InvCypher(input, expanded_key);
}