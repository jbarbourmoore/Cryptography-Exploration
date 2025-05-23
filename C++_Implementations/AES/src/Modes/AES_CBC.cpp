#include "AES_CBC.hpp"

std::vector<AESDataBlock> AES_CBC::AES128Cypher(std::string input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector){
    std::vector<AESDataBlock> input_blocks = AESDataBlock::dataBlocksFromHexString(input);
    std::vector<AESDataBlock> output_blocks = AES_CBC::AES128Cypher(input_blocks, expanded_key, initialization_vector);
    return output_blocks;
}

std::vector<AESDataBlock> AES_CBC::AES128Cypher(std::string input, std::string key, AESDataBlock initialization_vector){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key);
    return AES_CBC::AES128Cypher(input, expanded_key, initialization_vector);
}

std::vector<AESDataBlock> AES_CBC::AES128Cypher(std::string input, unsigned char *key, AESDataBlock initialization_vector){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key,AES_KEY_128);
    return AES_CBC::AES128Cypher(input, expanded_key, initialization_vector);
}

std::vector<AESDataBlock> AES_CBC::AES128InvCypher(std::string input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector){
    std::vector<AESDataBlock> input_blocks = AESDataBlock::dataBlocksFromHexString(input);
    std::vector<AESDataBlock> output_blocks = AES_CBC::AES128InvCypher(input_blocks, expanded_key, initialization_vector);
    return output_blocks;
}

std::vector<AESDataBlock> AES_CBC::AES128InvCypher(std::string input, std::string key, AESDataBlock initialization_vector){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key);
    return AES_CBC::AES128InvCypher(input, expanded_key, initialization_vector);
}

std::vector<AESDataBlock> AES_CBC::AES128InvCypher(std::string input, unsigned char *key, AESDataBlock initialization_vector){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key,AES_KEY_128);
    return AES_CBC::AES128InvCypher(input, expanded_key, initialization_vector);
}

std::vector<AESDataBlock> AES_CBC::AES128Cypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector){
    std::vector<AESDataBlock> output_blocks;
    for (int i = 0; i < input.size(); i ++){
        AESDataBlock output_block = AESDataBlock(input.at(i));
        output_block.xorBlock(initialization_vector);
        output_block = AES::AES128Cypher(output_block, expanded_key);
        initialization_vector = AESDataBlock(output_block);
        output_blocks.push_back(output_block);
    }
    return output_blocks;
}

std::vector<AESDataBlock> AES_CBC::AES128Cypher(std::vector<AESDataBlock> input, std::string key, AESDataBlock initialization_vector){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key);
    return AES_CBC::AES128Cypher(input, expanded_key, initialization_vector);
}

std::vector<AESDataBlock> AES_CBC::AES128Cypher(std::vector<AESDataBlock> input, unsigned char *key, AESDataBlock initialization_vector){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key,AES_KEY_128);
    return AES_CBC::AES128Cypher(input, expanded_key, initialization_vector);
}

std::vector<AESDataBlock> AES_CBC::AES128InvCypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector){
    std::vector<AESDataBlock> output_blocks;
    for (int i = 0; i < input.size(); i ++){
        AESDataBlock output_block = AESDataBlock(input.at(i));
        output_block = AES::AES128InvCypher(output_block, expanded_key);
        output_block.xorBlock(initialization_vector);
        initialization_vector = AESDataBlock(input.at(i));
        output_blocks.push_back(output_block);
    }
    return output_blocks;
}

std::vector<AESDataBlock> AES_CBC::AES128InvCypher(std::vector<AESDataBlock> input, std::string key, AESDataBlock initialization_vector){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key);
    return AES_CBC::AES128InvCypher(input, expanded_key, initialization_vector);
}

std::vector<AESDataBlock> AES_CBC::AES128InvCypher(std::vector<AESDataBlock> input, unsigned char *key, AESDataBlock initialization_vector){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key,AES_KEY_128);
    return AES_CBC::AES128InvCypher(input, expanded_key, initialization_vector);
}

std::vector<AESDataBlock> AES_CBC::AES192Cypher(std::string input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector){
    std::vector<AESDataBlock> input_blocks = AESDataBlock::dataBlocksFromHexString(input);
    std::vector<AESDataBlock> output_blocks = AES_CBC::AES192Cypher(input_blocks, expanded_key, initialization_vector);
    return output_blocks;
}

std::vector<AESDataBlock> AES_CBC::AES192Cypher(std::string input, std::string key, AESDataBlock initialization_vector){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key);
    return AES_CBC::AES192Cypher(input, expanded_key, initialization_vector);
}

std::vector<AESDataBlock> AES_CBC::AES192Cypher(std::string input, unsigned char *key, AESDataBlock initialization_vector){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key,AES_KEY_192);
    return AES_CBC::AES192Cypher(input, expanded_key, initialization_vector);
}

std::vector<AESDataBlock> AES_CBC::AES192InvCypher(std::string input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector){
    std::vector<AESDataBlock> input_blocks = AESDataBlock::dataBlocksFromHexString(input);
    std::vector<AESDataBlock> output_blocks = AES_CBC::AES192InvCypher(input_blocks, expanded_key, initialization_vector);
    return output_blocks;
}

std::vector<AESDataBlock> AES_CBC::AES192InvCypher(std::string input, std::string key, AESDataBlock initialization_vector){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key);
    return AES_CBC::AES192InvCypher(input, expanded_key, initialization_vector);
}

std::vector<AESDataBlock> AES_CBC::AES192InvCypher(std::string input, unsigned char *key, AESDataBlock initialization_vector){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key,AES_KEY_192);
    return AES_CBC::AES192InvCypher(input, expanded_key, initialization_vector);
}

std::vector<AESDataBlock> AES_CBC::AES192Cypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector){
    std::vector<AESDataBlock> output_blocks;
    for (int i = 0; i < input.size(); i ++){
        AESDataBlock output_block = AESDataBlock(input.at(i));
        output_block.xorBlock(initialization_vector);
        output_block = AES::AES192Cypher(output_block, expanded_key);
        initialization_vector = AESDataBlock(output_block);
        output_blocks.push_back(output_block);
    }
    return output_blocks;
}

std::vector<AESDataBlock> AES_CBC::AES192Cypher(std::vector<AESDataBlock> input, std::string key, AESDataBlock initialization_vector){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key);
    return AES_CBC::AES192Cypher(input, expanded_key, initialization_vector);
}

std::vector<AESDataBlock> AES_CBC::AES192Cypher(std::vector<AESDataBlock> input, unsigned char *key, AESDataBlock initialization_vector){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key,AES_KEY_192);
    return AES_CBC::AES192Cypher(input, expanded_key, initialization_vector);
}

std::vector<AESDataBlock> AES_CBC::AES192InvCypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector){
    std::vector<AESDataBlock> output_blocks;
    for (int i = 0; i < input.size(); i ++){
        AESDataBlock output_block = AESDataBlock(input.at(i));
        output_block = AES::AES192InvCypher(output_block, expanded_key);
        output_block.xorBlock(initialization_vector);
        initialization_vector = AESDataBlock(input.at(i));
        output_blocks.push_back(output_block);
    }
    return output_blocks;
}

std::vector<AESDataBlock> AES_CBC::AES192InvCypher(std::vector<AESDataBlock> input, std::string key, AESDataBlock initialization_vector){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key);
    return AES_CBC::AES192InvCypher(input, expanded_key, initialization_vector);
}

std::vector<AESDataBlock> AES_CBC::AES192InvCypher(std::vector<AESDataBlock> input, unsigned char *key, AESDataBlock initialization_vector){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key,AES_KEY_192);
    return AES_CBC::AES192InvCypher(input, expanded_key, initialization_vector);
}

std::vector<AESDataBlock> AES_CBC::AES256Cypher(std::string input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector){
    std::vector<AESDataBlock> input_blocks = AESDataBlock::dataBlocksFromHexString(input);
    std::vector<AESDataBlock> output_blocks = AES_CBC::AES256Cypher(input_blocks, expanded_key, initialization_vector);
    return output_blocks;
}

std::vector<AESDataBlock> AES_CBC::AES256Cypher(std::string input, std::string key, AESDataBlock initialization_vector){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key);
    return AES_CBC::AES256Cypher(input, expanded_key, initialization_vector);
}

std::vector<AESDataBlock> AES_CBC::AES256Cypher(std::string input, unsigned char *key, AESDataBlock initialization_vector){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key,AES_KEY_256);
    return AES_CBC::AES256Cypher(input, expanded_key, initialization_vector);
}

std::vector<AESDataBlock> AES_CBC::AES256InvCypher(std::string input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector){
    std::vector<AESDataBlock> input_blocks = AESDataBlock::dataBlocksFromHexString(input);
    std::vector<AESDataBlock> output_blocks = AES_CBC::AES256InvCypher(input_blocks, expanded_key, initialization_vector);
    return output_blocks;
}

std::vector<AESDataBlock> AES_CBC::AES256InvCypher(std::string input, std::string key, AESDataBlock initialization_vector){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key);
    return AES_CBC::AES256InvCypher(input, expanded_key, initialization_vector);
}

std::vector<AESDataBlock> AES_CBC::AES256InvCypher(std::string input, unsigned char *key, AESDataBlock initialization_vector){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key,AES_KEY_256);
    return AES_CBC::AES256InvCypher(input, expanded_key, initialization_vector);
}

std::vector<AESDataBlock> AES_CBC::AES256Cypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector){
    std::vector<AESDataBlock> output_blocks;
    for (int i = 0; i < input.size(); i ++){
        AESDataBlock output_block = AESDataBlock(input.at(i));
        output_block.xorBlock(initialization_vector);
        output_block = AES::AES256Cypher(output_block, expanded_key);
        initialization_vector = AESDataBlock(output_block);
        output_blocks.push_back(output_block);
    }
    return output_blocks;
}

std::vector<AESDataBlock> AES_CBC::AES256Cypher(std::vector<AESDataBlock> input, std::string key, AESDataBlock initialization_vector){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key);
    return AES_CBC::AES256Cypher(input, expanded_key, initialization_vector);
}

std::vector<AESDataBlock> AES_CBC::AES256Cypher(std::vector<AESDataBlock> input, unsigned char *key, AESDataBlock initialization_vector){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key,AES_KEY_256);
    return AES_CBC::AES256Cypher(input, expanded_key, initialization_vector);
}

std::vector<AESDataBlock> AES_CBC::AES256InvCypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector){
    std::vector<AESDataBlock> output_blocks;
    for (int i = 0; i < input.size(); i ++){
        AESDataBlock output_block = AESDataBlock(input.at(i));
        output_block = AES::AES256InvCypher(output_block, expanded_key);
        output_block.xorBlock(initialization_vector);
        initialization_vector = AESDataBlock(input.at(i));
        output_blocks.push_back(output_block);
    }
    return output_blocks;
}

std::vector<AESDataBlock> AES_CBC::AES256InvCypher(std::vector<AESDataBlock> input, std::string key, AESDataBlock initialization_vector){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key);
    return AES_CBC::AES256InvCypher(input, expanded_key, initialization_vector);
}

std::vector<AESDataBlock> AES_CBC::AES256InvCypher(std::vector<AESDataBlock> input, unsigned char *key, AESDataBlock initialization_vector){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key, AES_KEY_256);
    return AES_CBC::AES256InvCypher(input, expanded_key, initialization_vector);
}