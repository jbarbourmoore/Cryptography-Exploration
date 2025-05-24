#include "AES_CFB.hpp"

std::vector<AESDataBlock> AES_CFB::AES128Cypher(std::string input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector, int s_bits){
    std::vector<AESDataBlock> input_blocks = AESDataBlock::dataBlocksFromHexString(input);
    std::vector<AESDataBlock> output_blocks = AES_CFB::AES128Cypher(input_blocks, expanded_key, initialization_vector, s_bits);
    return output_blocks;
}

std::vector<AESDataBlock> AES_CFB::AES128Cypher(std::string input, std::string key, AESDataBlock initialization_vector, int s_bits){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key);
    return AES_CFB::AES128Cypher(input, expanded_key, initialization_vector, s_bits);
}

std::vector<AESDataBlock> AES_CFB::AES128Cypher(std::string input, unsigned char *key, AESDataBlock initialization_vector, int s_bits){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key,AES_KEY_128);
    return AES_CFB::AES128Cypher(input, expanded_key, initialization_vector, s_bits);
}

std::vector<AESDataBlock> AES_CFB::AES128InvCypher(std::string input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector, int s_bits){
    std::vector<AESDataBlock> input_blocks = AESDataBlock::dataBlocksFromHexString(input);
    std::vector<AESDataBlock> output_blocks = AES_CFB::AES128InvCypher(input_blocks, expanded_key, initialization_vector, s_bits);
    return output_blocks;
}

std::vector<AESDataBlock> AES_CFB::AES128InvCypher(std::string input, std::string key, AESDataBlock initialization_vector, int s_bits){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key);
    return AES_CFB::AES128InvCypher(input, expanded_key, initialization_vector, s_bits);
}

std::vector<AESDataBlock> AES_CFB::AES128InvCypher(std::string input, unsigned char *key, AESDataBlock initialization_vector, int s_bits){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key,AES_KEY_128);
    return AES_CFB::AES128InvCypher(input, expanded_key, initialization_vector, s_bits);
}

std::vector<AESDataBlock> AES_CFB::AES128Cypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector, int s_bits){
    std::vector<AESDataBlock> output_blocks;
    int shift = block_size - s_bits;
    AESDataBlock I = AESDataBlock(initialization_vector);
    int rounds_per_block = block_size / s_bits;
    for (int i = 0; i < input.size(); i ++){
        AESDataBlock output_block = AESDataBlock();
        for (int round = 0; round < rounds_per_block; round ++){
            AESDataBlock O = AES::AES128Cypher(I, expanded_key);
            AESDataBlock P = input.at(i).getSegment(round * s_bits, s_bits);
            AESDataBlock C = O.getSegment(0, s_bits);
            C.xorBlock(P);
            // if(round < 2){
            //     printf("I : ");
            //     I.print();
            //     printf("O : ");
            //     O.print();
            //     printf("P : ");
            //     P.print();
            //     printf("C : ");
            //     C.print();
            // }
            output_block.addSegment(C, round * s_bits, s_bits);
            I<<(s_bits);
            I.xorBlock(C);
        }
        output_blocks.push_back(output_block);
    }
    return output_blocks;
}

std::vector<AESDataBlock> AES_CFB::AES128Cypher(std::vector<AESDataBlock> input, std::string key, AESDataBlock initialization_vector, int s_bits){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key);
    return AES_CFB::AES128Cypher(input, expanded_key, initialization_vector, s_bits);
}

std::vector<AESDataBlock> AES_CFB::AES128Cypher(std::vector<AESDataBlock> input, unsigned char *key, AESDataBlock initialization_vector, int s_bits){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key,AES_KEY_128);
    return AES_CFB::AES128Cypher(input, expanded_key, initialization_vector, s_bits);
}

std::vector<AESDataBlock> AES_CFB::AES128InvCypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector, int s_bits){
    std::vector<AESDataBlock> output_blocks;
    int shift = block_size - s_bits;
    AESDataBlock I = AESDataBlock(initialization_vector);
    int rounds_per_block = block_size / s_bits;
    for (int i = 0; i < input.size(); i ++){
        AESDataBlock output_block = AESDataBlock();
        for (int round = 0; round < rounds_per_block; round ++){
            AESDataBlock O = AES::AES128Cypher(I, expanded_key);
            AESDataBlock C = input.at(i).getSegment(round * s_bits, s_bits);
            AESDataBlock P = O.getSegment(0, s_bits);
            P.xorBlock(C);
            output_block.addSegment(P, round * s_bits, s_bits);
            I<<(s_bits);
            I.xorBlock(C);
        }
        output_blocks.push_back(output_block);
    }
    return output_blocks;
}

std::vector<AESDataBlock> AES_CFB::AES128InvCypher(std::vector<AESDataBlock> input, std::string key, AESDataBlock initialization_vector, int s_bits){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key);
    return AES_CFB::AES128InvCypher(input, expanded_key, initialization_vector, s_bits);
}

std::vector<AESDataBlock> AES_CFB::AES128InvCypher(std::vector<AESDataBlock> input, unsigned char *key, AESDataBlock initialization_vector, int s_bits){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key,AES_KEY_128);
    return AES_CFB::AES128InvCypher(input, expanded_key, initialization_vector, s_bits);
}

std::vector<AESDataBlock> AES_CFB::AES192Cypher(std::string input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector, int s_bits){
    std::vector<AESDataBlock> input_blocks = AESDataBlock::dataBlocksFromHexString(input);
    std::vector<AESDataBlock> output_blocks = AES_CFB::AES192Cypher(input_blocks, expanded_key, initialization_vector, s_bits);
    return output_blocks;
}

std::vector<AESDataBlock> AES_CFB::AES192Cypher(std::string input, std::string key, AESDataBlock initialization_vector, int s_bits){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key);
    return AES_CFB::AES192Cypher(input, expanded_key, initialization_vector, s_bits);
}

std::vector<AESDataBlock> AES_CFB::AES192Cypher(std::string input, unsigned char *key, AESDataBlock initialization_vector, int s_bits){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key,AES_KEY_192);
    return AES_CFB::AES192Cypher(input, expanded_key, initialization_vector, s_bits);
}

std::vector<AESDataBlock> AES_CFB::AES192InvCypher(std::string input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector, int s_bits){
    std::vector<AESDataBlock> input_blocks = AESDataBlock::dataBlocksFromHexString(input);
    std::vector<AESDataBlock> output_blocks = AES_CFB::AES192InvCypher(input_blocks, expanded_key, initialization_vector, s_bits);
    return output_blocks;
}

std::vector<AESDataBlock> AES_CFB::AES192InvCypher(std::string input, std::string key, AESDataBlock initialization_vector, int s_bits){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key);
    return AES_CFB::AES192InvCypher(input, expanded_key, initialization_vector, s_bits);
}

std::vector<AESDataBlock> AES_CFB::AES192InvCypher(std::string input, unsigned char *key, AESDataBlock initialization_vector, int s_bits){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key,AES_KEY_192);
    return AES_CFB::AES192InvCypher(input, expanded_key, initialization_vector, s_bits);
}

std::vector<AESDataBlock> AES_CFB::AES192Cypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector, int s_bits){
    std::vector<AESDataBlock> output_blocks;
    int shift = block_size - s_bits;
    AESDataBlock I = AESDataBlock(initialization_vector);
    int rounds_per_block = block_size / s_bits;
    for (int i = 0; i < input.size(); i ++){
        AESDataBlock output_block = AESDataBlock();
        for (int round = 0; round < rounds_per_block; round ++){
            AESDataBlock O = AES::AES192Cypher(I, expanded_key);
            AESDataBlock P = input.at(i).getSegment(round * s_bits, s_bits);
            AESDataBlock C = O.getSegment(0, s_bits);
            C.xorBlock(P);
            output_block.addSegment(C, round * s_bits, s_bits);
            I<<(s_bits);
            I.xorBlock(C);
        }
        output_blocks.push_back(output_block);
    }
    return output_blocks;
}

std::vector<AESDataBlock> AES_CFB::AES192Cypher(std::vector<AESDataBlock> input, std::string key, AESDataBlock initialization_vector, int s_bits){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key);
    return AES_CFB::AES192Cypher(input, expanded_key, initialization_vector, s_bits);
}

std::vector<AESDataBlock> AES_CFB::AES192Cypher(std::vector<AESDataBlock> input, unsigned char *key, AESDataBlock initialization_vector, int s_bits){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key,AES_KEY_192);
    return AES_CFB::AES192Cypher(input, expanded_key, initialization_vector, s_bits);
}

std::vector<AESDataBlock> AES_CFB::AES192InvCypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector, int s_bits){
    std::vector<AESDataBlock> output_blocks;
    int shift = block_size - s_bits;
    AESDataBlock I = AESDataBlock(initialization_vector);
    int rounds_per_block = block_size / s_bits;
    for (int i = 0; i < input.size(); i ++){
        AESDataBlock output_block = AESDataBlock();
        for (int round = 0; round < rounds_per_block; round ++){
            AESDataBlock O = AES::AES192Cypher(I, expanded_key);
            AESDataBlock C = input.at(i).getSegment(round * s_bits, s_bits);
            AESDataBlock P = O.getSegment(0, s_bits);
            P.xorBlock(C);
            output_block.addSegment(P, round * s_bits, s_bits);
            I<<(s_bits);
            I.xorBlock(C);
        }
        output_blocks.push_back(output_block);
    }
    return output_blocks;
}

std::vector<AESDataBlock> AES_CFB::AES192InvCypher(std::vector<AESDataBlock> input, std::string key, AESDataBlock initialization_vector, int s_bits){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key);
    return AES_CFB::AES192InvCypher(input, expanded_key, initialization_vector, s_bits);
}

std::vector<AESDataBlock> AES_CFB::AES192InvCypher(std::vector<AESDataBlock> input, unsigned char *key, AESDataBlock initialization_vector, int s_bits){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key,AES_KEY_192);
    return AES_CFB::AES192InvCypher(input, expanded_key, initialization_vector, s_bits);
}

std::vector<AESDataBlock> AES_CFB::AES256Cypher(std::string input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector, int s_bits){
    std::vector<AESDataBlock> input_blocks = AESDataBlock::dataBlocksFromHexString(input);
    std::vector<AESDataBlock> output_blocks = AES_CFB::AES256Cypher(input_blocks, expanded_key, initialization_vector, s_bits);
    return output_blocks;
}

std::vector<AESDataBlock> AES_CFB::AES256Cypher(std::string input, std::string key, AESDataBlock initialization_vector, int s_bits){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key);
    return AES_CFB::AES256Cypher(input, expanded_key, initialization_vector, s_bits);
}

std::vector<AESDataBlock> AES_CFB::AES256Cypher(std::string input, unsigned char *key, AESDataBlock initialization_vector, int s_bits){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key,AES_KEY_256);
    return AES_CFB::AES256Cypher(input, expanded_key, initialization_vector, s_bits);
}

std::vector<AESDataBlock> AES_CFB::AES256InvCypher(std::string input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector, int s_bits){
    std::vector<AESDataBlock> input_blocks = AESDataBlock::dataBlocksFromHexString(input);
    std::vector<AESDataBlock> output_blocks = AES_CFB::AES256InvCypher(input_blocks, expanded_key, initialization_vector, s_bits);
    return output_blocks;
}

std::vector<AESDataBlock> AES_CFB::AES256InvCypher(std::string input, std::string key, AESDataBlock initialization_vector, int s_bits){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key);
    return AES_CFB::AES256InvCypher(input, expanded_key, initialization_vector, s_bits);
}

std::vector<AESDataBlock> AES_CFB::AES256InvCypher(std::string input, unsigned char *key, AESDataBlock initialization_vector, int s_bits){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key,AES_KEY_256);
    return AES_CFB::AES256InvCypher(input, expanded_key, initialization_vector, s_bits);
}

std::vector<AESDataBlock> AES_CFB::AES256Cypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector, int s_bits){
    std::vector<AESDataBlock> output_blocks;
    int shift = block_size - s_bits;
    AESDataBlock I = AESDataBlock(initialization_vector);
    int rounds_per_block = block_size / s_bits;
    for (int i = 0; i < input.size(); i ++){
        AESDataBlock output_block = AESDataBlock();
        for (int round = 0; round < rounds_per_block; round ++){
            AESDataBlock O = AES::AES256Cypher(I, expanded_key);
            AESDataBlock P = input.at(i).getSegment(round * s_bits, s_bits);
            AESDataBlock C = O.getSegment(0, s_bits);
            C.xorBlock(P);
            output_block.addSegment(C, round * s_bits, s_bits);
            I<<(s_bits);
            I.xorBlock(C);
        }
        output_blocks.push_back(output_block);
    }
    return output_blocks;
}

std::vector<AESDataBlock> AES_CFB::AES256Cypher(std::vector<AESDataBlock> input, std::string key, AESDataBlock initialization_vector, int s_bits){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key);
    return AES_CFB::AES256Cypher(input, expanded_key, initialization_vector, s_bits);
}

std::vector<AESDataBlock> AES_CFB::AES256Cypher(std::vector<AESDataBlock> input, unsigned char *key, AESDataBlock initialization_vector, int s_bits){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key,AES_KEY_256);
    return AES_CFB::AES256Cypher(input, expanded_key, initialization_vector, s_bits);
}

std::vector<AESDataBlock> AES_CFB::AES256InvCypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector, int s_bits){
    std::vector<AESDataBlock> output_blocks;
    int shift = block_size - s_bits;
    AESDataBlock I = AESDataBlock(initialization_vector);
    int rounds_per_block = block_size / s_bits;
    for (int i = 0; i < input.size(); i ++){
        AESDataBlock output_block = AESDataBlock();
        for (int round = 0; round < rounds_per_block; round ++){
            AESDataBlock O = AES::AES256Cypher(I, expanded_key);
            AESDataBlock C = input.at(i).getSegment(round * s_bits, s_bits);
            AESDataBlock P = O.getSegment(0, s_bits);
            P.xorBlock(C);
            output_block.addSegment(P, round * s_bits, s_bits);
            I<<(s_bits);
            I.xorBlock(C);
        }
        output_blocks.push_back(output_block);
    }
    return output_blocks;
}

std::vector<AESDataBlock> AES_CFB::AES256InvCypher(std::vector<AESDataBlock> input, std::string key, AESDataBlock initialization_vector, int s_bits){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key);
    return AES_CFB::AES256InvCypher(input, expanded_key, initialization_vector, s_bits);
}

std::vector<AESDataBlock> AES_CFB::AES256InvCypher(std::vector<AESDataBlock> input, unsigned char *key, AESDataBlock initialization_vector, int s_bits){
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key, AES_KEY_256);
    return AES_CFB::AES256InvCypher(input, expanded_key, initialization_vector, s_bits);
}