#include "SHA3.hpp"


std::vector<bool> SHAKE256::hashAsBitset(std::vector<bool> bit_message, int digest_length){
    bit_message.push_back(true);
    bit_message.push_back(true);
    bit_message.push_back(true);
    bit_message.push_back(true);
    std::vector<std::bitset<1600>> blocks = padBitMessage(bit_message, d_);
    std::vector<bool> hash = sponge(blocks, d_, digest_length);
    return hash;
};

std::string SHAKE256::hashAsHex(std::vector<bool> bit_message, int digest_length){
    std::vector<bool> hash = hashAsBitset(bit_message, digest_length);
    std::string hex_hash = b2h(hash);
    return hex_hash;
};

std::vector<bool> SHAKE256::hashAsBitset(std::string hex_input, int digest_length){
    std::vector<bool> bits = h2b(hex_input);
    return hashAsBitset(bits, digest_length);
};

std::string SHAKE256::hashAsHex(std::string hex_input, int digest_length){
    std::vector<bool> bits = h2b(hex_input);
    return hashAsHex(bits, digest_length);
};