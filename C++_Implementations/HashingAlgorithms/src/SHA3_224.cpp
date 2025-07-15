#include "SHA3.hpp"

std::bitset<224> SHA3_224::hashAsBitset(std::vector<bool> bit_message){
    bit_message.push_back(false);
    bit_message.push_back(true);
    std::vector<std::bitset<1600>> blocks = padBitMessage(bit_message, d_);
    std::bitset<1600> S = sponge(blocks);
    std::bitset<d_> hash = std::bitset<224>();
    for (int i = 0 ; i < 224 ; i ++){
        hash.set(i, S.test(i));
    }
    return hash;
};

std::string SHA3_224::b2h(std::bitset<d_> bits){
    std::string res = "";
    std::string hex_values = "0123456789ABCDEF";
    int m = 224 / 8;
    for (int i = 0; i < m; i ++){
            int index = i * 8;
            int value = 0;
           
            for (int bit_position = 0; bit_position < 8; bit_position++){
                value += bits.test(index + bit_position) * pow(2, bit_position);
            }
            int remainder = value % 16;
            int divisor = (value - remainder) / 16;
            res.push_back(hex_values.at(divisor));
            res.push_back(hex_values.at(remainder));
    }
    return res;
}

std::string SHA3_224::hashAsHex(std::vector<bool> bit_message){
    std::bitset<d_> hash = hashAsBitset(bit_message);
    std::string hex_hash = b2h(hash);
    return hex_hash;
};

std::bitset<224> SHA3_224::hashAsBitset(std::string hex_input){
    std::vector<bool> bits = h2b(hex_input);
    return hashAsBitset(bits);
};

std::string SHA3_224::hashAsHex(std::string hex_input){
    std::vector<bool> bits = h2b(hex_input);
    return hashAsHex(bits);
};

std::string SHA3_224::hashStringAsHex(std::string string_input){
    std::string hex_input = stringToHex(string_input);
    return hashAsHex(hex_input);
}