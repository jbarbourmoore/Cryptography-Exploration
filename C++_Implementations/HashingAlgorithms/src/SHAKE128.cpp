#include "SHA3.hpp"


std::vector<bool> SHAKE128::hashAsBitset(std::vector<bool> bit_message, int digest_length){
    bit_message.push_back(true);
    bit_message.push_back(true);
    bit_message.push_back(true);
    bit_message.push_back(true);
    std::vector<std::bitset<1600>> blocks = padBitMessage(bit_message, d_);
    std::vector<bool> hash = sponge(blocks, d_, digest_length);
    return hash;
};

std::string SHA3::b2h(std::vector<bool> bits){
    std::string res = "";
    std::string hex_values = "0123456789ABCDEF";
    int m = bits.size() / 8;
    for (int i = 0; i < m; i ++){
            int index = i * 8;
            int value = 0;
           
            for (int bit_position = 0; bit_position < 8; bit_position++){
                int bit = 0;
                if(bits.at(i * 8 + bit_position)){
                    bit = 1;
                }
                value += bit * pow(2, bit_position);
            }
            int remainder = value % 16;
            int divisor = (value - remainder) / 16;
            res.push_back(hex_values.at(divisor));
            res.push_back(hex_values.at(remainder));
    }
    return res;
}

std::string SHAKE128::hashAsHex(std::vector<bool> bit_message, int digest_length){
    std::vector<bool> hash = hashAsBitset(bit_message, digest_length);
    std::string hex_hash = b2h(hash);
    return hex_hash;
};

std::vector<bool>  SHAKE128::hashAsBitset(std::string hex_input, int digest_length){
    std::vector<bool> bits = h2b(hex_input);
    return hashAsBitset(bits, digest_length);
};

std::string SHAKE128::hashAsHex(std::string hex_input, int digest_length){
    std::vector<bool> bits = h2b(hex_input);
    return hashAsHex(bits, digest_length);
};

std::string SHAKE128::hashStringAsHex(std::string string_input, int digest_length){
    std::string hex_input = stringToHex(string_input);
    return hashAsHex(hex_input, digest_length);
}