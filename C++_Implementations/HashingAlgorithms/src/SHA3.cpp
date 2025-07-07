#include "SHA3.hpp"

std::vector<std::bitset<1600>> SHA3::padBitMessage(std::vector<bool> bit_message, int digest_length){

    int c = 2 * digest_length;
    int x = block_bit_size_ - c;
    int input_bit_length = bit_message.size();
    int j = SHA3_State::mod(-1 * input_bit_length - 2, x);
    bit_message.push_back(true);
    for (int i = 0 ; i < j ; i ++){
        bit_message.push_back(false);
    }
    bit_message.push_back(true);

    int block_count = bit_message.size() / x;

    std::vector<std::bitset<1600>> result = vector<std::bitset<1600>>();

    for ( int block = 0 ; block < block_count ; block ++){
        result.push_back(std::bitset<1600>());
        for (int bit = 0 ; bit < x ; bit ++){
            result.at(block).set(bit, bit_message.at(block * x + bit));
        }
    }

    return result;
}

std::bitset<1600> SHA3::keccak_f_1600(std::bitset<1600> input_bits){
    // as defined in Algorithm 7: KECCAK-p[b, nr](S) and Section 3.4 keccak f of NIST FIPS 202
    SHA3_State state = SHA3_State(input_bits);

    for (int i = 0 ; i < 24 ; i ++){
        state.round(i);
    }

    return state.getValueAsBitset();
}

std::vector<bool> SHA3::sponge(std::vector<std::bitset<1600>> P, int digest_length){
    // as defined in Algorithm 8: SPONGE[f, pad, r](N, d) of NIST FIPS 202
    int n = P.size();
    std::bitset<1600> S = std::bitset<1600>();
    for(int i = 0 ; i < n ; i ++){
        S = S ^ P.at(i);
        S = keccak_f_1600(S);
    }
    std::vector<bool> Z = std::vector<bool>(digest_length);
    for (int i = 0 ; i < digest_length ; i ++){
        Z.at(i) = S.test(i);
    }
    return Z;
}
// std::vector<std::string> SHA3::padHexMessage(std::string hex_message, int digest_length){
//     int input_hex_length = hex_message.size();
//     int j = SHA3_State::mod(-1 * input_hex_length - 2, block_hex_size_);

//     // as block size is divisible by 4 it is possible to add the padding in a hex form consisting of 8 0* 1 instead of 1 0* 1
//     // hex 8 is equivalent to binary 1 0 0 0 
//     hex_message.append("8");

//     for (int i = 0 ; i < j ; i ++){
//         hex_message.append("0");
//     }
//     // hex 1 is equivalent to binary 0 0 0 1
//     hex_message.append("1");

//     int block_count = hex_message.size() / block_hex_size_;

//     std::vector<std::string> result = std::vector<std::string>();

//     for ( int block = 0 ; block < block_count ; block ++){
//         result.push_back(hex_message.substr(block * block_hex_size_, block_hex_size_));
//     }

//     return result;
// }

