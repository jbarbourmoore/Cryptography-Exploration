#include "SHA3.hpp"

SHA3_State::SHA3_State(){
    a_ = std::array<std::array<std::bitset<64>, 5>, 5>();
}

SHA3_State::SHA3_State(std::bitset<1600> bitset_input){
    a_ = std::array<std::array<std::bitset<64>, 5>, 5>();
    bitsetToState(bitset_input);
}

void SHA3_State::bitsetToState(std::bitset<1600> bitset_input){
    for (int x = 0; x < 5; x ++){
        for (int y = 0; y < 5; y ++){
            for(int z = 0; z < w_; z ++){
                if(bitset_input.test(w_ * (5 * y + x) + z)){
                    setBit(true, x, y, z);
                }
            }
        }
    }
}

SHA3_State::SHA3_State(std::string hex_input){

    // Algorithm 10: h2b(H, n) from NIST FIPS 202

    std::bitset<1600> bits = std::bitset<1600>();
    a_ = std::array<std::array<std::bitset<64>, 5>, 5>();
    int hex_length = hex_input.size();
    std::string hex_values = "0123456789ABCDEF";

    if (hex_length == 1600 / 4){
        for (int i = 0; i < hex_length; i += 2){
            int value = hex_values.find(hex_input.at(i));
            value *= 16;
            value += hex_values.find(hex_input.at(i + 1));

            for (int bit_location = 0 ; bit_location < 8 ; bit_location ++){
                if(value >= pow(2, 7 - bit_location)){
                    bits.set((i / 2) * 8 + bit_location, true);
                    value -= pow(2, 7 - bit_location);
                }
            }
        }
    }
    bitsetToState(bits);
}

void SHA3_State::setBit(bool value, int x, int y, int z){
    a_.at(x).at(y).set(z, value);
}

bool SHA3_State::checkBit(int x, int y, int z){
    return a_.at(x).at(y).test(z);
}

void SHA3_State::printBits(){
    for (int x = 0; x < 5; x ++){
        for (int y = 0; y < 5; y ++){
            for(int z = 0; z < w_; z ++){
                printf("%d", checkBit(x, y, z));
            }
            printf(" ");
        }
        printf("\n");
    }
}

void SHA3_State::printHex(){
    printf("%s\n", getValueAsHex().c_str());
}

std::bitset<1600> SHA3_State::getValueAsBitset(){
    std::bitset<1600> result = std::bitset<1600>();
    for (int x = 0; x < 5; x ++){
        for (int y = 0; y < 5; y ++){
            for(int z = 0; z < w_; z ++){
                if (checkBit(x, y, z)){
                    setBit(true, x, y, z);
                    result.set(w_ * (5 * y + x) + z, true);
                }
            }
        }
    }
    return result;
}

std::string SHA3_State::getValueAsHex(){

    ///Algorithm 11: b2h(S) from NIST FIPS 202

    std::string res = "";
    std::bitset<1600> bits = getValueAsBitset();
    std::string hex_values = "0123456789ABCDEF";
    int m = 1600 / 8;
    for (int i = 0; i < m; i ++){
            int index = i * 8;
            int value = 0;
           
            for (int bit_position = 0; bit_position < 8; bit_position++){
                value += bits.test(index + bit_position) * pow(2, 7 - bit_position);
            }
            int remainder = value % 16;
            int divisor = (value - remainder) / 16;
            res.push_back(hex_values.at(divisor));
            res.push_back(hex_values.at(remainder));
    }
    return res;
}

std::bitset<5> SHA3_State::getRow(int y, int z){
    std::bitset<5> row = std::bitset<5>();
    for (int i = 0 ; i < 5 ; i ++){
        row.set(i, checkBit(i, y, z));
    }
    return row;
}

void SHA3_State::setRow(int y, int z, bitset<5> input_row){
    for (int i = 0 ; i < 5 ; i ++){
        setBit(i, y, z, input_row.test(i));
    }
}

std::bitset<5> SHA3_State::getColumn(int x, int z){
    std::bitset<5> column = std::bitset<5>();
    for (int i = 0 ; i < 5 ; i ++){
        column.set(i, checkBit(x, i, z));
    }
    return column;
}

void SHA3_State::setColumn(int x, int z, bitset<5> input_column){
    for (int i = 0 ; i < 5 ; i ++){
        setBit(x, i, z, input_column.test(i));
    }
}

std::bitset<64> SHA3_State::getLane(int x, int y){
    std::bitset<64> lane = std::bitset<64>();
    for (int i = 0 ; i < w_ ; i ++){
        lane.set(i, checkBit(x, y, i));
    }
    return lane;
}

void SHA3_State::setLane(int x, int y, std::bitset<64> input_lane){
    for (int i = 0 ; i < 64 ; i ++){
        setBit(x, y, i, input_lane.test(i));
    }
}

int SHA3_State::mod(int val, int modulus){
    return (val % modulus + modulus) % modulus;
}

void SHA3_State::theta(){
    // Algorithm 1: θ(A) from NIST FIPS 202

    std::array<std::bitset<64>, 5> c = std::array<std::bitset<64>, 5>();
    for (int x = 0 ; x < 5 ; x ++){
        for (int z = 0 ; z < w_ ; z ++){
            bool c_xz0 = a_.at(x).at(0).test(z);
            bool c_xz1 = a_.at(x).at(1).test(z);
            bool c_xz2 = a_.at(x).at(2).test(z);
            bool c_xz3 = a_.at(x).at(3).test(z);
            bool c_xz4 = a_.at(x).at(4).test(z);
            c.at(x).set(z, c_xz0 ^ c_xz1 ^ c_xz2 ^ c_xz3 ^ c_xz4);
        }
    }

    std::array<std::bitset<64>, 5> d = std::array<std::bitset<64>, 5>();
    for (int x = 0 ; x < 5 ; x ++){
        for (int z = 0 ; z < w_ ; z ++){
            bool c_xmin = c.at(mod(x - 1, 5)).test(z);
            bool c_zmin = c.at(mod(x + 1, 5)).test(mod(z - 1, w_));
            d.at(x).set(z, c_xmin ^ c_zmin);
        }
    }

    for (int x = 0 ; x < 5 ; x ++){
        for (int y = 0 ; y < 5 ; y ++){
            for (int z = 0 ; z < w_ ; z ++){
                setBit(checkBit(x, y, z) ^ d.at(x).test(z), x, y, z);
            }
        }
    }
}


void SHA3_State::rho(){
    // Algorithm 2: ρ(A) from NIST FIPS 202

    std::array<std::array<int, 5>, 5> rho_matrix ={{{0,36,3,41,18}, {1,44,10,45,2}, {62,6,43,15,61}, {28,55,25,21,56}, {27,20,39,8,14}}};

    std::array<std::array<std::bitset<64>, 5>, 5> a_prime = std::array<std::array<std::bitset<64>, 5>, 5>();
    for (int x = 0 ; x < 5 ; x ++ ){
        for (int y = 0 ; y < 5 ; y ++){
            int select = rho_matrix.at(x).at(y);
            for (int z = 0 ; z < w_ ; z ++){
                bool select_bit = checkBit(x, y, mod(z - select, w_));
                a_prime.at(x).at(y).set(z, select_bit);
            }
        }
    }
    a_ = a_prime;
}

void SHA3_State::pi(){
    // Algorithm 2: ρ(A) from NIST FIPS 202

    std::array<std::array<std::bitset<64>, 5>, 5> a_prime = std::array<std::array<std::bitset<64>, 5>, 5>();
    for (int x = 0 ; x < 5 ; x ++ ){
        for (int y = 0 ; y < 5 ; y ++){
            for (int z = 0 ; z < w_ ; z ++){
                bool select_bit = checkBit(mod(x + 3 * y, 5), x, z);
                a_prime.at(x).at(y).set(z, select_bit);
            }
        }
    }
    a_ = a_prime;
}