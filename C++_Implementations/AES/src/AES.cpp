#include "AES.hpp"

unsigned char AES::xTimes(unsigned char byte_to_multiply, int mult_factor){
    unsigned char result = 0;
    if(mult_factor == 1){
        result = byte_to_multiply;
    }
    else if(mult_factor == 2){
        result = (byte_to_multiply << 1) & 0xff;
        if(result >= 128){
            result = result ^ 0x1b;
        }
    }
    else if (mult_factor % 2 == 0){
        unsigned char x_time_res = xTimes(byte_to_multiply, mult_factor / 2);
        result = (x_time_res << 1) && 0xff;
        if(result >= 128){
            result = result ^ 0x1b;
        }
    }
    else {
        result = xTimes(byte_to_multiply, mult_factor - 1);
        result = result ^ byte_to_multiply;
    }
    return result;
}