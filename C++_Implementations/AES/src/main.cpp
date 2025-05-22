/// This is my main method for AES Experimentation in C++
///
/// Author        : Jamie Barbour-Moore
/// Created       : 05/22/25

#include "AESState.hpp"
#include <cassert>

int main(int argc, char const *argv[])
{
    unsigned char value = 0x57;
    unsigned char test_values[9] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x13};
    unsigned char exp_res[9] = {0x57, 0xae, 0x47, 0x8e, 0x07, 0x0e, 0x1c,0x38, 0xfe};
    unsigned char result;
    for (int i = 0; i < 9; i++){
        result = AESState::xTimes(value, test_values[i]);
        printf("xTimes(%.2x, %.2x) = %.2x (exp = %.2x)\n", value, test_values[i], result, exp_res[i]);
        assert(result == exp_res[i]);
    }
    

    unsigned char mix_col_example[16] = {0xf2, 0x01, 0xc6, 0xdb, 0x0a, 0x01, 0xc6, 0x13, 0x22, 0x01, 0xc6, 0x53, 0x5c, 0x01, 0xc6, 0x45};
    unsigned char exp_mix[16] = {0x9f, 0x01, 0xc6, 0x8e, 0xdc, 0x01, 0xc6, 0x4d, 0x58, 0x01, 0xc6, 0xa1, 0x9d, 0x01, 0xc6, 0xbc};
    AESState s = AESState{mix_col_example};
    printf("\nMix Columns Example Matrix\n");
    s.printState();
    s.mixColumns();
    printf("Mixed Columns\n");
    s.printState();
    for (int i = 0; i < 16; i++){
        assert(s.getByte(i) == exp_mix[i]);
    }
    printf("Inverse Mixed Columns\n");
    s.invMixColumns();
    s.printState();

    unsigned char sub_example[16] = {0x53, 0x01, 0xc6, 0xdb, 0x0a, 0x01, 0xc6, 0x13, 0x22, 0x01, 0xc6, 0x53, 0x5c, 0x01, 0xc6, 0x45,};
    unsigned char exp_sub[16] = {0xed, 0x7c, 0xb4, 0xb9, 0x67, 0x7c, 0xb4, 0x7d, 0x93, 0x7c, 0xb4, 0xed, 0x4a, 0x7c, 0xb4, 0x6e,};
    s = AESState{sub_example};
    printf("\nSub Bytes Example Matrix\n");
    s.printState();
    s.subBytes();
    printf("Substituted Bytes\n");
    s.printState();
    for (int i = 0; i < 16; i++){
        assert(s.getByte(i) == exp_sub[i]);
    }
    printf("Inverse Substituted Bytes\n");
    s.invSubBytes();
    s.printState();

    unsigned char shift_example[16] = {0xed, 0x7c, 0xb4, 0xb9, 0x67, 0x7c, 0xb4, 0x7d, 0x93, 0x7c, 0xb4, 0xed, 0x4a, 0x7c, 0xb4, 0x6e,};
    unsigned char exp_shift[16] = {0xed, 0x7c, 0xb4, 0xb9, 0x7c, 0xb4, 0x7d, 0x67, 0xb4, 0xed, 0x93, 0x7c, 0x6e, 0x4a, 0x7c, 0xb4};
    s = AESState{shift_example};
    printf("\nShift Rows Example Matrix\n");
    s.printState();
    s.shiftRows();
    printf("Shifted Rows\n");
    s.printState();
    for (int i = 0; i < 16; i++){
        assert(s.getByte(i) == exp_shift[i]);
    }
    s.invShiftRows();
    printf("Inverse Shifted Rows\n");
    s.printState();
    
    return 0;
}