/// This is my main method for AES Experimentation in C++
///
/// Author        : Jamie Barbour-Moore
/// Created       : 05/22/25

#include "AES.hpp"
#include <cassert>

int main(int argc, char const *argv[])
{
    unsigned char value = 0x57;
    unsigned char test_values[9] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x13};
    unsigned char exp_res[9] = {0x57, 0xae, 0x47, 0x8e, 0x07, 0x0e, 0x1c,0x38, 0xfe};
    unsigned char result;
    for (int i = 0; i < 9; i++){
        result = AES::xTimes(value, test_values[i]);
        printf("xTimes(%.2x, %.2x) = %.2x (exp = %.2x)\n", value, test_values[i], result, exp_res[i]);
        assert(result == exp_res[i]);
    }
    

    unsigned char mix_col_example[16] = {0xf2, 0x01, 0xc6, 0xdb, 0x0a, 0x01, 0xc6, 0x13, 0x22, 0x01, 0xc6, 0x53, 0x5c, 0x01, 0xc6, 0x45};
    unsigned char exp_mix[16] = {0x9f, 0x01, 0xc6, 0x8e, 0xdc, 0x01, 0xc6, 0x4d, 0x58, 0x01, 0xc6, 0xa1, 0x9d, 0x01, 0xc6, 0xbc};
    printf("\nExample Matrix\n");
    AES::print4x4Matrix(mix_col_example);
    AES::mixColumns(mix_col_example);
    printf("Mixed Columns\n");
    AES::print4x4Matrix(mix_col_example);
    for (int i = 0; i < 16; i++){
        assert(mix_col_example[i] == exp_mix[i]);
    }
    printf("Inverse Mixed Columns\n");
    AES::invMixColumns(mix_col_example);
    AES::print4x4Matrix(mix_col_example);
    return 0;
}