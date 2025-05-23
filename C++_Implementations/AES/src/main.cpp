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

    unsigned char key_128[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    AESKey::keyExpansion(key_128,AES_KEY_128);

    unsigned char key_192[24] = {0x8e ,0x73 ,0xb0 ,0xf7 ,0xda ,0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b};
    AESKey::keyExpansion(key_192,AES_KEY_192);

    unsigned char key_256[32] = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
    AESKey::keyExpansion(key_256, AES_KEY_256);

    // unsigned char hex_to_cypher[16] = {0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A};
    // unsigned char hex_to_cypher[16] = {0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E,0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51};
    unsigned char hex_to_cypher[16] = {0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF};
    AESDataBlock input_block = AESDataBlock("F69F2445DF4F9B17AD2B417BE66C3710", true);
    AESDataBlock cypher_hex = AES::AES128Cypher(input_block, key_128);
    input_block.print();
    printf("\nCypher Result With AES 128\n");
    cypher_hex.print();
    printf("Inverse Cypher Result With AES 128\n");
    AESDataBlock inverse_cypher_hex = AES::AES128InvCypher(cypher_hex, key_128);
    inverse_cypher_hex.print();
    
    printf("\n");
    printf("\nCypher Result With AES 192\n");
    AESDataBlock cypher_hex_192 = AES::AES192Cypher(input_block, key_192);
    cypher_hex_192.print();
    AESDataBlock inverse_cypher_hex_192 = AES::AES192InvCypher(cypher_hex_192, key_192);
    printf("Inverse Cypher Result With AES 192\n");
    inverse_cypher_hex_192.print();

    printf("\n");
    printf("\nCypher Result With AES 256\n");
    AESDataBlock cypher_hex_256 = AES::AES256Cypher(input_block, key_256);
    cypher_hex_256.print();
    AESDataBlock inverse_cypher_hex_256 = AES::AES256InvCypher(cypher_hex_256, key_256);
    printf("Inverse Cypher Result With AES 256\n");
    inverse_cypher_hex_256.print();
    printf("\n");
    return 0;
}