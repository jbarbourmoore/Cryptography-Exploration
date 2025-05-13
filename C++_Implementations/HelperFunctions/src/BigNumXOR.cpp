/// This file is a helper function for Byte Wise XOR of openSSL BIGNUM
///
/// Libaries Used : OpenSSL BIGNUM for dealing with extremely large integers
/// Author        : Jamie Barbour-Moore
/// Created       : 05/13/25
/// Updated       : 05/13/25

#include "BigNumHelpers.hpp"

BIGNUM* BigNumHelpers::xorBigNums(BIGNUM* first_bn, BIGNUM* second_bn){
    int first_num_bytes = BN_num_bytes(first_bn);
    int second_num_bytes = BN_num_bytes(second_bn);

    // Find the maximum byte length of the two inputs
    int max_bytes = first_num_bytes;
    if (second_num_bytes > max_bytes){
        max_bytes = second_num_bytes;
    }
    
    // Create two character arrays of the maximum byte length and populate them with the inputes (padded if necessary)
    unsigned char first_char_array[max_bytes];
    unsigned char second_char_array[max_bytes];
    if (first_num_bytes == second_num_bytes) {
        BN_bn2bin(first_bn, first_char_array);
        BN_bn2bin(second_bn, second_char_array);
    } else if (first_num_bytes > second_num_bytes) {
        BN_bn2bin(first_bn, first_char_array);
        BN_bn2binpad(second_bn, second_char_array, max_bytes);
    } else {
        BN_bn2binpad(first_bn, first_char_array, max_bytes);
        BN_bn2bin(second_bn, second_char_array);
    }

    // Perform the XOR of each Byte
    unsigned char result_char_array[max_bytes];
    for(int i = 0; i < max_bytes; ++i) {
        result_char_array[i] = first_char_array[i] ^ second_char_array[i];
    }

    // Transform the result into a new BIGNUM and return
    BIGNUM *result = BN_new();
    BN_bin2bn(result_char_array, max_bytes, result);
    return result;
}