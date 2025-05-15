#include "BigNumHelpers.hpp"

unsigned long long int BigNumHelpers::bnToUnsignedLongLong(BIGNUM*input){
    if (BN_num_bits(input) >= 63){
        return 0;
    }

    char *input_str = BN_bn2dec(input);
    // printf("%s",input_str);
    unsigned long long int number = atoll(input_str);

    return number;
}