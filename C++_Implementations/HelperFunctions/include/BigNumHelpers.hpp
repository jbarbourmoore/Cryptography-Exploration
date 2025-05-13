#ifndef BigNumHelpers_HPP
#define BigNumHelpers_HPP

#include <openssl/bn.h>
#include <bits/stdc++.h>

class BigNumHelpers{
    public:
        /// @brief This method performs a Byte Wise Xor for two big numbers
        /// @param first_bn The first big number to be XORed
        /// @param second_bn The second big number to be xored
        /// @return The result of the bytewise XOR operation as a big number
        static BIGNUM* xorBigNums(BIGNUM* first_bn, BIGNUM* second_bn);
};
#endif