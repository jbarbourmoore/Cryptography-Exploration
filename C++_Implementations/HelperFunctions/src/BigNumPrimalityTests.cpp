#include "BigNumHelpers.hpp"

int BigNumHelpers::trialDivision(BIGNUM* candidate_prime_bn){
    if (BN_num_bits(candidate_prime_bn) >= 63){
        return -1;
    }

    unsigned long long int candidate_prime = BigNumHelpers::bnToUnsignedLongLong(candidate_prime_bn);
    unsigned long long int square_root = calculateSquareRoot(candidate_prime);

    std::vector<unsigned long long int> prime_list = BigNumHelpers::primeSieve(candidate_prime);

    for (unsigned long long i = 0; i < prime_list.size(); i++){
        // if (candidate_prime % prime_list[i] == 0){
        //     return 0;
        // }
        if (std::gcd(candidate_prime, prime_list[i]) != 1){
            printf("%lld\n",prime_list[i]);
            return 0;
        }
    }
    return 1;
}

int gcd(unsigned long long int first_number, unsigned long long int second_number) {

    if (first_number == 0)
        return second_number;
    if (second_number == 0)
        return first_number;
    if (first_number == second_number)
        return first_number;
    if (first_number > second_number)
      return gcd(first_number - second_number, second_number);
    return gcd(first_number, second_number - first_number);
}
unsigned long long int BigNumHelpers::calculateSquareRoot(unsigned long long int value) {

    unsigned long long int low = 0, high = value, result = 0;
    while (low <= high) {
        unsigned long long int middle = low + (high - low) / 2;

        if (middle * middle <= value) {
            result = middle;
            low = middle + 1;
        } else {
            high = middle - 1;
        }
    }

    return result;
}