#include "BigNumHelpers.hpp"

std::vector<unsigned long long int> BigNumHelpers::primeSieve(BIGNUM* maximum_bignum){

    unsigned long long int max_val = bnToUnsignedLongLong(maximum_bignum);

    unsigned long long int potential_prime = 2;
    std::vector<bool> is_prime_list( max_val, true );

    while(potential_prime * potential_prime <= max_val){
        // printf("potential prime : %lld - ",potential_prime);
        if (is_prime_list[potential_prime] == true){

            for(unsigned long long int i = 2 * potential_prime; i <= max_val; i+=potential_prime){
                // printf("%lld ",i);
                is_prime_list[i] = false;
            }
        }
        // printf("\n");
        potential_prime += 1;
    }

    std::vector<unsigned long long int> prime_list;
    for(unsigned long long int i = 2; i < max_val; i ++){
        if (is_prime_list[i] == true){
            prime_list.push_back(i);
        }
    }
    return prime_list;
}

std::vector<unsigned long long int> BigNumHelpers::primeSieve(unsigned long long int max_val){

    // bool is_prime_list[max_val] = {true};

    unsigned long long int potential_prime = 2;
    std::vector<bool> is_prime_list( max_val, true );

    while(potential_prime * potential_prime <= max_val){
        // printf("potential prime : %lld - ",potential_prime);
        if (is_prime_list[potential_prime] == true){

            for(unsigned long long int i = potential_prime; i <= max_val; i+=potential_prime){
                // printf("%lld ",i);
                is_prime_list[i] = false;
            }
        }
        // printf("\n");
        potential_prime += 1;
    }

    std::vector<unsigned long long int> prime_list;
    for(unsigned long long int i = 0; i < max_val; i ++){
        if (is_prime_list[i] == true){
            prime_list.push_back(i);
        }
    }
    return prime_list;
}