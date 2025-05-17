#include "RSAKeyGeneration.hpp"

ShaweTaylorRandomPrimeResult RSAKeyGeneration::shaweTaylorShort(int length, PassBigNum input_seed_passed){

    int hash_length_ = 512;
    

    BN_CTX *ctx_shawe_short = BN_CTX_secure_new();

    assert(ctx_shawe_short != NULL);

    BN_CTX_start(ctx_shawe_short);

    BIGNUM *number_one = BN_CTX_get(ctx_shawe_short);
    BN_set_word(number_one, 1);
    BIGNUM *number_two = BN_CTX_get(ctx_shawe_short);
    BN_set_word(number_two, 2);

    BIGNUM *prime_seed = BN_CTX_get(ctx_shawe_short);
    input_seed_passed.copyAndClear(prime_seed);

    int prime_gen_counter = 0;
    int max_counter = length * 10;
    bool prime_found = false;

    BIGNUM *c = BN_CTX_get(ctx_shawe_short);

    while (prime_gen_counter <= max_counter && !prime_found){
\
        // step 5 : XOR(hash(pseed),hash(pseed+1))
        BIGNUM *hash_prime_seed = BN_CTX_get(ctx_shawe_short);

        PassBigNum prime_seed_to_hash = PassBigNum(prime_seed);
        BigNumHelpers::sha512BigNum(prime_seed_to_hash).copyAndClear(hash_prime_seed);
        BIGNUM *inc_seed = BN_CTX_get(ctx_shawe_short);
        BN_add(inc_seed, prime_seed, number_one);
        BIGNUM *hash_inc_seed = BN_CTX_get(ctx_shawe_short);
        PassBigNum prime_inc_seed_to_hash = PassBigNum(inc_seed);
        BigNumHelpers::sha512BigNum(prime_inc_seed_to_hash).copyAndClear(hash_inc_seed);
        c = BigNumHelpers::xorBigNums(hash_prime_seed, hash_inc_seed);

        // step 6
        BIGNUM *c_base = BN_CTX_get(ctx_shawe_short);
        BIGNUM *length_min_1 = BN_CTX_get(ctx_shawe_short);
        BN_set_word(length_min_1, length - 1);
        BN_exp(c_base, number_two, length_min_1, context_);
        BN_mod(c, c, c_base, context_);
        BN_add(c, c, c_base);

        // step 7 : make sure c is odd
        if(BN_is_odd(c) == 0){
            BN_add(c, c, number_one);
        }

        // step 8 : inc prime gen counter by one
        prime_gen_counter += 1;

        // step 9 : inc prime seed by two
        BN_add(prime_seed, prime_seed, number_two);
        
        // step 10 & 11 : return prime if it is in fact prime

        if (BN_check_prime(c,context_, nullptr)==1){
            prime_found = true;
        }
    }

    ShaweTaylorRandomPrimeResult short_shawe_result;
    
    if(prime_found){
        short_shawe_result = ShaweTaylorRandomPrimeResult(true, c, prime_seed, prime_gen_counter);
    } else {
        short_shawe_result = ShaweTaylorRandomPrimeResult();
    }

    if(ctx_shawe_short){
        BN_CTX_end(ctx_shawe_short);
        BN_CTX_free(ctx_shawe_short);
    }
    return short_shawe_result;
}

ShaweTaylorRandomPrimeResult RSAKeyGeneration::generateRandomPrimeWithShaweTaylor(int length, PassBigNum input_seed_passed){
    
    BIGNUM* prime_seed = BN_new();
    input_seed_passed.copyAndClear(prime_seed);
    ShaweTaylorRandomPrimeResult result;

    PassBigNum seed_to_pass = PassBigNum(prime_seed);
    
    if (length < 33) {

        result = shaweTaylorShort(length, seed_to_pass);
    } else {
        // step 14
        ShaweTaylorRandomPrimeResult previous_recursion_result = generateRandomPrimeWithShaweTaylor(length/2, seed_to_pass);

        BN_CTX *shawe_ctx = BN_CTX_new();
        assert(shawe_ctx != NULL);
        BN_CTX_start(shawe_ctx);

        BIGNUM *number_one = BN_CTX_get(shawe_ctx);
        BN_set_word(number_one, 1);
        BIGNUM *number_two = BN_CTX_get(shawe_ctx);
        BN_set_word(number_two, 2);

        int prime_gen_counter = 0;
        int max_counter = length * 10;
    

        // step 15
        if (previous_recursion_result.success_ == false) {
            result = ShaweTaylorRandomPrimeResult();
        } else {
            // the candidate prime
            BIGNUM *c = BN_CTX_get(shawe_ctx);
            BIGNUM *c0 = BN_CTX_get(shawe_ctx);
            BIGNUM *x = BN_CTX_get(shawe_ctx);
            BIGNUM *two_to_ihashlen = BN_CTX_get(shawe_ctx);
            BIGNUM *prime_seed_inc_i = BN_CTX_get(shawe_ctx);
            BIGNUM *hash_value = BN_CTX_get(shawe_ctx);
            BIGNUM *two_length_1_bn = BN_CTX_get(shawe_ctx);
            BIGNUM *two_c0 = BN_CTX_get(shawe_ctx);
            BIGNUM *t = BN_CTX_get(shawe_ctx);
            BIGNUM *t_rem = BN_CTX_get(shawe_ctx);
            // temporary variable for 2 * c_0
            BIGNUM *t2c0 = BN_CTX_get(shawe_ctx);
            // temporary variable for 2 ** length
            BIGNUM *two_to_length = BN_CTX_get(shawe_ctx);
            // temporary variable for length as a BIGNUM
            BIGNUM *length_bn = BN_CTX_get(shawe_ctx);
            // temporary variable for a
            BIGNUM *a = BN_CTX_get(shawe_ctx);
            BIGNUM *gcd_result = BN_CTX_get(shawe_ctx);
            BIGNUM *z_c0_modc = BN_CTX_get(shawe_ctx);

            // step 16
            int iteration = length / hash_length_;
            if (length % hash_length_ == 0 and iteration != 0){
                iteration -= 1;
            }

            BN_copy(c0, previous_recursion_result.prime_);
            BN_copy(prime_seed, previous_recursion_result.prime_seed_);
            max_counter = length * 4 + previous_recursion_result.prime_gen_counter_;

            previous_recursion_result.freeResult();
        
            // step 18
            BN_set_word(x, 0);

            // step 19        
            for (int i = 0; i <= iteration; i ++){
                BN_set_word(two_to_ihashlen, i * hash_length_);
                BN_exp(two_to_ihashlen, number_two, two_to_ihashlen, context_);
                BN_set_word(prime_seed_inc_i, i);
                BN_add(prime_seed_inc_i,prime_seed_inc_i,prime_seed);
                PassBigNum pass_prime_seed_inc = PassBigNum(prime_seed_inc_i);
                BigNumHelpers::sha512BigNum(pass_prime_seed_inc).copyAndClear(hash_value);
                BN_mul(prime_seed_inc_i, hash_value, two_to_ihashlen,context_);
                BN_add(x, x, prime_seed_inc_i);
            }

            // step 20
            BN_add_word(prime_seed, iteration + 1);

            // step 21
            BN_set_word(two_length_1_bn, length - 1);
            BN_exp(two_length_1_bn,number_two, two_length_1_bn, context_);
            BN_mod(x,  x,two_length_1_bn, context_);
            BN_add(x, x, two_length_1_bn);

            // step 22
            BN_mul(two_c0, c0, number_two, context_);
            BN_div(t, t_rem, x, two_c0, context_);
            if (BN_is_zero(t_rem) != 1){
                BN_add_word(t, 1);
            }

            while (prime_gen_counter <= max_counter){

                // step 23
                
                BN_mul(t2c0, t, two_c0, context_);
                BN_set_word(length_bn, length);
                BN_exp(two_to_length, number_two, length_bn, context_);
                int cmp_t2c0_2toL = BN_cmp(t2c0, two_to_length);
                if(cmp_t2c0_2toL == 0 or cmp_t2c0_2toL == 1){
                    BN_div(t, t_rem, two_length_1_bn, two_c0, context_);
                    if (BN_is_zero(t_rem) != 1){
                        BN_add_word(t, 1);
                    }
                }

                // step 24
                
                BN_mul(c, two_c0, t, context_);
                BN_add_word(c, 1);

                // step 25
                prime_gen_counter += 1;

                // step 26
                
                BN_set_word(a, 0);
                
                hash_value = BN_CTX_get(shawe_ctx);
                // step 27
                for (int i = 0; i <= iteration; i ++){
                    BN_set_word(two_to_ihashlen, i * hash_length_);
                    BN_exp(two_to_ihashlen, number_two, two_to_ihashlen, context_);
                    BN_set_word(prime_seed_inc_i, i);
                    BN_add(prime_seed_inc_i,prime_seed_inc_i,prime_seed);
                    PassBigNum pass_prime_seed_inc = PassBigNum(prime_seed_inc_i);
                    BigNumHelpers::sha512BigNum(pass_prime_seed_inc).copyAndClear(hash_value);
                    BN_mul(prime_seed_inc_i, hash_value, two_to_ihashlen,context_);
                    BN_add(a, a, prime_seed_inc_i);
                }

                // step 28
                BN_add_word(prime_seed, iteration + 1);

                // step 29 : a = 2 + a mod (c - 3)
                // temporary variable for c -3
                BIGNUM *c_min_3 = BN_CTX_get(shawe_ctx);
                BN_copy(c_min_3, c);
                BN_sub_word(c_min_3, 3);
                BN_mod(a, a, c_min_3, context_);
                BN_add_word(a, 2);

                // step 30 : z = a ** 2t mod c
                // temporary variable for z (z = a ** 2t mod c)
                BIGNUM *z = BN_CTX_get(shawe_ctx);
                BN_mul(z, t, number_two, context_);
                BN_mod_exp(z, a, z, c, context_);
                
                // step 31
                gcd_result = BigNumHelpers::gcdValueMinusOneSecondValue(z, c);
                
                if (BN_is_one(gcd_result) == 1) {
                    BN_mod_exp(z_c0_modc, z, c0, c, context_);
                    if (BN_is_one(z_c0_modc) == 1) {
                        result = ShaweTaylorRandomPrimeResult(true, c, prime_seed, prime_gen_counter);
                        BN_CTX_end(shawe_ctx);
                        BN_CTX_free(shawe_ctx);
                        break;
                    }
                }

                // step 32
                if (prime_gen_counter >= max_counter){
                    printf("Failed with gen_counter %d\n",prime_gen_counter);
                    result = ShaweTaylorRandomPrimeResult();
                    BN_CTX_end(shawe_ctx);
                    BN_CTX_free(shawe_ctx);
                    break;
                }
                BN_add_word(t, 1);
            }
        }
    }
    BN_free(prime_seed);
    return result;
};
