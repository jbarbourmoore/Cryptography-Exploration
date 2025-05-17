/// This file handles generation of RSA Keys in C++
///
/// Libaries Used : OpenSSL BIGNUM for dealing with extremely large integers
/// Author        : Jamie Barbour-Moore
/// Created       : 05/12/25
/// Updated       : 05/14/25

#include "RSAKeyGeneration.hpp"

RSAKeyGenerationResult RSAKeyGeneration::generateRSAKeysUsingProvablePrimesWithAuxPrimes(int N1, int N2, bool use_key_quintuple_form){
    // generate a random public exponent
    BIGNUM *e = generateRandomE();
    char *hex_e = BN_bn2hex(e);
    printf("The value of e is %s\n", hex_e);
    OPENSSL_free(hex_e);

    int d_is_0 = 1;

    BIGNUM *n = BN_new();
    BIGNUM *d;

    BIGNUM *seed;
    ConstructPandQResult p_and_q;

    while(d_is_0){

        // generate a random seed
        seed = generateRandomSeed();
        char *hex_seed = BN_bn2hex(seed);
        printf("The value of seed is %s\n", hex_seed);
        OPENSSL_free(hex_seed);

        p_and_q =  constructTheProvablePrimesWithAuxillary(seed, N1, N2, e);
        if(p_and_q.success_){
            d = generatePrivateExponent(e,p_and_q.p_,p_and_q.q_);

            BN_mul(n, p_and_q.p_, p_and_q.q_, context_);
            const char *hex_d = BN_bn2hex(d);
            printf("The value of d is %s\n", hex_d);
            const char *hex_n = BN_bn2hex(n);
            printf("The value of n is %s\n", hex_n);
            d_is_0 = BN_is_zero(d);
            int e_retry = 0;
            while( d_is_0 and e_retry < 10){
                printf("retrying new e\n");
                e = generateRandomE();
                hex_e = BN_bn2hex(e);
                printf("The value of e is %s\n", hex_e);
                d = generatePrivateExponent(e,p_and_q.p_,p_and_q.q_);
                hex_d = BN_bn2hex(d);
                printf("The value of d is %s\n", hex_d);
                d_is_0 = BN_is_zero(d);
                e_retry++;
            }
        }
    }
    RSAPrivateKey private_key;
    if (use_key_quintuple_form){
        private_key = RSAPrivateKey(n, d, p_and_q.p_, p_and_q.q_, keylength_);
    } else {
        private_key = RSAPrivateKey(n, d, keylength_);
    }
    RSAPublicKey public_key = RSAPublicKey(n, e, keylength_);
    RSAKeyGenerationResult key_generation_result = RSAKeyGenerationResult(true,private_key,public_key,keylength_);
    return key_generation_result;
}

RSAKeyGenerationResult RSAKeyGeneration::generateRSAKeysUsingProvablePrimes(bool use_key_quintuple_form){
    // generate a random public exponent
    BIGNUM *e = generateRandomE();
    char *hex_e = BN_bn2hex(e);
    printf("The value of e is %s\n", hex_e);
    OPENSSL_free(hex_e);

    int d_is_0 = 1;

    BIGNUM *seed;
    BIGNUM *n = BN_new();
    BIGNUM *d;

    ConstructPandQResult result_primes;

    while(d_is_0){

        // generate a random seed
        seed = generateRandomSeed();
        char *hex_seed = BN_bn2hex(seed);
        printf("The value of seed is %s\n", hex_seed);
        OPENSSL_free(hex_seed);

        result_primes = constructTheProvablePrimes(seed, e);
        if(result_primes.success_){
            d = generatePrivateExponent(e,result_primes.p_,result_primes.q_);

            BN_mul(n, result_primes.p_, result_primes.q_, context_);
            const char *hex_d = BN_bn2hex(d);
            printf("The value of d is %s\n", hex_d);
            const char *hex_n = BN_bn2hex(n);
            printf("The value of n is %s\n", hex_n);
            d_is_0 = BN_is_zero(d);
            int e_retry = 0;
            while( d_is_0 and e_retry < 10){
                printf("retrying new e\n");
                e = generateRandomE();
                hex_e = BN_bn2hex(e);
                printf("The value of e is %s\n", hex_e);
                d = generatePrivateExponent(e,result_primes.p_,result_primes.q_);
                hex_d = BN_bn2hex(d);
                printf("The value of d is %s\n", hex_d);
                d_is_0 = BN_is_zero(d);
                e_retry ++;
            }
        }
    }
    RSAPrivateKey private_key;
    if (use_key_quintuple_form){
        private_key = RSAPrivateKey(n, d, result_primes.p_, result_primes.q_, keylength_);
    } else {
        private_key = RSAPrivateKey(n, d, keylength_);
    }
    RSAPublicKey public_key = RSAPublicKey(n, e, keylength_);
    RSAKeyGenerationResult key_generation_result = RSAKeyGenerationResult(true,private_key,public_key,keylength_);
    return key_generation_result;
}

ConstructPandQResult RSAKeyGeneration::constructTheProvablePrimesWithAuxillary(BIGNUM *seed, int N1, int N2, BIGNUM *e){

    ProvablePrimeGenerationResult result = constructAProvablePrimePotentiallyWithConditions(getPrimeLength(), N1, N2, seed, e);

    if (result.success_ != true) {
        printf("Failed to construct provable prime 'p'\n");
        return ConstructPandQResult();
    }

    BIGNUM *p = BN_new();
    BN_copy(p, result.prime_);
    BN_copy(seed, result.prime_seed_);

    result.freeResult();

    result = constructAProvablePrimePotentiallyWithConditions(getPrimeLength(), N1, N2, seed, e);

    if (result.success_ != true) {
        printf("Failed to construct provable prime 'q'\n");
        return ConstructPandQResult();
    }

    BIGNUM *q = BN_new();
    BN_copy(q, result.prime_);

    result.freeResult();

    ConstructPandQResult p_and_q_result = ConstructPandQResult(true, p, q);

    return p_and_q_result;
};


ConstructPandQResult RSAKeyGeneration::constructTheProvablePrimes(BIGNUM *seed, BIGNUM *e){


    
    ProvablePrimeGenerationResult result = constructAProvablePrimePotentiallyWithConditions(getPrimeLength(), 1, 1, seed, e);

    if (result.success_ != true) {
        printf("Failed to construct provable prime 'p'\n");
        result.freeResult();
        return ConstructPandQResult();
    }
    
    BIGNUM *p = BN_new();
    BN_copy(p, result.prime_);
    BN_copy(seed, result.prime_seed_);

    result.freeResult();

    result = constructAProvablePrimePotentiallyWithConditions(getPrimeLength(), 1, 1, seed, e);
    
    if (result.success_ != true) {
        printf("Failed to construct provable prime 'q'\n");
        return ConstructPandQResult();
    }
    
    BIGNUM *q = BN_new();
    BN_copy(q, result.prime_);

    result.freeResult();

    ConstructPandQResult p_and_q_result = ConstructPandQResult(true, p, q);

    return p_and_q_result;
};

ProvablePrimeGenerationResult RSAKeyGeneration::constructAProvablePrimePotentiallyWithConditions(int L, int N1, int N2, BIGNUM *first_seed, BIGNUM *e){
    // An instance of the result struct for if the function fails
    ProvablePrimeGenerationResult false_result = ProvablePrimeGenerationResult();

    BN_CTX *prime_gen_ctx = BN_CTX_new();
    BN_CTX_start(prime_gen_ctx);
    
    BIGNUM *number_one = BN_CTX_get(prime_gen_ctx);
    BN_set_word(number_one, 1);
    BIGNUM *number_two = BN_CTX_get(prime_gen_ctx);
    BN_set_word(number_two, 2);

    bool success_generating_p1 = false;
    // step 2 and 3
    // an auxillary prime of length N1
    BIGNUM *p1 = BN_CTX_get(prime_gen_ctx);
    // The prime seed to be used when generating p2
    BIGNUM *p2_seed = BN_CTX_get(prime_gen_ctx);

    if (N1 == 1){
        BN_set_word(p1, 1);
        BN_copy(p2_seed, first_seed);
        success_generating_p1 = true;
    } else {
        ShaweTaylorRandomPrimeResult random_prime = generateRandomPrimeWithShaweTaylor(N1, first_seed);
        BN_copy(p1, random_prime.prime_);
        BN_copy(p2_seed, random_prime.prime_seed_);
        success_generating_p1 = random_prime.success_;
        random_prime.freeResult();
    }

    if (!success_generating_p1){
        printf("Failed when attempting to generate p1\n");
        BN_CTX_end(prime_gen_ctx);
        BN_CTX_free(prime_gen_ctx);
        return false_result;
    }

    bool success_generating_p2 = false;

    // Step 4 and 6
    // an auxillary prime of length N2
    BIGNUM *p2 = BN_CTX_get(prime_gen_ctx);
    // the prime seed to be used when generating p0
    BIGNUM *p0_seed = BN_CTX_get(prime_gen_ctx);

    if (N2 == 1){
        BN_set_word(p2,1);
        BN_copy(p0_seed, p2_seed);
        success_generating_p2 = true;
    } else {
        ShaweTaylorRandomPrimeResult random_prime = generateRandomPrimeWithShaweTaylor(N2, p2_seed);
        BN_copy(p2, random_prime.prime_);
        BN_copy(p0_seed, random_prime.prime_seed_);
        success_generating_p2 = random_prime.success_;
        random_prime.freeResult();
    }

    BN_free(p2_seed);

    if (!success_generating_p2){
        printf("Failed when attempting to generate p2\n");
        BN_CTX_end(prime_gen_ctx);
        BN_CTX_free(prime_gen_ctx);
        return false_result;
    }

    // ceil(L / 2) + 1
    int length = L/2;
    if (L % 2 != 0) {
        length += 1;
    }

    // Step 6
    // the result of the prime generation using shawe taylor to find p0
    ShaweTaylorRandomPrimeResult shawe_taylor_result = generateRandomPrimeWithShaweTaylor(length, p0_seed);
    if (shawe_taylor_result.success_ == false){
        printf("Failed when attempting to generate p0\n");
        BN_CTX_end(prime_gen_ctx);
        BN_CTX_free(prime_gen_ctx);
        return false_result;
    }

    BN_free(p0_seed);

    // The generated value for p0 from the shawe taylor result in step 6
    BIGNUM *p0 =  BN_CTX_get(prime_gen_ctx);
    BN_copy(p0, shawe_taylor_result.prime_);

    // The generated value for pseed from the shawe taylor result in step 6
    BIGNUM *pseed =  BN_CTX_get(prime_gen_ctx);
    BN_copy(pseed, shawe_taylor_result.prime_seed_);

    shawe_taylor_result.freeResult();

    // Step 7
    // the result of the greatest common denominator of p0p1 and p2
    BIGNUM *gcd_result = BN_CTX_get(prime_gen_ctx);
    // p0 * p1
    BIGNUM *p0p1 = BN_CTX_get(prime_gen_ctx);
    BN_mul(p0p1, p0, p1, context_);
    BN_gcd(gcd_result, p0p1, p2, context_);
    if(BN_is_one(gcd_result) != 1){
        printf("The gcd of p0p1 and p2 is not 1");
        BN_CTX_end(prime_gen_ctx);
        BN_CTX_free(prime_gen_ctx);
        return false_result;
    }

    // Step 8
    int iteration = L / hash_length_;
    if (L % hash_length_ == 0 and iteration != 0){
        iteration -= 1;
    }

    // Step 9
    // A counter to track how many iterations have been ran while attempting to generate the prime
    int pgen_counter = 0;

    // step 18
    BIGNUM *x = BN_CTX_get(prime_gen_ctx);
    BN_set_word(x, 0);

    // step 19
    // BIGNUM *hash_for_x;
    BIGNUM *two_to_ihashlen = BN_CTX_get(prime_gen_ctx);
    BIGNUM *prime_seed_inc_i = BN_CTX_get(prime_gen_ctx);
    BIGNUM *hash_result = BN_CTX_get(prime_gen_ctx);
    for (int i = 0; i <= iteration; i ++){
        BN_set_word(two_to_ihashlen, i * hash_length_);
        BN_exp(two_to_ihashlen, number_two, two_to_ihashlen, context_);
        BIGNUM *i_bn = BN_new();
        BN_set_word(i_bn, i);
        BN_add(prime_seed_inc_i, i_bn, pseed);
        PassBigNum pass_prime_seed_inc = PassBigNum(prime_seed_inc_i);
        BigNumHelpers::sha512BigNum(pass_prime_seed_inc).copyAndClear(hash_result);
        BN_mul(hash_result,hash_result,two_to_ihashlen,context_);
        BN_add(x, x, hash_result);
    }

    BN_add_word(pseed, iteration + 1);

    // step 13
    // the modulus for x (2**L - sq2 * 2**(L-1))
    BIGNUM *x_modulus = BN_CTX_get(prime_gen_ctx);
    // the value of L as a BIGNUM
    BIGNUM *l_bn = BN_CTX_get(prime_gen_ctx);
    BN_set_word(l_bn, L);
    BN_exp(x_modulus, number_two, l_bn, context_);
    BN_sub(x_modulus, x_modulus, min_prime_value_);
    BN_mod(x, x, x_modulus, context_);
    BN_add(x, x, min_prime_value_);

    // hex_x = BN_bn2hex(x);
    // printf("x : %s\n", hex_x);

    // Step 14
    // The inverse of p0p1 in the modulus p2
    BIGNUM *y = BN_CTX_get(prime_gen_ctx);
    BN_mod_inverse(y, p0p1, p2, context_);

    // Step 15
    // The value of t as a BIGNUM
    BIGNUM *t = BN_CTX_get(prime_gen_ctx);
    // the remainder when calculating t
    BIGNUM *t_r = BN_CTX_get(prime_gen_ctx);
    // The numerator for calculating t (2yp0p1 + x)
    BIGNUM *t_num = BN_CTX_get(prime_gen_ctx);
    // 2 * y * p0 * p1
    BIGNUM *two_y_p0p1 = BN_CTX_get(prime_gen_ctx);
    // The denominator for calculating t (2p0p1p2)
    BIGNUM *t_den = BN_CTX_get(prime_gen_ctx);
    BN_mul(two_y_p0p1, p0p1,number_two, context_);
    BN_mul(two_y_p0p1, two_y_p0p1, y, context_);
    BN_add(t_num, two_y_p0p1, x);
    BN_mul(t_den, p0p1, number_two, context_);
    BN_mul(t_den, t_den, p2, context_);
    BN_div(t, t_r, t_num, t_den, context_);
    if (BN_is_zero(t_r) != 1){
        BN_add_word(t, 1);
    }
    // const char *hex_t = BN_bn2hex(t);
    // printf("t : %s\n", hex_t);

    int max_counter = 10*L;
    while(pgen_counter <= max_counter){
        // Step 16 
        // p =  (2(t p2 − y) p0 p1 + 1)
        BIGNUM *p = BN_new();
        BN_mul(p, t, p2, context_);
        BN_sub(p, p, y);
        BN_mul_word(p, 2);
        BN_mul(p, p, p0p1, context_);
        BN_add_word(p, 1);
        BIGNUM *two_to_L = BN_new();
        BN_exp(two_to_L, number_two, l_bn, context_);
        if(BN_cmp(p, two_to_L) == 1){
            BN_add(t_num, two_y_p0p1, min_prime_value_);
            BN_div(t,t_r,t_num,t_den,context_);
            if (BN_is_zero(t_r) != 1){
                BN_add_word(t, 1);
            }
        }
        // const char *p_start_hex = BN_bn2hex(p);
        // printf("p start : %s\n",p_start_hex);
        // Step 18
        pgen_counter += 1;

        BN_sub(gcd_result, p, number_one);
        BN_gcd(gcd_result, gcd_result, e, context_);

        //step 19
        if (BN_is_odd(gcd_result) == 1){
            // printf("hi");
            // step 19.1
            BIGNUM *a = BN_new();
            BN_set_word(a, 0);
        
            // printf("iterations : %d\n",iteration);
            // step 19.2
            for (int i = 0; i <= iteration; i ++){
                BN_set_word(two_to_ihashlen, i * hash_length_);
                BN_exp(two_to_ihashlen, number_two, two_to_ihashlen, context_);
                BN_set_word(prime_seed_inc_i, i);
                BN_add(prime_seed_inc_i,prime_seed_inc_i,pseed);
                PassBigNum pass_prime_seed_inc = PassBigNum(prime_seed_inc_i);
                BigNumHelpers::sha512BigNum(pass_prime_seed_inc).copyAndClear(prime_seed_inc_i);
                BN_mul(prime_seed_inc_i,prime_seed_inc_i,two_to_ihashlen,context_);
                BN_add(a, a, prime_seed_inc_i);
                // printf("this loop\n");
            }

            // char *hex_a = BN_bn2hex(a);
            // printf("a : %s\n",hex_a);

            // step 19.3
            BN_add_word(pseed, iteration + 1);

            // step 19.4 : a = 2 + a mod (p - 3)
            // temporary variable for p -3
            BIGNUM *p_min_3 = BN_CTX_get(prime_gen_ctx);
            BN_copy(p_min_3, p);
            BN_sub_word(p_min_3, 3);
            BN_mod(a, a, p_min_3, context_);
            BN_add_word(a, 2);
            // const char *a_hex = BN_bn2hex(a);
            // printf("a : %s\n", a_hex);

            // temporary variable for z (z = a ** (2(t p2 − y) p1) mod p)
            BIGNUM *z = BN_CTX_get(prime_gen_ctx);
            BN_mul(z, t, p2, context_);
            BN_sub(z, z, y);
            BN_mul_word(z, 2);
            BN_mul(z, z, p1, context_);
            BN_mod_exp(z, a, z, p, context_);

            BIGNUM *z_minus_1 = BN_CTX_get(prime_gen_ctx);
            BN_sub(z_minus_1, z, number_one);
            BN_gcd(gcd_result, z_minus_1, p, context_);
            // const char *gcd_result_hex = BN_bn2hex(gcd_result);
            // printf("gcd : %s\n",gcd_result_hex);
            if(BN_is_one(gcd_result) == 1){
                // const char *p_hex = BN_bn2hex(p);
                // printf("p end   : %s\n",p_hex);
                BIGNUM *z_p0_modp = BN_CTX_get(prime_gen_ctx);
                BN_mod_exp(z_p0_modp, z, p0, p, context_);
                
                if(BN_is_one(z_p0_modp) == 1){
                    // const char *hex_c = BN_bn2hex(p);
                    // printf("p : %s\n",hex_c);    
                    ProvablePrimeGenerationResult final_result =ProvablePrimeGenerationResult(true, p, p1, p2, pseed);
                    BN_free(x);
                    BN_free(y);
                    BN_free(a);
                    BN_free(z);
                    BN_free(p0p1);
                    BN_free(two_to_ihashlen);

                    // BN_CTX_end(prime_gen_ctx);
                    // BN_CTX_free(prime_gen_ctx);
                    // printf("final result length %d : %b\n", L, final_result.success_);  
                    return final_result;
                }
            }

            // //printf("max counter : %d\n",max_counter);
            // //printf("iteration %d\n", iteration);
            // // step 32
            if (pgen_counter > max_counter){
                printf("Failed with gen_counter %d\n",pgen_counter);
                BN_free(x);
                BN_free(y);
                BN_free(a);
                BN_free(z);
                BN_free(p0p1);
                BN_free(two_to_ihashlen);
                BN_free(two_to_L);
                return false_result;
                
            }

            BN_add_word(t, 1);

        }
    }


    return false_result;
};