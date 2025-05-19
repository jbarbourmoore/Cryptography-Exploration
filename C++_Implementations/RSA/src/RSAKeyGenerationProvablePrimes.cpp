/// This file handles generation of RSA Keys in C++
///
/// Libaries Used : OpenSSL BIGNUM for dealing with extremely large integers
/// Author        : Jamie Barbour-Moore
/// Created       : 05/12/25
/// Updated       : 05/14/25

#include "RSAKeyGeneration.hpp"

RSAKeyGenerationResult RSAKeyGeneration::generateRSAKeysUsingProvablePrimesWithAuxPrimes(int bitlen1, int bitlen2, int bitlen3, int bitlen4, bool use_key_quintuple_form){
    
    // The context for this function generating RSA Keys using provable primes
    BN_CTX *gen_keys_ctx = BN_CTX_secure_new();
    BN_CTX_start(gen_keys_ctx);

    // the prime seed
    BIGNUM *seed = BN_CTX_get(gen_keys_ctx);
    // n = p * q
    BIGNUM *n = BN_CTX_get(gen_keys_ctx);
    // the private exponent
    BIGNUM *d = BN_CTX_get(gen_keys_ctx);
    // the first large prime
    BIGNUM *p = BN_CTX_get(gen_keys_ctx);
    // the second large prime
    BIGNUM *q = BN_CTX_get(gen_keys_ctx);
    // the public exponent
    BIGNUM *e =  BN_CTX_get(gen_keys_ctx);

    // select a random value between 2 ** 16 and 2 ** 256 for use as e
    generateRandomE(e);

    int d_is_0 = 1;
    ConstructPandQResult result_primes;
    while(d_is_0){

        // generate a random seed
        generateRandomSeed(seed);

        // generate the primes p and q
        result_primes =  constructTheProvablePrimesWithAuxillary(seed, bitlen1, bitlen2, bitlen3, bitlen4, e);
        if(result_primes.success_){

            BN_copy(p, result_primes.p_);
            BN_copy(q, result_primes.q_);
            result_primes.freeResult();
            
            // calculate the private exponent, d based on the generated value for e, p and q
            generatePrivateExponent(d, e, p, q);
            
            // if there in an issue finding e due to the inverse, attempt to use a couple different value for e before regenerating both primes
            d_is_0 = BN_is_zero(d);
            int e_retry = 0;
            while( d_is_0 and e_retry < 10){
                generateRandomE(e);
                // calculate the private exponent, d based on the generated value for e, p and q
                generatePrivateExponent(d, e, p, q);
                d_is_0 = BN_is_zero(d);
                e_retry++;
            }
        }
    }
    // calculate n based on the generated prime p and q
    BN_mul(n, p, q, context_);

    // construct the private key using n, d and keylength.
    // also use p and q if the private key is in quintuple form.
    RSAPrivateKey private_key;
    if (use_key_quintuple_form){
        private_key = RSAPrivateKey(n, d, p, q, keylength_);
    } else {
        private_key = RSAPrivateKey(n, d, keylength_);
    }
    // construct the public key based on n, e and key length
    RSAPublicKey public_key = RSAPublicKey(n, e, keylength_);
    RSAKeyGenerationResult key_generation_result = RSAKeyGenerationResult(true, private_key, public_key,keylength_);
    
    // clean up the context used and its data
    if (gen_keys_ctx){
        BN_CTX_end(gen_keys_ctx);
        BN_CTX_free(gen_keys_ctx);
    }
    return key_generation_result;
}

RSAKeyGenerationResult RSAKeyGeneration::generateRSAKeysUsingProvablePrimes(bool use_key_quintuple_form){
    // The context for this function generating RSA Keys using provable primes
    BN_CTX *gen_keys_ctx = BN_CTX_secure_new();
    BN_CTX_start(gen_keys_ctx);

    // the prime seed
    BIGNUM *seed = BN_CTX_get(gen_keys_ctx);
    // n = p * q
    BIGNUM *n = BN_CTX_get(gen_keys_ctx);
    // the private exponent
    BIGNUM *d = BN_CTX_get(gen_keys_ctx);
    // the first large prime
    BIGNUM *p = BN_CTX_get(gen_keys_ctx);
    // the second large prime
    BIGNUM *q = BN_CTX_get(gen_keys_ctx);
    // the public exponent
    BIGNUM *e =  BN_CTX_get(gen_keys_ctx);

    // select a random value between 2 ** 16 and 2 ** 256 for use as e
    generateRandomE(e);

    int d_is_0 = 1;
    ConstructPandQResult result_primes;
    while(d_is_0){

        // generate a random seed
        generateRandomSeed(seed);

        // generate the primes p and q
        result_primes = constructTheProvablePrimes(seed, e);
        if(result_primes.success_){

            BN_copy(p, result_primes.p_);
            BN_copy(q, result_primes.q_);
            result_primes.freeResult();
            
            // calculate the private exponent, d based on the generated value for e, p and q
            generatePrivateExponent(d, e, p, q);
            
            // if there in an issue finding e due to the inverse, attempt to use a couple different value for e before regenerating both primes
            d_is_0 = BN_is_zero(d);
            int e_retry = 0;
            while( d_is_0 and e_retry < 10){
                generateRandomE(e);
                // calculate the private exponent, d based on the generated value for e, p and q
                generatePrivateExponent(d, e, p, q);
                d_is_0 = BN_is_zero(d);
                e_retry++;
            }
        }
    }
    // calculate n based on the generated prime p and q
    BN_mul(n, p, q, context_);

    // construct the private key using n, d and keylength.
    // also use p and q if the private key is in quintuple form.
    RSAPrivateKey private_key;
    if (use_key_quintuple_form){
        private_key = RSAPrivateKey(n, d, p, q, keylength_);
    } else {
        private_key = RSAPrivateKey(n, d, keylength_);
    }
    // construct the public key based on n, e and key length
    RSAPublicKey public_key = RSAPublicKey(n, e, keylength_);
    RSAKeyGenerationResult key_generation_result = RSAKeyGenerationResult(true, private_key, public_key, keylength_);
    
    // clean up the context used and its data
    if (gen_keys_ctx){
        BN_CTX_end(gen_keys_ctx);
        BN_CTX_free(gen_keys_ctx);
    }
    return key_generation_result;
}

ConstructPandQResult RSAKeyGeneration::constructTheProvablePrimesWithAuxillary(BIGNUM *seed, int bitlen1, int bitlen2, int bitlen3, int bitlen4, BIGNUM *e){
    
    // The context for this function generating the provable primes 'p' and 'q'
    BN_CTX *construct_ctx = BN_CTX_new();
    BN_CTX_start(construct_ctx);

    // A temporary variable for the first costructed provable prime, 'p'
    BIGNUM *p = BN_CTX_get(construct_ctx);
    // A temporary variable for the second constructed provable prime, 'q'
    BIGNUM *q = BN_CTX_get(construct_ctx);
    // A temporary variable for the difference between 'p' and 'q'
    BIGNUM *diff_p_q = BN_CTX_get(construct_ctx);

    ProvablePrimeGenerationResult prime_generation_result = constructAProvablePrimePotentiallyWithConditions(getPrimeLength(), bitlen1, bitlen2, seed, e);

    // Whether the primes with successfully constructed thus far
    bool prime_generation_success = prime_generation_result.success_;

    if (prime_generation_success){
        BN_copy(p, prime_generation_result.prime_);
        BN_copy(seed, prime_generation_result.prime_seed_);

        bool p_q_min_diff_success = false;
        int retry_counter = 0;
        while (prime_generation_success & !p_q_min_diff_success){
            prime_generation_result.freeResult();

            prime_generation_result = constructAProvablePrimePotentiallyWithConditions(getPrimeLength(), bitlen3, bitlen4, seed, e);
            
            if(prime_generation_success){
                BN_copy(q, prime_generation_result.prime_);
                BN_copy(seed, prime_generation_result.prime_seed_);

                BN_sub(diff_p_q, p, q);
                int comp_result = BN_ucmp(diff_p_q,min_pq_diff_);
                if (comp_result == 1){
                    p_q_min_diff_success = true;
                } else {
                    printf("p and q are too close together, regenerating q\n");
                }
                if (retry_counter > 5){
                    prime_generation_success = false;
                }
                retry_counter ++;
            }
        }
    }
    prime_generation_result.freeResult();

    // The result of attempting constuction of both 'p' and 'q'
    ConstructPandQResult p_and_q_result;
    if (prime_generation_success) {
        p_and_q_result = ConstructPandQResult(true, p, q);
    } else {
        p_and_q_result = ConstructPandQResult();
    }

    BN_CTX_end(construct_ctx);
    BN_CTX_free(construct_ctx);
    return p_and_q_result;
};


ConstructPandQResult RSAKeyGeneration::constructTheProvablePrimes(BIGNUM *seed, BIGNUM *e){

    BN_CTX *construct_ctx = BN_CTX_new();
    BN_CTX_start(construct_ctx);
    // The first costructed provable prime, 'p'
    BIGNUM *p = BN_CTX_get(construct_ctx);
    // The second constructed provable prime, 'q'
    BIGNUM *q = BN_CTX_get(construct_ctx);

    BIGNUM *diff_p_q = BN_CTX_get(construct_ctx);
    // The result of attempting constuction of both 'p' and 'q'
    ConstructPandQResult p_and_q_result;

    ProvablePrimeGenerationResult prime_generation_result = constructAProvablePrimePotentiallyWithConditions(getPrimeLength(), 1, 1, seed, e);

    // Whether the primes with successfully constructed thus far
    bool prime_generation_success = prime_generation_result.success_;

    if (prime_generation_success){
        BN_copy(p, prime_generation_result.prime_);
        BN_copy(seed, prime_generation_result.prime_seed_);

        bool p_q_min_diff_success = false;
        int retry_counter = 0;
        while (prime_generation_success & !p_q_min_diff_success){
            prime_generation_result.freeResult();

            prime_generation_result = constructAProvablePrimePotentiallyWithConditions(getPrimeLength(), 1, 1, seed, e);
            if(prime_generation_success){
                BN_copy(q, prime_generation_result.prime_);
                BN_copy(seed, prime_generation_result.prime_seed_);

                BN_sub(diff_p_q, p, q);
                int comp_result = BN_ucmp(diff_p_q,min_pq_diff_);
                if (comp_result == 1){
                    p_q_min_diff_success = true;
                } else {
                    printf("p and q are too close together, regenerating q\n");
                }
                if (retry_counter > 5){
                    prime_generation_success = false;
                }
                retry_counter ++;
            }
        }
    }
    prime_generation_result.freeResult();

    if (prime_generation_success) {
        p_and_q_result = ConstructPandQResult(true, p, q);
    } else {
        p_and_q_result = ConstructPandQResult();
    }

    BN_CTX_end(construct_ctx);
    BN_CTX_free(construct_ctx);
    return p_and_q_result;
};

ProvablePrimeGenerationResult RSAKeyGeneration::constructAProvablePrimePotentiallyWithConditions(int L, int N1, int N2, BIGNUM *first_seed, BIGNUM *e){

    BN_CTX *prime_gen_ctx = BN_CTX_secure_new();
    BN_CTX_start(prime_gen_ctx);

    BIGNUM *first_seed_copied = BN_CTX_get(prime_gen_ctx);
    BN_copy(first_seed_copied, first_seed);
    
    // A temporary variable for 1 as a BIGNUM
    BIGNUM *number_one = BN_CTX_get(prime_gen_ctx);
    BN_set_word(number_one, 1);
    // A temporary variable for 2 as a BIGNUM
    BIGNUM *number_two = BN_CTX_get(prime_gen_ctx);
    BN_set_word(number_two, 2);

    // A temporary variable for p =  (2(t p2 − y) p0 p1 + 1)
    BIGNUM *p = BN_CTX_get(prime_gen_ctx);
    // A temporary variable for an auxillary prime of length N1
    BIGNUM *p1 = BN_CTX_get(prime_gen_ctx);
    // A temporary variable for the prime seed to be used when generating p2
    BIGNUM *p2_seed = BN_CTX_get(prime_gen_ctx);
    // A temporary variable for an auxillary prime of length N2
    BIGNUM *p2 = BN_CTX_get(prime_gen_ctx);
    // A temporary variable for the prime seed to be used when generating p0
    BIGNUM *p0_seed = BN_CTX_get(prime_gen_ctx);
    // A temporary variable for the generated value for p0 from the shawe taylor result in step 6
    BIGNUM *p0 =  BN_CTX_get(prime_gen_ctx);
    // A temporary variable for the generated value for pseed from the shawe taylor result in step 6
    BIGNUM *pseed =  BN_CTX_get(prime_gen_ctx);
    // A temporary variable for the result of the greatest common denominator of p0p1 and p2
    BIGNUM *gcd_result = BN_CTX_get(prime_gen_ctx);
    // A temporary variable for p0 * p1
    BIGNUM *p0p1 = BN_CTX_get(prime_gen_ctx);
    // A temporary variable for x
    BIGNUM *x = BN_CTX_get(prime_gen_ctx);
    // A temporary variable for the modulus for x (2**L - sq2 * 2**(L-1))
    BIGNUM *x_modulus = BN_CTX_get(prime_gen_ctx);
    // A temporary variable for the value of L as a BIGNUM
    BIGNUM *L_bn = BN_CTX_get(prime_gen_ctx);
    // A temporary variable for the inverse of p0p1 in the modulus p2
    BIGNUM *y = BN_CTX_get(prime_gen_ctx);
    // A temporary variable for the value of t as a BIGNUM
    BIGNUM *t = BN_CTX_get(prime_gen_ctx);
    // A temporary variable for the remainder when calculating t
    BIGNUM *t_r = BN_CTX_get(prime_gen_ctx);
    // A temporary variable for the numerator for calculating t (2yp0p1 + x)
    BIGNUM *t_num = BN_CTX_get(prime_gen_ctx);
    // A temporary variable for 2 * y * p0 * p1
    BIGNUM *two_y_p0p1 = BN_CTX_get(prime_gen_ctx);
    // A temporary variable for the denominator for calculating t (2p0p1p2)
    BIGNUM *t_den = BN_CTX_get(prime_gen_ctx);
    // A temporary variable for 2 ** L
    BIGNUM *two_to_L = BN_CTX_get(prime_gen_ctx);
    // A temporary variable for a
    BIGNUM *a = BN_CTX_get(prime_gen_ctx);
    // A temporary variable for p - 3
    BIGNUM *p_min_3 = BN_CTX_get(prime_gen_ctx);
    // temporary variable for z (z = a ** (2(t p2 − y) p1) mod p)
    BIGNUM *z = BN_CTX_get(prime_gen_ctx);
    // A temporary variable for z ** p0 % p
    BIGNUM *z_p0_modp = BN_CTX_get(prime_gen_ctx);
    
    bool success_generating_primes = true;

    // step 2 and 3
    if (N1 == 1){
        BN_set_word(p1, 1);
        BN_copy(p2_seed, first_seed_copied);
        success_generating_primes = true;
    } else {
        // A random prime with bit length N1
        PassBigNum passing_seed = PassBigNum(first_seed_copied);
        ShaweTaylorRandomPrimeResult random_prime = generateRandomPrimeWithShaweTaylor(N1, passing_seed);
        BN_copy(p1, random_prime.prime_);
        BN_copy(p2_seed, random_prime.prime_seed_);
        success_generating_primes = random_prime.success_;
        random_prime.freeResult();
    }

    // Step 4 and 5
    if (success_generating_primes && N2 == 1){
        BN_set_word(p2, 1);
        BN_copy(p0_seed, p2_seed);
    } else if (success_generating_primes) {
        // A random prime with bit length N2
        PassBigNum passing_seed = PassBigNum(p2_seed);
        ShaweTaylorRandomPrimeResult random_prime = generateRandomPrimeWithShaweTaylor(N2, passing_seed);
        BN_copy(p2, random_prime.prime_);
        BN_copy(p0_seed, random_prime.prime_seed_);
        success_generating_primes = random_prime.success_;
        random_prime.freeResult();
    }

    if (success_generating_primes) {
        // ceil(L / 2) + 1
        int length = L/2;
        if (L % 2 != 0) {
            length += 1;
        }

        // Step 6
        // the result of the prime generation using shawe taylor to find p0
        PassBigNum passing_seed = PassBigNum(p0_seed);
        ShaweTaylorRandomPrimeResult shawe_taylor_result = generateRandomPrimeWithShaweTaylor(length, passing_seed);
        success_generating_primes = shawe_taylor_result.success_;

        // copy the results into this context
        BN_copy(p0, shawe_taylor_result.prime_);
        BN_copy(pseed, shawe_taylor_result.prime_seed_);

        // Step 7
        BN_mul(p0p1, p0, p1, context_);
        BN_gcd(gcd_result, p0p1, p2, context_);
        shawe_taylor_result.freeResult();

        success_generating_primes = ( BN_is_one(gcd_result) == 1 );
    }

    if (success_generating_primes){

        // Step 8
        int iteration = L / hash_length_;
        if (L % hash_length_ == 0 and iteration != 0){
            iteration -= 1;
        }

        // Step 9
        // A counter to track how many iterations have been ran while attempting to generate the prime
        int pgen_counter = 0;

        generatePseudoRandomNumber(x, iteration, pseed);

        // step 13
        BN_set_word(L_bn, L);
        BN_exp(x_modulus, number_two, L_bn, context_);
        BN_sub(x_modulus, x_modulus, min_prime_value_);
        BN_mod(x, x, x_modulus, context_);
        BN_add(x, x, min_prime_value_);

        // Step 14
        BN_mod_inverse(y, p0p1, p2, context_);

        // Step 15
        BN_mul(two_y_p0p1, p0p1,number_two, context_);
        BN_mul(two_y_p0p1, two_y_p0p1, y, context_);
        BN_add(t_num, two_y_p0p1, x);
        BN_mul(t_den, p0p1, number_two, context_);
        BN_mul(t_den, t_den, p2, context_);
        BN_div(t, t_r, t_num, t_den, context_);
        if (BN_is_zero(t_r) != 1){
            BN_add_word(t, 1);
        }

        int max_counter = 10*L;
        while(pgen_counter <= max_counter){
            // Step 16 
            // p =  (2(t p2 − y) p0 p1 + 1)
            BN_mul(p, t, p2, context_);
            BN_sub(p, p, y);
            BN_mul_word(p, 2);
            BN_mul(p, p, p0p1, context_);
            BN_add_word(p, 1);
            BN_exp(two_to_L, number_two, L_bn, context_);
            if(BN_cmp(p, two_to_L) == 1){
                BN_add(t_num, two_y_p0p1, min_prime_value_);
                BN_div(t,t_r,t_num,t_den,context_);
                if (BN_is_zero(t_r) != 1){
                    BN_add_word(t, 1);
                }
            }

            // Step 18
            pgen_counter += 1;

            BigNumHelpers::gcdValueMinusOneSecondValue(gcd_result, p, e);
            //step 19
            if (BN_is_odd(gcd_result) == 1){

                // step 19.1 - 19.3
                generatePseudoRandomNumber(a, iteration, pseed);
                
                // step 19.4 : a = 2 + a mod (p - 3)
                BN_copy(p_min_3, p);
                BN_sub_word(p_min_3, 3);
                BN_mod(a, a, p_min_3, context_);
                BN_add_word(a, 2);

                // step 19.5 z = a ** 2 * (t * p2 − y) * p1 mod p. 
                BN_mul(z, t, p2, context_);
                BN_sub(z, z, y);
                BN_mul_word(z, 2);
                BN_mul(z, z, p1, context_);
                BN_mod_exp(z, a, z, p, context_);

                BigNumHelpers::gcdValueMinusOneSecondValue(gcd_result, z, p);
    
                if(BN_is_one(gcd_result) == 1){
                    BN_mod_exp(z_p0_modp, z, p0, p, context_);
                    
                    if(BN_is_one(z_p0_modp) == 1){
                        break;
                    }
                }

                // // step 32
                if (pgen_counter >= max_counter){
                    success_generating_primes = false;
                    break;
                }
                BN_add_word(t, 1);
            }
        }
    }

    // construct the result of the provable prime generation
    ProvablePrimeGenerationResult result;
    if (success_generating_primes){
        result =ProvablePrimeGenerationResult(true, p, p1, p2, pseed);
    } else {
        result = ProvablePrimeGenerationResult();
    }

    // clear the context and free it's memory
    if(prime_gen_ctx){
        BN_CTX_end(prime_gen_ctx);
        BN_CTX_free(prime_gen_ctx);
    }
    return result;
};