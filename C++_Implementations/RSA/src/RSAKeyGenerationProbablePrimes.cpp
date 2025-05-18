#include "RSAKeyGeneration.hpp"

RSAKeyGenerationResult RSAKeyGeneration::generateRSAKeysUsingProbablePrimes(int a, int b, bool use_key_quintuple_form){

    // The context for this function generating RSA Keys using probable primes
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

    // select a random value between 2 ** 16 and 2 ** 256 for use as 2
    e = generateRandomE();

    int d_is_0 = 1;
    ConstructPandQResult result_primes;
    while(d_is_0 == 1){
        // generate the primes p and q
        result_primes = constructTheProbablePrimes(a, b, e);
        if(result_primes.success_){
            BN_copy(p, result_primes.p_);
            BN_copy(q, result_primes.q_);
            result_primes.freeResult();

            // calculate the private exponent, d based on the generated value for e, p and q
            d = generatePrivateExponent(e, p, q);

            // if there in an issue finding e due to the inverse, attempt to use a couple different value for e before regenerating both primes
            d_is_0 = BN_is_zero(d);
            int e_retry = 0;
            while( d_is_0 and e_retry < 10){
                e = generateRandomE();
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
    RSAKeyGenerationResult key_generation_result = RSAKeyGenerationResult(true,private_key,public_key,keylength_);
    
    // clean up the context used and its data
    if (gen_keys_ctx){
        BN_CTX_end(gen_keys_ctx);
        BN_CTX_free(gen_keys_ctx);
    }
    return key_generation_result;
}

RSAKeyGenerationResult RSAKeyGeneration::generateRSAKeysUsingProbablePrimesWithProvableAux(int a, int b, int bitlen1, int bitlen2, int bitlen3, int bitlen4, bool use_key_quintuple_form){

    // The context for this function generating RSA Keys using probable primes
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

    // select a random value between 2 ** 16 and 2 ** 256 for use as 2
    e = generateRandomE();

    int d_is_0 = 1;
    ConstructPandQResult result_primes;
    while(d_is_0 == 1){

        // generate a random seed
        seed = generateRandomSeed();
    
        // generate the primes p and q
        result_primes = constructTheProbablePrimesWithProvableAux(a, b, bitlen1, bitlen2, bitlen3, bitlen4, seed, e);

        if(result_primes.success_){

            BN_copy(p, result_primes.p_);
            BN_copy(q, result_primes.q_);
            result_primes.freeResult();

            // calculate the private exponent, d based on the generated value for e, p and q
            d = generatePrivateExponent(e, p, q);
            
            // if there in an issue finding e due to the inverse, attempt to use a couple different value for e before regenerating both primes
            d_is_0 = BN_is_zero(d);
            int e_retry = 0;
            while( d_is_0 and e_retry < 10){
                e = generateRandomE();
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
    RSAKeyGenerationResult key_generation_result = RSAKeyGenerationResult(true,private_key,public_key,keylength_);
    
    // clean up the context used and its data
    if (gen_keys_ctx){
        BN_CTX_end(gen_keys_ctx);
        BN_CTX_free(gen_keys_ctx);
    }
    return key_generation_result;
}

RSAKeyGenerationResult RSAKeyGeneration::generateRSAKeysUsingProbablePrimesWithProbableAux(int a, int b, int bitlen1, int bitlen2, int bitlen3, int bitlen4, bool use_key_quintuple_form){
    // The context for this function generating RSA Keys using probable primes
    BN_CTX *gen_primes_ctx = BN_CTX_secure_new();
    BN_CTX_start(gen_primes_ctx);

    // the prime seed
    BIGNUM *seed = BN_CTX_get(gen_primes_ctx);
    // n = p * q
    BIGNUM *n = BN_CTX_get(gen_primes_ctx);
    // the private exponent
    BIGNUM *d = BN_CTX_get(gen_primes_ctx);
    // the first large prime
    BIGNUM *p = BN_CTX_get(gen_primes_ctx);
    // the second large prime
    BIGNUM *q = BN_CTX_get(gen_primes_ctx);
    // the public exponent
    BIGNUM *e =  BN_CTX_get(gen_primes_ctx);

    // select a random value between 2 ** 16 and 2 ** 256 for use as 2
    e = generateRandomE();

    int d_is_0 = 1;
    ConstructPandQResult result_primes;
    while(d_is_0 == 1){
        // generate the primes p and q
        result_primes = constructTheProbablePrimesWithProbableAux(a, b, bitlen1, bitlen2, bitlen3, bitlen4, e);
        if(result_primes.success_){

            BN_copy(p, result_primes.p_);
            BN_copy(q, result_primes.q_);
            result_primes.freeResult();

            // calculate the private exponent, d based on the generated value for e, p and q
            d = generatePrivateExponent(e, p, q);
            
            // if there in an issue finding e due to the inverse, attempt to use a couple different value for e before regenerating both primes
            d_is_0 = BN_is_zero(d);
            int e_retry = 0;
            while( d_is_0 and e_retry < 10){
                e = generateRandomE();
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
    if (gen_primes_ctx){
        BN_CTX_end(gen_primes_ctx);
        BN_CTX_free(gen_primes_ctx);
    }
    return key_generation_result;
}


ConstructPandQResult RSAKeyGeneration::constructTheProbablePrimes(int a, int b, BIGNUM *e){

    BN_CTX *construct_ctx = BN_CTX_secure_new();
    BN_CTX_start(construct_ctx);

    int security_strength = getSecurityStrength();
    int max_iterations = 5 * keylength_;

    // a temporary value for 8 as a BIGNUM
    BIGNUM *number_eight = BN_CTX_get(construct_ctx);
    BN_set_word(number_eight,8);
    // the first prime being generated with optional restriction a
    BIGNUM *p = BN_CTX_get(construct_ctx);
    // the second prime being generated with optional restriction b
    BIGNUM *q = BN_CTX_get(construct_ctx);
    // a temporary variable for use with calculations
    BIGNUM* temp_value = BN_CTX_get(construct_ctx);
    // a temporary variable for a as a BIGNUM
    BIGNUM *a_bn = BN_CTX_get(construct_ctx);
    // a temporary variable for b as a BIGNUM
    BIGNUM *b_bn = BN_CTX_get(construct_ctx);

    bool success_generating_p = false;
    bool success_generating_q = false;

    for(int i = 0; i <= max_iterations; i ++){
        // a value which will be 1 or 0 if the random value is greater than or equal to the minimum acceptable prime value
        int p_cmp_minprime = -1;
        while (p_cmp_minprime == -1){
            // step 4.2 : generate random odd value for p
            BN_rand(p, getPrimeLength(), BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ODD);

            // step 4.3 : handle the optional restriction, p % 8 = a
            if (a != -1){
                BN_set_word(a_bn, a);
                BN_mod_sub(temp_value, a_bn, p, number_eight, context_);
                BN_add(p, p, temp_value);
            }
            // step 4.4 : ensure p is larger than the minimum prime allow for the key length
            p_cmp_minprime = BN_cmp(p, min_prime_value_);
        }

        // step 4.5 : ensure the gcd of p-1 and e is one and then test for primality
        temp_value = BigNumHelpers::gcdValueMinusOneSecondValue(p, e);
        if (BN_is_one(temp_value) == 1){
            int is_prime = BN_check_prime(p, context_, nullptr);
            if (is_prime == 1){
                success_generating_p = true;
                break;
            }
        }
    }

    if (success_generating_p ){
        for(int i = 0; i <= max_iterations; i ++){
            int q_cmp_minprime = -1;
            int qminp_cmp_mindiff = -1;
            while (q_cmp_minprime == -1 || qminp_cmp_mindiff == -1){
                // step 5.2 : generate random odd value for q
                BN_rand(q, getPrimeLength(), BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ODD);
                // step 5.3 : handle the optional restriction, q % 8 = b
                if (b != -1){
                    BN_set_word(b_bn, b);
                    BN_mod_sub(temp_value, b_bn, q, number_eight, context_);
                    BN_add(q, q, temp_value);
                }
                // step 5.4 : ensure q is larger than the minimum prime allow for the key length
                q_cmp_minprime = BN_cmp(q, min_prime_value_);
                BN_usub(temp_value, p, q);
                // step 5.5 : ensure the gap between p and q is larger than the minimum for the key length
                qminp_cmp_mindiff = BN_cmp(temp_value, min_pq_diff_);
            }
            
            // step 5.6 : ensure the gcd of q - 1 and e is one and then test for primality
            temp_value = BigNumHelpers::gcdValueMinusOneSecondValue(q, e);
            if (BN_is_one(temp_value) == 1){
                int is_prime = BN_check_prime(q, context_, nullptr);
                if (is_prime == 1){
                    success_generating_q = true;
                    break;
                }
            }
        }
    }

    // construct the instance of the result structure for the return
    ConstructPandQResult result;
    if (success_generating_p && success_generating_q) {
        result = ConstructPandQResult(true, p, q);
    } else {
        result = ConstructPandQResult();
    }

    // clean up the context used and its data
    if (construct_ctx){
        BN_CTX_end(construct_ctx);
        BN_CTX_free(construct_ctx);
    }

    return result;

}

ConstructPandQResult RSAKeyGeneration::constructTheProbablePrimesWithProvableAux(int a, int b, int bitlen1, int bitlen2, int bitlen3, int bitlen4, BIGNUM *seed, BIGNUM *e){
    // the context to be used for the mathematical operations to allow memory cleanup
    BN_CTX *construct_ctx = BN_CTX_secure_new();
    BN_CTX_start(construct_ctx);

    // a temporary value for 8 as a BIGNUM
    BIGNUM *number_eight = BN_CTX_get(construct_ctx);
    BN_set_word(number_eight,8);
    // the first prime being generated with optional restriction a
    BIGNUM *p = BN_CTX_get(construct_ctx);
    // the second prime being generated with optional restriction b
    BIGNUM *q = BN_CTX_get(construct_ctx);
    // a temporary variable for use with calculations
    BIGNUM* temp_value = BN_CTX_get(construct_ctx);
    // a temporary variable for a as a BIGNUM
    BIGNUM *a_bn = BN_CTX_get(construct_ctx);
    // a temporary variable for b as a BIGNUM
    BIGNUM *b_bn = BN_CTX_get(construct_ctx);
    // a temporary variable for the auxillary prime p1
    BIGNUM *p1 = BN_CTX_get(construct_ctx);
    // a temporary variable for the seed for p2
    BIGNUM *p2_seed = BN_CTX_get(construct_ctx);
    // a temporary variable for the auxillary prime p2
    BIGNUM *p2 = BN_CTX_get(construct_ctx);
    // a temporary variable for the auxillary prime q1
    BIGNUM *q1 = BN_CTX_get(construct_ctx);
    // a temporary variable for the seed for q2
    BIGNUM *q2_seed = BN_CTX_get(construct_ctx);
    // a temporary variable for the auxillary prime q2
    BIGNUM *q2 = BN_CTX_get(construct_ctx);
    // a temporary variable for the seed for q1
    BIGNUM *q1_seed = BN_CTX_get(construct_ctx);
    // a temporary variable for the value of X when generating p
    BIGNUM *Xp = BN_CTX_get(construct_ctx);
    // a temporary variable for the value of X when generating q
    BIGNUM *Xq = BN_CTX_get(construct_ctx);
    // a temporary variable for the unsigned difference between p and q
    BIGNUM *diff_p_q = BN_CTX_get(construct_ctx);
    // a temporary variable for the unsigned difference between Xp and Xq
    BIGNUM *diff_Xp_Xq = BN_CTX_get(construct_ctx);

    bool success_generating_p = false;
    bool success_generating_q = false;

    // step 5.1 : obtain p1
    PassBigNum passing_seed = PassBigNum(seed);
    ShaweTaylorRandomPrimeResult random_prime = generateRandomPrimeWithShaweTaylor(bitlen1, passing_seed);
    BN_copy(p1, random_prime.prime_);
    BN_copy(p2_seed, random_prime.prime_seed_);
    success_generating_p = random_prime.success_;
    random_prime.freeResult();

    if (success_generating_p) {
        // step 5.2 : obtain p2
        PassBigNum passing_seed = PassBigNum(p2_seed);
        ShaweTaylorRandomPrimeResult random_prime = generateRandomPrimeWithShaweTaylor(bitlen2, passing_seed);
        BN_copy(p2, random_prime.prime_);
        BN_copy(q1_seed, random_prime.prime_seed_);
        success_generating_p = random_prime.success_;
        random_prime.freeResult();
    }

    if (success_generating_p ){
        // step 5.3 : obtain p
        ProbablePrimeGenerationWithAuxResult p_result = constructAProbablePrimeWithAux(p1, p2, e, a);
        success_generating_p = p_result.success_;
        if (success_generating_p){
            BN_copy(p, p_result.prime_);
            BN_copy(Xp, p_result.X_);
        }
        p_result.freeResult();
    }

    bool p_q_min_diff_success = false;
    bool Xp_Xq_min_diff_success = false;

    if (success_generating_p ){
        int retry_counter = 0;
        while(!p_q_min_diff_success || !Xp_Xq_min_diff_success && retry_counter < 5){
            // step 6.1 : obtain q1
            PassBigNum passing_seed = PassBigNum(q1_seed);
            ShaweTaylorRandomPrimeResult random_prime = generateRandomPrimeWithShaweTaylor(bitlen3, passing_seed);
            BN_copy(q1, random_prime.prime_);
            BN_copy(q2_seed, random_prime.prime_seed_);
            success_generating_q = random_prime.success_;
            random_prime.freeResult();

            if (success_generating_q) {
                // step 6.2 : obtain q2
                PassBigNum passing_seed = PassBigNum(q2_seed);
                ShaweTaylorRandomPrimeResult random_prime = generateRandomPrimeWithShaweTaylor(bitlen4, passing_seed);
                BN_copy(q2, random_prime.prime_);
                BN_copy(q1_seed, random_prime.prime_seed_);
                success_generating_q = random_prime.success_;
                random_prime.freeResult();
            }

            if (success_generating_q ){
                // step 6.3 : obtain q
                ProbablePrimeGenerationWithAuxResult q_result = constructAProbablePrimeWithAux(q1, q2, e, b);
                success_generating_q = q_result.success_;
                if (success_generating_q){
                    BN_copy(q, q_result.prime_);
                    BN_copy(Xq, q_result.X_);
                }
                q_result.freeResult();
            }
            if (success_generating_p && success_generating_q) {
                // step 7 : (a) ensure p and q are far enough apart
                BN_sub(diff_p_q, p, q);
                int comp_result = BN_ucmp(diff_p_q, min_pq_diff_);
                if (comp_result == 1){
                    p_q_min_diff_success = true;
                } else {
                    printf("p and q are too close together, regenerating q\n");
                }

                // step 7 : (b) ensure Xp and Xq are far enough apart
                BN_sub(diff_Xp_Xq, Xp, Xq);
                comp_result = BN_ucmp(diff_Xp_Xq, min_pq_diff_);
                if (comp_result == 1){
                    Xp_Xq_min_diff_success = true;
                } else {
                    printf("Xp and Xq are too close together, regenerating q\n");
                }
            }
        }
    }

    // construct the instance of the result structure for the return
    ConstructPandQResult result;
    if (success_generating_p && success_generating_q) {
        result = ConstructPandQResult(true, p, q);
    } else {
        result = ConstructPandQResult();
    }

    // clean up the context used and its data
    if (construct_ctx){
        BN_CTX_end(construct_ctx);
        BN_CTX_free(construct_ctx);
    }

    return result;
}

ConstructPandQResult RSAKeyGeneration::constructTheProbablePrimesWithProbableAux(int a, int b, int bitlen1, int bitlen2, int bitlen3, int bitlen4, BIGNUM *e){

    // the context to be used for the mathematical operations to allow memory cleanup
    BN_CTX *construct_ctx = BN_CTX_secure_new();
    BN_CTX_start(construct_ctx);

    // a temporary value for 8 as a BIGNUM
    BIGNUM *number_eight = BN_CTX_get(construct_ctx);
    BN_set_word(number_eight,8);
    // the first prime being generated with optional restriction a
    BIGNUM *p = BN_CTX_get(construct_ctx);
    // the second prime being generated with optional restriction b
    BIGNUM *q = BN_CTX_get(construct_ctx);
    // a temporary variable for use with calculations
    BIGNUM* temp_value = BN_CTX_get(construct_ctx);
    // a temporary variable for a as a BIGNUM
    BIGNUM *a_bn = BN_CTX_get(construct_ctx);
    // a temporary variable for b as a BIGNUM
    BIGNUM *b_bn = BN_CTX_get(construct_ctx);
    // a temporary variable for the auxillary prime p1
    BIGNUM *p1 = BN_CTX_get(construct_ctx);
    // a temporary variable for the seed for p2
    BIGNUM *p2_seed = BN_CTX_get(construct_ctx);
    // a temporary variable for the auxillary prime p2
    BIGNUM *p2 = BN_CTX_get(construct_ctx);
    // a temporary variable for the auxillary prime q1
    BIGNUM *q1 = BN_CTX_get(construct_ctx);
    // a temporary variable for the seed for q2
    BIGNUM *q2_seed = BN_CTX_get(construct_ctx);
    // a temporary variable for the auxillary prime q2
    BIGNUM *q2 = BN_CTX_get(construct_ctx);
    // a temporary variable for the seed for q1
    BIGNUM *q1_seed = BN_CTX_get(construct_ctx);
    // a temporary variable for the value of X when generating p
    BIGNUM *Xp = BN_CTX_get(construct_ctx);
    // a temporary variable for the value of X when generating q
    BIGNUM *Xq = BN_CTX_get(construct_ctx);
    // a temporary variable for the unsigned difference between p and q
    BIGNUM *diff_p_q = BN_CTX_get(construct_ctx);
    // a temporary variable for the unsigned difference between Xp and Xq
    BIGNUM *diff_Xp_Xq = BN_CTX_get(construct_ctx);
    // a temporary variable for the X value used when finding p1
    BIGNUM *Xp1 = BN_CTX_get(construct_ctx);
    // a temporary variable for the X value used when finding p2
    BIGNUM *Xq1 = BN_CTX_get(construct_ctx);
    // a temporary variable for the X value used when finding q1
    BIGNUM *Xp2 = BN_CTX_get(construct_ctx);
    // a temporary variable for the X value used when finding q2
    BIGNUM *Xq2 = BN_CTX_get(construct_ctx);

    bool success_generating_p = false;
    bool success_generating_q = false;

    // step 4.1 : find p1
    BN_rand(Xp1, bitlen1, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ODD);
    BN_copy(p1, Xp1);
    while (BN_check_prime(p1, context_, nullptr) != 1){
        BN_add_word(p1, 2);
    }
    // step 4.2 : find p2
    BN_rand(Xp2, bitlen2, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ODD);
    BN_copy(p2, Xp2);
    while (BN_check_prime(p2, context_, nullptr) != 1){
        BN_add_word(p2, 2);
    }
    //step 4.3 : find p
    ProbablePrimeGenerationWithAuxResult p_result = constructAProbablePrimeWithAux(p1, p2, e, a);
    success_generating_p = p_result.success_;
    if (success_generating_p){
        BN_copy(p, p_result.prime_);
        BN_copy(Xp, p_result.X_);
    }
    p_result.freeResult();

    bool p_q_min_diff_success = false;
    bool Xp_Xq_min_diff_success = false;

    if (success_generating_p ){
        int retry_counter = 0;
        while(!p_q_min_diff_success || !Xp_Xq_min_diff_success && retry_counter < 5){
            // step 5.1 : find q1
            BN_rand(Xq1, bitlen3, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ODD);
            BN_copy(q1, Xq1);
            while (BN_check_prime(q1, context_, nullptr) != 1){
                BN_add_word(q1, 2);
            }
            // step 5.2 : find q2
            BN_rand(Xq2, bitlen4, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ODD);
            BN_copy(q2, Xq2);
            while (BN_check_prime(q2, context_, nullptr) != 1){
                BN_add_word(q2, 2);
            }
            // step 5.3 : find q
            ProbablePrimeGenerationWithAuxResult q_result = constructAProbablePrimeWithAux(q1, q2, e, b);
            success_generating_q = p_result.success_;
            if (success_generating_q){
                BN_copy(q, q_result.prime_);
                BN_copy(Xq, q_result.X_);
            }
            q_result.freeResult();

            if (success_generating_p && success_generating_q) {
                // step 6 : (a) ensure p and q are far enough apart
                BN_sub(diff_p_q, p, q);
                int comp_result = BN_ucmp(diff_p_q, min_pq_diff_);
                if (comp_result == 1){
                    p_q_min_diff_success = true;
                } else {
                    printf("p and q are too close together, regenerating q\n");
                }
                // step 6 : (b) ensure Xp and Xq are far enough apart
                BN_sub(diff_Xp_Xq, Xp, Xq);
                comp_result = BN_ucmp(diff_Xp_Xq, min_pq_diff_);
                if (comp_result == 1){
                    Xp_Xq_min_diff_success = true;
                } else {
                    printf("Xp and Xq are too close together, regenerating q\n");
                }
            }
        }
    }

    // construct the instance of the result structure for the return
    ConstructPandQResult result;
    if (success_generating_p && success_generating_q) {
        result = ConstructPandQResult(true, p, q);
    } else {
        result = ConstructPandQResult();
    }
    // clean up the context used and its data
    if (construct_ctx){
        BN_CTX_end(construct_ctx);
        BN_CTX_free(construct_ctx);
    }
    return result;

}

ProbablePrimeGenerationWithAuxResult RSAKeyGeneration::constructAProbablePrimeWithAux(BIGNUM *r1, BIGNUM *r2, BIGNUM *e, int c){
    
    // the context to be used for the mathematical operations to allow memory cleanup
    BN_CTX *construct_ctx = BN_CTX_secure_new();
    BN_CTX_start(construct_ctx);
    
    // A temporary variable holding the value of 2 to be used in BIGNUM calculations
    BIGNUM *number_two = BN_CTX_get(construct_ctx);
    BN_set_word(number_two, 2);
    // A temporary variable holding the value of 8 to be used in BIGNUM calculations
    BIGNUM *number_eight = BN_CTX_get(construct_ctx);
    BN_set_word(number_eight, 8);

    // A temporary variable for 2 * r1
    BIGNUM *r1_mul_2 = BN_CTX_get(construct_ctx);
    // A temporary variable for r2 ** -1 % (2 * r1) * r2
    BIGNUM *r2_inv_mul_r2 = BN_CTX_get(construct_ctx);
    // A temporary variable for (2 * r1) ** -1 % r2 * (2 * r1)
    BIGNUM *r1_2_inv_mul_r1_2 = BN_CTX_get(construct_ctx);
    // A temporary variable for the greatest common denominator
    BIGNUM *gcd_result = BN_CTX_get(construct_ctx);
    // A temporary variable for R
    BIGNUM *R = BN_CTX_get(construct_ctx);
    // A temporary variable for X
    BIGNUM *X = BN_CTX_get(construct_ctx);
    // A temporary variable for 2 * r1 * r2
    BIGNUM *r1_r2_mul_2 = BN_CTX_get(construct_ctx);
    // A temporary variable for 8 * r1 * r2
    BIGNUM *r1_r2_mul_8 = BN_CTX_get(construct_ctx);
    // A temporary variable for Y 
    BIGNUM *Y = BN_CTX_get(construct_ctx);
    // A temporary variable for R - X
    BIGNUM *r_min_x = BN_CTX_get(construct_ctx);
    // A temporary variable for Y % 8
    BIGNUM *Y_mod_8 = BN_CTX_get(construct_ctx);
    // A temporary variable for the maximum value allowed for Y 
    BIGNUM *Y_max = BN_CTX_get(construct_ctx);
    // A temporary variable for the length of the prime as a BIGNUM
    BIGNUM *prime_length = BN_CTX_get(construct_ctx);

    // set the prime length
    BN_set_word(prime_length, getPrimeLength());
    // set Y max = 2 ** prime length
    BN_exp(Y_max, number_two, prime_length,context_);

    bool prime_found = false;
    bool successful_so_far = true;

    // calculate 2 * r1
    BN_mul(r1_mul_2, r1, number_two, context_);
    // Step 1 : ensure the greatest common denominator of 2*r1 and r2 is 1
    BN_gcd(gcd_result, r1_mul_2, r2, context_);
    successful_so_far = (BN_is_one(gcd_result) == 1);
    if (successful_so_far){
        // Step 2 : calculate R = ((r2**–1 % 2*r1) × r*2) – (((2*r1)**–1 % r2) × 2*r1).
        BN_mod_inverse(r2_inv_mul_r2, r2, r1_mul_2, context_);
        BN_mul(r2_inv_mul_r2, r2_inv_mul_r2, r2, context_);
        BN_mod_inverse(r1_2_inv_mul_r1_2, r1_mul_2, r2, context_);
        BN_mul(r1_2_inv_mul_r1_2, r1_2_inv_mul_r1_2, r1_mul_2, context_);
        BN_sub(R, r2_inv_mul_r2, r1_2_inv_mul_r1_2);

        // calculate 2 * r1 * r2 and 8 * r1 * r2
        BN_mul(r1_r2_mul_2, r1_mul_2, r2, context_);
        BN_copy(r1_r2_mul_8, r1_r2_mul_2);
        BN_mul_word(r1_r2_mul_8,4);

        int max_iterations = getPrimeLength() * 20;
        successful_so_far = false;

        for (int i =0; i < max_iterations; i++){
            int Y_in_range = 1;
            int X_in_range = -1;
            while (Y_in_range == 1){
                // Step 3 : generate random value for x between min and max prime
                while (X_in_range == -1){
                    BN_rand(X, getPrimeLength(),BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
                    X_in_range = BN_cmp(X, min_prime_value_);
                }
               
                // step 4 : calculate Y = X + ((R – X) % 2*r1*r2).
                BN_mod_sub(r_min_x, R, X, r1_r2_mul_2,context_);
                BN_add(Y, r_min_x, X);
                // set Y to the only element of the following values {Y, Y + 2*r1*r2, Y + 4*r1*r2, Y +6*r1*r2} that is equal to c mod 8
                if (c != -1){
                    BN_mod(Y_mod_8, number_eight, Y, context_);
                    int compare_to_c = BN_is_word(Y_mod_8, c);
                    if(compare_to_c == 0){
                        BN_add(Y, Y, r1_r2_mul_2);
                        BN_mod(Y_mod_8, number_eight, Y, context_);
                        int compare_to_c = BN_is_word(Y_mod_8, c);
                        if(compare_to_c == 0){
                            BN_add(Y, Y, r1_r2_mul_2);
                            BN_mod(Y_mod_8, number_eight, Y, context_);
                            int compare_to_c = BN_is_word(Y_mod_8, c);
                        }
                    }
                }
                // Step 6 : ensure Y is below the maximum value for a prime given the key length
                Y_in_range = BN_cmp(Y, Y_max);
            }
            // Step 7 : ensure the gcd of Y - 1 and e is 1
            BigNumHelpers::gcdValueMinusOneSecondValue(Y, e);
            successful_so_far = (BN_is_one(gcd_result) == 1);
            if (successful_so_far){
                prime_found = BN_check_prime(Y, context_,nullptr) == 1;
                if(prime_found){
                    break;
                }
            }

            // Step 10 : increment Y
            if(c != -1){
                BN_add(Y, Y, r1_r2_mul_8);
            } else{
                BN_add(Y, Y, r1_r2_mul_2);
            }
        }
    }
    // Construct the prime generation result using Y as the prime and the X that was used to generate Y
    ProbablePrimeGenerationWithAuxResult result;
    if (prime_found){
        result = ProbablePrimeGenerationWithAuxResult(true, Y, X);
    } else {
        result = ProbablePrimeGenerationWithAuxResult();
    }
    // clean up the context used and its data
    if (construct_ctx){
        BN_CTX_end(construct_ctx);
        BN_CTX_free(construct_ctx);
    }
    return result;
}