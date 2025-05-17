#include "RSAKeyGeneration.hpp"

RSAKeyGenerationResult RSAKeyGeneration::generateRSAKeysUsingProbablePrimes(int a, int b, bool use_key_quintuple_form){

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

    e = generateRandomE();

    int d_is_0 = 1;
    ConstructPandQResult result_primes;
    while(d_is_0 == 1){

        // generate a random seed
        seed = generateRandomSeed();
    
        result_primes = constructTheProbablePrimes(a, b, e);

        if(result_primes.success_){

            BN_copy(p, result_primes.p_);
            BN_copy(q, result_primes.q_);
            result_primes.freeResult();

            d = generatePrivateExponent(e, p, q);
            
            d_is_0 = BN_is_zero(d);

            int e_retry = 0;
            while( d_is_0 and e_retry < 10){
                printf("retrying new e\n");
                e = generateRandomE();
                d_is_0 = BN_is_zero(d);
                e_retry++;
            }
        }
    }

    BN_mul(n, p, q, context_);

    RSAPrivateKey private_key;
    if (use_key_quintuple_form){
        private_key = RSAPrivateKey(n, d, p, q, keylength_);
    } else {
        private_key = RSAPrivateKey(n, d, keylength_);
    }
    RSAPublicKey public_key = RSAPublicKey(n, e, keylength_);
    RSAKeyGenerationResult key_generation_result = RSAKeyGenerationResult(true,private_key,public_key,keylength_);
    
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
            BN_rand(p, getPrimeLength(), BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ODD);
            if (a != -1){
                BN_set_word(a_bn, a);
                BN_mod_sub(temp_value, a_bn, p, number_eight, context_);
                BN_add(p, p, temp_value);
            }
            p_cmp_minprime = BN_cmp(p, min_prime_value_);
        }

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
                BN_rand(q, getPrimeLength(), BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ODD);
                if (b != -1){
                    BN_set_word(b_bn, b);
                    BN_mod_sub(temp_value, b_bn, q, number_eight, context_);
                    BN_add(q, q, temp_value);
                }
                q_cmp_minprime = BN_cmp(q, min_prime_value_);
                BN_usub(temp_value, p, q);
                qminp_cmp_mindiff = BN_cmp(temp_value, min_pq_diff_);
            }
            
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

    ConstructPandQResult result;
    if (success_generating_p && success_generating_q) {
        result = ConstructPandQResult(true, p, q);
    } else {
        result = ConstructPandQResult();
    }
    if (construct_ctx){
        BN_CTX_end(construct_ctx);
        BN_CTX_free(construct_ctx);
    }
    return result;

}