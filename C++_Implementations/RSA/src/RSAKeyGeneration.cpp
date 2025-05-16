/// This file handles generation of RSA Keys in C++
///
/// Libaries Used : OpenSSL BIGNUM for dealing with extremely large integers
/// Author        : Jamie Barbour-Moore
/// Created       : 05/12/25
/// Updated       : 05/14/25

#include "RSAKeyGeneration.hpp"

RSAKeyGeneration::RSAKeyGeneration(int keylength){
    keylength_ = keylength;

    setEParameters();
    setMinPQDiff();
    setMinPrimeValue();
}

BIGNUM* RSAKeyGeneration::generatePrivateExponent(BIGNUM *e, BIGNUM *p, BIGNUM *q){
    BN_CTX_start(context_);
    // phi = (p.getValue() - 1) * (q.getValue() - 1)
    BIGNUM *phi = BN_CTX_get(context_);

    // p_1 = p.getValue() - 1
    BIGNUM *p_min_1 = BN_CTX_get(context_);
    p_min_1 = BN_copy(p_min_1, p);
    BN_sub_word(p_min_1, 1);

    // q_1 = q.getValue() - 1
    BIGNUM *q_min_1  = BN_CTX_get(context_);
    q_min_1 = BN_copy(q_min_1, q);
    BN_sub_word(q_min_1, 1);

    BN_mul(phi, q_min_1, p_min_1, context_);

    // gcd_p1_q1 = euclidsAlgorithm(p_1, q_1)
    BIGNUM *gcd_p1_q1 = BN_CTX_get(context_);
    BN_gcd(gcd_p1_q1, p_min_1, q_min_1, context_);

    // phi = p_1 * q_1 // gcd_p1_q1
    BN_div(phi, NULL, phi, gcd_p1_q1, context_);

    // d = calculateInverseMod_GCD1_ExtendedEuclidsBased(e.getValue(), phi)
    BIGNUM *d = BN_new();
    BN_mod_inverse(d, e, phi, context_);

    BN_CTX_end(context_);

    return d;
}

BIGNUM* RSAKeyGeneration::generateRandomE(){
    int security_strength = getSecurityStrength();

    BIGNUM *random = BN_new();

    int bits = 256 - 16;

    // generate the random value in the range
    int success = BN_rand_ex(random, bits, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ODD, security_strength, context_);

    assert(success == 1);

    // add the random value to e_min
    BN_add(random, random, e_min_);

    return random;
}

RSAKeyGenerationResult RSAKeyGeneration::generateRSAKeysUsingProbablePrimes(int a, int b, bool use_key_quintuple_form){

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

        result_primes = constructTheProbablePrimes(a, b, e);
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
            e_retry++;
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


ConstructPandQResult RSAKeyGeneration::constructTheProbablePrimes(int a, int b, BIGNUM *e){

    int security_strength = getSecurityStrength();
    int max_iterations = 10 * keylength_;

    BIGNUM *number_eight = BN_new();
    BN_set_word(number_eight,8);

    // the first prime being generated with optional restriction a
    BIGNUM *p = BN_new();

     // the second prime being generated with optional restriction b
    BIGNUM *q = BN_new();

    BIGNUM* temp_value = BN_new();

    BN_GENCB *callback;
    callback = BN_GENCB_new();

    for(int i = 0; i <= max_iterations; i ++){
        int p_cmp_minprime = -1;
        while (p_cmp_minprime == -1){
            BN_rand(p, getPrimeLength(), BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ODD);
            if (a != -1){
                BIGNUM *a_bn = BN_new();
                BN_set_word(a_bn, a);
                BN_mod_sub(temp_value, a_bn, p, number_eight, context_);

                BN_add(p, p, temp_value);
            }
            p_cmp_minprime = BN_cmp(p, min_prime_value_);
        }

        temp_value = BigNumHelpers::gcdValueMinusOneSecondValue(p, e);

        if (BN_is_one(temp_value) == 1){
            // int is_prime = BN_check_prime(p, context_, gencb);
            int is_prime = BN_check_prime(p, context_, nullptr);
            if (is_prime == 1){
                break;
            }
        }

        if ( i >= max_iterations){
            printf("Failed to construct p\n");
            return ConstructPandQResult();
        }
    }

    for(int i = 0; i <= max_iterations; i ++){
        int q_cmp_minprime = -1;
        int qminp_cmp_mindiff = -1;
        while (q_cmp_minprime == -1 || qminp_cmp_mindiff == -1){
            BN_rand(q, getPrimeLength(), BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ODD);
            if (b != -1){
                BIGNUM *b_bn = BN_new();
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
                char *hex_p = BN_bn2hex(p);
                printf("%d : p is %s\n", is_prime, hex_p);
                hex_p = BN_bn2hex(q);
                printf("%d : q is %s\n", is_prime, hex_p);
                break;
            }
        }

        if ( i >= max_iterations){
            printf("Failed to construct q\n");
            return ConstructPandQResult();
        }
    }

    return ConstructPandQResult(true, p, q);

}

ShaweTaylorRandomPrimeResult RSAKeyGeneration::generateRandomPrimeWithShaweTaylor(int length, BIGNUM* input_seed){
    ShaweTaylorRandomPrimeResult false_result {};

    BN_CTX *ctx_shawe = BN_CTX_new();
    assert(ctx_shawe != NULL);

    BN_CTX_start(ctx_shawe);

    // BIGNUM *prime_seed;
    // BigNumHelpers::getBNCopyInContext(prime_seed, input_seed, ctx_shawe);
    // OPENSSL_assert(prime_seed != nullptr);
    // const char *seed_hex = BN_bn2hex(prime_seed);
    // printf("prime seed %s\n", seed_hex);

    BIGNUM *prime_seed = BN_new();
    BN_copy(prime_seed, input_seed);

    BIGNUM *copied_input_seed = BN_new();
    BN_copy(copied_input_seed, input_seed);

    BIGNUM *number_one = BN_CTX_get(ctx_shawe);
    BN_set_word(number_one, 1);
    BIGNUM *number_two = BN_CTX_get(ctx_shawe);
    BN_set_word(number_two, 2);

    int prime_gen_counter = 0;
    int max_counter = length * 10;

    BN_CTX *while_lt33_ctx = BN_CTX_secure_new();
    if (length < 33) {
        while (prime_gen_counter <= max_counter){
            BN_CTX_start(while_lt33_ctx);

            // step 5 : XOR(hash(pseed),hash(pseed+1))
            BIGNUM *hash_prime_seed = BN_CTX_get(while_lt33_ctx);

            PassBigNum prime_seed_to_hash = PassBigNum(prime_seed);
            BigNumHelpers::sha512BigNum(prime_seed_to_hash).copyAndClear(hash_prime_seed);
            BIGNUM *inc_seed = BN_CTX_get(while_lt33_ctx);
            BN_add(inc_seed, prime_seed, number_one);
            BIGNUM *hash_inc_seed = BN_CTX_get(while_lt33_ctx);
            PassBigNum prime_inc_seed_to_hash = PassBigNum(inc_seed);
            BigNumHelpers::sha512BigNum(prime_inc_seed_to_hash).copyAndClear(hash_inc_seed);
            BIGNUM *c = BigNumHelpers::xorBigNums(hash_prime_seed, hash_inc_seed);

            // step 6
            BIGNUM *c_base = BN_CTX_get(while_lt33_ctx);
            int length_minus_1 = length - 1;
            BIGNUM *length_1_bn = BN_CTX_get(while_lt33_ctx);
            BN_set_word(length_1_bn,length_minus_1);
            BN_exp(c_base, number_two, length_1_bn, context_);
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
                
                ShaweTaylorRandomPrimeResult final_result {true, c, prime_seed, prime_gen_counter};
                BN_CTX_end(while_lt33_ctx);
                BN_CTX_free(while_lt33_ctx);
                BN_CTX_end(ctx_shawe);
                BN_CTX_free(ctx_shawe);
                return final_result;
            }

            // step 12
            if (prime_gen_counter > max_counter){
                printf("length %d : Failed at counter %d with max %d\n",length, prime_gen_counter,max_counter);
                BN_CTX_end(while_lt33_ctx);
                BN_CTX_free(while_lt33_ctx);
                BN_CTX_end(ctx_shawe);
                BN_CTX_free(ctx_shawe);
                return false_result;
            }
            BN_CTX_end(while_lt33_ctx);
        }
    }

    // step 14
    ShaweTaylorRandomPrimeResult iterative_result = generateRandomPrimeWithShaweTaylor(length/2, copied_input_seed);
    
    BN_CTX *after_recurse_ctx = BN_CTX_secure_new();
    BN_CTX_start(after_recurse_ctx);

    // step 15
    if (iterative_result.success_ == false) {
        return false_result;
    }

    // step 16
    int iteration = length / hash_length_;
    if (length % hash_length_ == 0 and iteration != 0){
        iteration -= 1;
    }

    BIGNUM *c0 = BN_CTX_get(after_recurse_ctx);
    BN_copy(c0, iterative_result.prime_);
    prime_seed = BN_CTX_get(after_recurse_ctx);
    BN_copy(c0, iterative_result.prime_seed_);
    max_counter = length * 4 + iterative_result.prime_gen_counter_;

    // iterative_result.freeResult();
   
    // step 18
    BIGNUM *x = BN_CTX_get(after_recurse_ctx);
    BN_set_word(x, 0);

    // step 19
    // BIGNUM *hash_for_x;
    BIGNUM *two_to_ihashlen = BN_CTX_get(after_recurse_ctx);
    BIGNUM *prime_seed_inc_i = BN_CTX_get(after_recurse_ctx);
    BIGNUM *hash_value = BN_CTX_get(after_recurse_ctx);
    for (int i = 0; i <= iteration; i ++){
        BN_set_word(two_to_ihashlen, i * hash_length_);
        BN_exp(two_to_ihashlen, number_two, two_to_ihashlen, context_);
        BN_set_word(prime_seed_inc_i, i);
        BN_add(prime_seed_inc_i,prime_seed_inc_i,prime_seed);
        PassBigNum pass_prime_seed_inc = PassBigNum(prime_seed_inc_i);
        BigNumHelpers::sha512BigNum(pass_prime_seed_inc).copyAndClear(hash_value);
        
        BN_mul(prime_seed_inc_i, hash_value,two_to_ihashlen,context_);
        BN_add(x, x, prime_seed_inc_i);
        // BN_free(hash_value);
    }

    // step 20
    BN_add_word(prime_seed, iteration + 1);

    // step 21
    BIGNUM *two_length_1_bn = BN_CTX_get(after_recurse_ctx);
    BN_set_word(two_length_1_bn, length - 1);
    BN_exp(two_length_1_bn,number_two, two_length_1_bn, context_);
    BN_mod(x,  x,two_length_1_bn, context_);
    BN_add(x, x, two_length_1_bn);

    // step 22
    BIGNUM *two_c0 = BN_CTX_get(after_recurse_ctx);
    BN_mul(two_c0, c0, number_two, context_);
    BIGNUM *t = BN_CTX_get(after_recurse_ctx);
    BIGNUM *t_rem = BN_CTX_get(after_recurse_ctx);
    BN_div(t, t_rem, x, two_c0, context_);
    if (BN_is_zero(t_rem) != 1){
        BN_add_word(t, 1);
    }

    while (prime_gen_counter <= max_counter){

        // step 23

        // temporary variable for 2 * c_0
        BIGNUM *t2c0 = BN_CTX_get(after_recurse_ctx);
        BN_mul(t2c0, t, two_c0, context_);

        // temporary variable for 2 ** length
        BIGNUM *two_to_length = BN_CTX_get(after_recurse_ctx);

        // temporary variable for length as a BIGNUM
        BIGNUM *length_bn = BN_CTX_get(after_recurse_ctx);
        BN_set_word(length_bn, length);
        BN_exp(two_to_length, number_two, length_bn, context_);
        int cmp_t2c0_2toL = BN_cmp(t2c0, two_to_length);
        if(cmp_t2c0_2toL == 0 or cmp_t2c0_2toL == 1){
            BIGNUM *t = BN_CTX_get(after_recurse_ctx);
            BIGNUM *t_rem = BN_CTX_get(after_recurse_ctx);
            BN_div(t, t_rem, two_length_1_bn, two_c0, context_);
            if (BN_is_zero(t_rem) != 1){
                BN_add_word(t, 1);
            }
        }

        // step 24
        // the candidate prime
        BIGNUM *c = BN_CTX_get(after_recurse_ctx);
        BN_mul(c, two_c0, t, context_);
        BN_add_word(c, 1);

        // step 25
        prime_gen_counter += 1;

        // step 26

        // temporary variable for a
        BIGNUM *a = BN_CTX_get(after_recurse_ctx);
        BN_set_word(a, 0);
        
        hash_value = BN_CTX_get(after_recurse_ctx);
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
        BIGNUM *c_min_3 = BN_CTX_get(after_recurse_ctx);
        BN_copy(c_min_3, c);
        BN_sub_word(c_min_3, 3);
        BN_mod(a, a, c_min_3, context_);
        BN_add_word(a, 2);

        // step 30 : z = a ** 2t mod c
        // temporary variable for z (z = a ** 2t mod c)
        BIGNUM *z = BN_CTX_get(after_recurse_ctx);
        BN_mul(z, t, number_two, context_);
        BN_mod_exp(z, a, z, c, context_);
        
        // step 31
        BIGNUM *gcd_result = BigNumHelpers::gcdValueMinusOneSecondValue(z, c);
        
        if(BN_is_one(gcd_result) == 1){

            BIGNUM *z_c0_modc = BN_CTX_get(after_recurse_ctx);
            BN_mod_exp(z_c0_modc, z, c0, c, context_);

            if(BN_is_one(z_c0_modc) == 1){
                 
                ShaweTaylorRandomPrimeResult final_result {true, c, prime_seed, prime_gen_counter};

                // if (gcd_result){
                //     BN_free(gcd_result);
                // }
                // if(ctx_shawe){
                //     BN_CTX_end(ctx_shawe);
                //     BN_CTX_free(ctx_shawe);
                // }
                if (after_recurse_ctx){
                    BN_CTX_end(after_recurse_ctx);
                    BN_CTX_free(after_recurse_ctx);
                }
                

                return final_result;
            }
        }

        // step 32
        if (prime_gen_counter > max_counter){
            printf("Failed with gen_counter %d\n",prime_gen_counter);
            // BN_free(gcd_result);
            // BN_CTX_end(ctx_shawe);
            // BN_CTX_free(ctx_shawe);
            return false_result;
        }
        // BN_free(gcd_result);
        BN_add_word(t, 1);
    }
    // printf("failed unknown ?\n");
    // BN_CTX_end(ctx_shawe);
    // BN_CTX_free(ctx_shawe);
    return false_result;
};


BIGNUM* RSAKeyGeneration::generateRandomSeed(){
    BIGNUM *seed = BN_new();
    int security_strength = getSecurityStrength();
    int length = 2 * security_strength + 1;
    int success = BN_rand_ex(seed, length, BN_RAND_TOP_ANY,BN_RAND_BOTTOM_ANY,security_strength,context_);
    assert(success == 1);
    return seed;
}

void RSAKeyGeneration::setEParameters(){
    // the max and min values for e as a hexadecimal string
    const char *hex_e_min = "010000";
    const char *hex_e_max = "010000000000000000000000000000000000000000000000000000000000000000";

    // set them to BIGNUM
    BN_hex2bn(&e_min_, hex_e_min);
    BN_hex2bn(&e_max_, hex_e_max);
}

void RSAKeyGeneration::setMinPrimeValue(){
    const char *hex_min_prime = "0";
    if (keylength_ == 2048) {
        hex_min_prime = "B504F333F9DE68000000000D69DD51BA07CF0930728CA984CB424FC1B7692DDBFB70A9E5D469EADD536D45398DBBCD6022779634136D29612502CB8F6F04FB3B56A2928A53073CE3978083009F5EA4E0769E4764B0DD62D32B887102580000000000000000000000000000000000000000000000000000000000000000000000";
    } else if (keylength_ == 3072) {
        hex_min_prime = "B504F333F9DE68000000000D7D4F8EC5E6F9B24422D017252D192AF704E153170ADAD97CC0E577EA17BBCCAC3B5D45DC7BBF091F9F7689FB695C4090112C398E9DEA1F7542D12CFD4C15C4C470EC669C40F3A44756C31D6DE70D14567EE58B317033D483B06CEF75B304CCAC47969D0B855F372238BFCCDBC693CE1379C972302BF4C903C0079A203498000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    } else if (keylength_ == 7680) {
        hex_min_prime = "B504F333F9DE680000000002DBCC5944D29679C6B026782D549D7DCCF5262B98E3380803F98DE79154E014E4C1AF8C4C4195882D2CAA63D6DB99C5EAF54D05E6F2129440E66D0B3F91D35C72633EBC00E65D69D7AEFA055325B0BA383F52489054F54B8A6DCB0A9412E234D861834749F74DF80CCDCF08019F7C16ADDC5124B3ECA3588FB07A40CC680FF498A0F377D9AE6B00152C97AE8733B7CD205E6640A62D4F1CE8B28CE40E10D981DAF45AAF4967D4BB6315D887EB80DED69A8461FB5C49B3FCB0C23450F625C77E3FCBE5854E8E51B3051018FD4F2A4EB17890AB7F2C0B0739BF37D60AFAC3861F20D20BB27FBEEF685D738CA0E199C9D32677F23485233D57FE17E4D57639BC8C5642EBE6A37BCF06C6BE25C0CA755EE3FB0DB90AA5559E45F8997D1F0443D70320541210A7E143E02BE39BB5C742CBEEDB04F87A0E88BE86DB98FC4B0E0F0186C0032979B8CF479B000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    } else if (keylength_ == 15360){
        hex_min_prime = "B504F333F9DE67FFFFFFFFFECF09E99863EFFE0BD0AA9D1F60903DFA4EED6F77C50A7E35CE10A18FA81A5AEC7B5EAE72792308005139A883364CAA573DB390221C62D2C5EE34B0CFE28A3FF00846327292B6DC7BF0F0393B0B3B53ABBE7A21859AEAD2FA3A23433043B3BA7FDE39368AF5538145BBE5104D0B32D50A2BE65618D6E99E8C160C39D01CA36EA3684527AE13BA83A0DB32C27D31EBDA8778EE3C591815E02F3C3543B5EB66D3B3EDB5E8600F85B6D694C980145451E9477845203F1EB2ADD3D6349D0FB70027DCFE0A11DAC6EA64ADE77317F743D28E859561F93D7E16651C275ACC78D7257AE4095CA3D68DFAD533CDE7A0D6F66CA543BBC984595980CCA4DAAE3EF538DA716BC41A1705034112D4B762D74084D95BB2CCB7967426DBAFDCF8A9AA1072946D7C24E7C53C1D5D99DF4B8E0AE25810E9931017D9C8A3F47B3284DD5A2EE6D0737B43E1CD98B4E43CC4AEF208688BA370AC68692A728CD5EBD545B5A1C4ADE7CC3F16DD1643CC4F2E515698F65523ABE1DE038E4469216E6BEA3CE6F5C1F3A4F111A7FB2E5253526B74B18BAC1465E9709E625830F4CB715DE01E0CBF7D45F53BCE4E07A8A25870CF4EC842E8318D5838D069C3181290BA1936E4D064AB91F47EEBA8363F8A6A8B73D195D13238FCB5929D88433EDD6126E142B271278D1882DB0F1B4646D5984426678643F918B6A464DB914D25D4681AF0E753F8C5016467393A419C9A3B72B3174C9C186A182B4A7F7F928CC73EB738254732048D5225E96E451454201418FD4E813EEB58BEF28668566A23FCE0E15635E38728585A2EC0F111DE326313C96BE6D63B1239206AC77CAC0D936BE8160878A2FA5906DC6020FECB4CDD4B65ED87B5B25F14549F0486FF6B89074CFBDBEE61F5F3245A819BF1206D6796DC9C72F400147D73E8CF7B1EAF30BCB39F15F955F0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    }
    BN_hex2bn(&min_prime_value_, hex_min_prime);
}

void RSAKeyGeneration::setMinPQDiff(){
    const char *hex_min_diff = "0";
    if (keylength_ == 2048) {
        hex_min_diff = "1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    } else if (keylength_ == 3072) {
        hex_min_diff = "100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    } else if (keylength_ == 7680) {
        hex_min_diff = "100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    } else if (keylength_ == 15360){
        hex_min_diff = "100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    }
    BN_hex2bn(&min_pq_diff_, hex_min_diff);
}

int RSAKeyGeneration::getSecurityStrength(){
    int security_strength = 0;
    if (keylength_ == 2048) {
        security_strength = 112;
    } else if (keylength_ == 3072) {
        security_strength = 128;
    } else if (keylength_ == 7680) {
        security_strength = 192;
    } else if (keylength_ == 15360){
        security_strength = 256;
    }
    return security_strength;
};

int RSAKeyGeneration::getKeyLength(){
    return keylength_;
};

int RSAKeyGeneration::getPrimeLength(){
    return keylength_ / 2;
};