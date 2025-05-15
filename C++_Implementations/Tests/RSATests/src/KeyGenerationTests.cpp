#include <gtest/gtest.h>  
#include <stddef.h>

#include "RSAPublicKey.hpp"
#include "RSAPrivateKey.hpp"
#include "RSAKeyGeneration.hpp"

/// @brief This unit tests generating a random key with bit length 2048 and using it to encrypt and decrypt a message 
TEST(KeyGenerationTests_ProvablyPrime, Test_nlen_2048_quint) {
    int keylength = 2048;
    bool use_quintuple_form = true;
    const char *input_message = "9BCD6D0F92B6495814E2F5701E051FD8EEEEB98C444CE784662CF27DBD8FFD22EBA7AF50E11FDD737203D6242C812899566E1954825B9F2B2F4EBD475A38DDE51E93D9422E0645D917CE19375CC2997C2CF6AFD1FC64522B95B270AAC53CFF674CF00257DB33496B310F0AEB4E6263B45C1F9465525CCE75FEB093B3CA345AB46593782421517248B4A1BB86378D99D1304FFBB664735908E166381E95CE7CF18041A8841F05A62A7D4F3CCA94A55032995EF19D404F25692D42A198491A8984477E937A25098B2C11AEB3FCE325C984FD6A3CEF91EB46E5DFDA9BE34877662F938A32D490D8CAFCD030927D5DFB70BB7632392D343C7EB7D403CE850B864C5C";
    RSAKeyGeneration my_key_gen = RSAKeyGeneration(keylength);

    RSAKeyGenerationResult gen_res = my_key_gen.generateRSAKeysUsingProvablePrimes(use_quintuple_form);
    const char *encrypted_message = gen_res.public_key_.encryptionPrimitive(input_message);
    const char *decrypted_message = gen_res.private_key_.decryptionPrimitive(encrypted_message);
    
    EXPECT_NE(strcmp(encrypted_message, input_message), 0);
    EXPECT_EQ(strcmp(decrypted_message, input_message), 0);
}

/// @brief This unit tests generating a random key with bit length 3076 and using it to encrypt and decrypt a message 
TEST(KeyGenerationTests_ProvablyPrime, Test_nlen_3076_quint) {
    int keylength = 3076;
    bool use_quintuple_form = true;
    const char *input_message = "9BCD6D0F92B6495814E2F5701E051FD8EEEEB98C444CE784662CF27DBD8FFD22EBA7AF50E11FDD737203D6242C812899566E1954825B9F2B2F4EBD475A38DDE51E93D9422E0645D917CE19375CC2997C2CF6AFD1FC64522B95B270AAC53CFF674CF00257DB33496B310F0AEB4E6263B45C1F9465525CCE75FEB093B3CA345AB46593782421517248B4A1BB86378D99D1304FFBB664735908E166381E95CE7CF18041A8841F05A62A7D4F3CCA94A55032995EF19D404F25692D42A198491A8984477E937A25098B2C11AEB3FCE325C984FD6A3CEF91EB46E5DFDA9BE34877662F938A32D490D8CAFCD030927D5DFB70BB7632392D343C7EB7D403CE850B864C5C";
    RSAKeyGeneration my_key_gen = RSAKeyGeneration(keylength);

    RSAKeyGenerationResult gen_res = my_key_gen.generateRSAKeysUsingProvablePrimes(use_quintuple_form);
    const char *encrypted_message = gen_res.public_key_.encryptionPrimitive(input_message);
    const char *decrypted_message = gen_res.private_key_.decryptionPrimitive(encrypted_message);
    
    EXPECT_NE(strcmp(encrypted_message, input_message), 0);
    EXPECT_EQ(strcmp(decrypted_message, input_message), 0);
}

/// @brief This unit tests generating a random key with bit length 7680 and using it to encrypt and decrypt a message 
TEST(KeyGenerationTests_ProvablyPrime, Test_nlen_7680_quint) {
    int keylength = 7680;
    bool use_quintuple_form = true;
    const char *input_message = "9BCD6D0F92B6495814E2F5701E051FD8EEEEB98C444CE784662CF27DBD8FFD22EBA7AF50E11FDD737203D6242C812899566E1954825B9F2B2F4EBD475A38DDE51E93D9422E0645D917CE19375CC2997C2CF6AFD1FC64522B95B270AAC53CFF674CF00257DB33496B310F0AEB4E6263B45C1F9465525CCE75FEB093B3CA345AB46593782421517248B4A1BB86378D99D1304FFBB664735908E166381E95CE7CF18041A8841F05A62A7D4F3CCA94A55032995EF19D404F25692D42A198491A8984477E937A25098B2C11AEB3FCE325C984FD6A3CEF91EB46E5DFDA9BE34877662F938A32D490D8CAFCD030927D5DFB70BB7632392D343C7EB7D403CE850B864C5C";
    RSAKeyGeneration my_key_gen = RSAKeyGeneration(keylength);

    RSAKeyGenerationResult gen_res = my_key_gen.generateRSAKeysUsingProvablePrimes(use_quintuple_form);
    const char *encrypted_message = gen_res.public_key_.encryptionPrimitive(input_message);
    const char *decrypted_message = gen_res.private_key_.decryptionPrimitive(encrypted_message);
    
    EXPECT_NE(strcmp(encrypted_message, input_message), 0);
    EXPECT_EQ(strcmp(decrypted_message, input_message), 0);
}

/// @brief This unit tests generating a random key with bit length 15360 and using it to encrypt and decrypt a message 
TEST(KeyGenerationTests_ProvablyPrime, Test_nlen_15360_quint) {
    int keylength = 15360;
    bool use_quintuple_form = true;
    const char *input_message = "9BCD6D0F92B6495814E2F5701E051FD8EEEEB98C444CE784662CF27DBD8FFD22EBA7AF50E11FDD737203D6242C812899566E1954825B9F2B2F4EBD475A38DDE51E93D9422E0645D917CE19375CC2997C2CF6AFD1FC64522B95B270AAC53CFF674CF00257DB33496B310F0AEB4E6263B45C1F9465525CCE75FEB093B3CA345AB46593782421517248B4A1BB86378D99D1304FFBB664735908E166381E95CE7CF18041A8841F05A62A7D4F3CCA94A55032995EF19D404F25692D42A198491A8984477E937A25098B2C11AEB3FCE325C984FD6A3CEF91EB46E5DFDA9BE34877662F938A32D490D8CAFCD030927D5DFB70BB7632392D343C7EB7D403CE850B864C5C";
    RSAKeyGeneration my_key_gen = RSAKeyGeneration(keylength);

    RSAKeyGenerationResult gen_res = my_key_gen.generateRSAKeysUsingProvablePrimes(use_quintuple_form);
    const char *encrypted_message = gen_res.public_key_.encryptionPrimitive(input_message);
    const char *decrypted_message = gen_res.private_key_.decryptionPrimitive(encrypted_message);

    EXPECT_NE(strcmp(encrypted_message, input_message), 0);
    EXPECT_EQ(strcmp(decrypted_message, input_message), 0);
}
/// @brief This unit tests generating a random key with bit length 2048 and using it to encrypt and decrypt a message 
TEST(KeyGenerationTests_ProvablyPrime, Test_nlen_2048_standard) {
    int keylength = 2048;
    bool use_quintuple_form = false;
    const char *input_message = "9BCD6D0F92B6495814E2F5701E051FD8EEEEB98C444CE784662CF27DBD8FFD22EBA7AF50E11FDD737203D6242C812899566E1954825B9F2B2F4EBD475A38DDE51E93D9422E0645D917CE19375CC2997C2CF6AFD1FC64522B95B270AAC53CFF674CF00257DB33496B310F0AEB4E6263B45C1F9465525CCE75FEB093B3CA345AB46593782421517248B4A1BB86378D99D1304FFBB664735908E166381E95CE7CF18041A8841F05A62A7D4F3CCA94A55032995EF19D404F25692D42A198491A8984477E937A25098B2C11AEB3FCE325C984FD6A3CEF91EB46E5DFDA9BE34877662F938A32D490D8CAFCD030927D5DFB70BB7632392D343C7EB7D403CE850B864C5C";
    RSAKeyGeneration my_key_gen = RSAKeyGeneration(keylength);

    RSAKeyGenerationResult gen_res = my_key_gen.generateRSAKeysUsingProvablePrimes(use_quintuple_form);
    const char *encrypted_message = gen_res.public_key_.encryptionPrimitive(input_message);
    const char *decrypted_message = gen_res.private_key_.decryptionPrimitive(encrypted_message);
    
    EXPECT_NE(strcmp(encrypted_message, input_message), 0);
    EXPECT_EQ(strcmp(decrypted_message, input_message), 0);
}

/// @brief This unit tests generating a random key with bit length 3076 and using it to encrypt and decrypt a message 
TEST(KeyGenerationTests_ProvablyPrime, Test_nlen_3076_standard) {
    int keylength = 3076;
    bool use_quintuple_form = false;
    const char *input_message = "9BCD6D0F92B6495814E2F5701E051FD8EEEEB98C444CE784662CF27DBD8FFD22EBA7AF50E11FDD737203D6242C812899566E1954825B9F2B2F4EBD475A38DDE51E93D9422E0645D917CE19375CC2997C2CF6AFD1FC64522B95B270AAC53CFF674CF00257DB33496B310F0AEB4E6263B45C1F9465525CCE75FEB093B3CA345AB46593782421517248B4A1BB86378D99D1304FFBB664735908E166381E95CE7CF18041A8841F05A62A7D4F3CCA94A55032995EF19D404F25692D42A198491A8984477E937A25098B2C11AEB3FCE325C984FD6A3CEF91EB46E5DFDA9BE34877662F938A32D490D8CAFCD030927D5DFB70BB7632392D343C7EB7D403CE850B864C5C";
    RSAKeyGeneration my_key_gen = RSAKeyGeneration(keylength);

    RSAKeyGenerationResult gen_res = my_key_gen.generateRSAKeysUsingProvablePrimes(use_quintuple_form);
    const char *encrypted_message = gen_res.public_key_.encryptionPrimitive(input_message);
    const char *decrypted_message = gen_res.private_key_.decryptionPrimitive(encrypted_message);
    
    EXPECT_NE(strcmp(encrypted_message, input_message), 0);
    EXPECT_EQ(strcmp(decrypted_message, input_message), 0);
}

/// @brief This unit tests generating a random key with bit length 7680 and using it to encrypt and decrypt a message 
TEST(KeyGenerationTests_ProvablyPrime, Test_nlen_7680_standard) {
    int keylength = 7680;
    bool use_quintuple_form = false;
    const char *input_message = "9BCD6D0F92B6495814E2F5701E051FD8EEEEB98C444CE784662CF27DBD8FFD22EBA7AF50E11FDD737203D6242C812899566E1954825B9F2B2F4EBD475A38DDE51E93D9422E0645D917CE19375CC2997C2CF6AFD1FC64522B95B270AAC53CFF674CF00257DB33496B310F0AEB4E6263B45C1F9465525CCE75FEB093B3CA345AB46593782421517248B4A1BB86378D99D1304FFBB664735908E166381E95CE7CF18041A8841F05A62A7D4F3CCA94A55032995EF19D404F25692D42A198491A8984477E937A25098B2C11AEB3FCE325C984FD6A3CEF91EB46E5DFDA9BE34877662F938A32D490D8CAFCD030927D5DFB70BB7632392D343C7EB7D403CE850B864C5C";
    RSAKeyGeneration my_key_gen = RSAKeyGeneration(keylength);

    RSAKeyGenerationResult gen_res = my_key_gen.generateRSAKeysUsingProvablePrimes(use_quintuple_form);
    const char *encrypted_message = gen_res.public_key_.encryptionPrimitive(input_message);
    const char *decrypted_message = gen_res.private_key_.decryptionPrimitive(encrypted_message);
    
    EXPECT_NE(strcmp(encrypted_message, input_message), 0);
    EXPECT_EQ(strcmp(decrypted_message, input_message), 0);
}

/// @brief This unit tests generating a random key with bit length 15360 and using it to encrypt and decrypt a message 
TEST(KeyGenerationTests_ProvablyPrime, Test_nlen_15360_standard) {
    int keylength = 15360;
    bool use_quintuple_form = false;
    const char *input_message = "9BCD6D0F92B6495814E2F5701E051FD8EEEEB98C444CE784662CF27DBD8FFD22EBA7AF50E11FDD737203D6242C812899566E1954825B9F2B2F4EBD475A38DDE51E93D9422E0645D917CE19375CC2997C2CF6AFD1FC64522B95B270AAC53CFF674CF00257DB33496B310F0AEB4E6263B45C1F9465525CCE75FEB093B3CA345AB46593782421517248B4A1BB86378D99D1304FFBB664735908E166381E95CE7CF18041A8841F05A62A7D4F3CCA94A55032995EF19D404F25692D42A198491A8984477E937A25098B2C11AEB3FCE325C984FD6A3CEF91EB46E5DFDA9BE34877662F938A32D490D8CAFCD030927D5DFB70BB7632392D343C7EB7D403CE850B864C5C";
    RSAKeyGeneration my_key_gen = RSAKeyGeneration(keylength);

    RSAKeyGenerationResult gen_res = my_key_gen.generateRSAKeysUsingProvablePrimes(use_quintuple_form);
    const char *encrypted_message = gen_res.public_key_.encryptionPrimitive(input_message);
    const char *decrypted_message = gen_res.private_key_.decryptionPrimitive(encrypted_message);

    EXPECT_NE(strcmp(encrypted_message, input_message), 0);
    EXPECT_EQ(strcmp(decrypted_message, input_message), 0);
}

/// @brief This unit tests generating a random key with bit length 2048 and using it to encrypt and decrypt a message 
TEST(KeyGenerationTests_ProvablyPrimeProvAux, Test_nlen_2048_quint) {
    int keylength = 2048;
    int N1 = 200;
    int N2 = 200;
    bool use_quintuple_form = true;
    const char *input_message = "9BCD6D0F92B6495814E2F5701E051FD8EEEEB98C444CE784662CF27DBD8FFD22EBA7AF50E11FDD737203D6242C812899566E1954825B9F2B2F4EBD475A38DDE51E93D9422E0645D917CE19375CC2997C2CF6AFD1FC64522B95B270AAC53CFF674CF00257DB33496B310F0AEB4E6263B45C1F9465525CCE75FEB093B3CA345AB46593782421517248B4A1BB86378D99D1304FFBB664735908E166381E95CE7CF18041A8841F05A62A7D4F3CCA94A55032995EF19D404F25692D42A198491A8984477E937A25098B2C11AEB3FCE325C984FD6A3CEF91EB46E5DFDA9BE34877662F938A32D490D8CAFCD030927D5DFB70BB7632392D343C7EB7D403CE850B864C5C";
    RSAKeyGeneration my_key_gen = RSAKeyGeneration(keylength);

    RSAKeyGenerationResult gen_res = my_key_gen.generateRSAKeysUsingProvablePrimesWithAuxPrimes(N1, N2, use_quintuple_form);
    const char *encrypted_message = gen_res.public_key_.encryptionPrimitive(input_message);
    const char *decrypted_message = gen_res.private_key_.decryptionPrimitive(encrypted_message);
    
    EXPECT_NE(strcmp(encrypted_message, input_message), 0);
    EXPECT_EQ(strcmp(decrypted_message, input_message), 0);
}

/// @brief This unit tests generating a random key with bit length 3076 and using it to encrypt and decrypt a message 
TEST(KeyGenerationTests_ProvablyPrimeProvAux, Test_nlen_3076_quint) {
    int keylength = 3076;
    int N1 = 200;
    int N2 = 200;
    bool use_quintuple_form = true;
    const char *input_message = "9BCD6D0F92B6495814E2F5701E051FD8EEEEB98C444CE784662CF27DBD8FFD22EBA7AF50E11FDD737203D6242C812899566E1954825B9F2B2F4EBD475A38DDE51E93D9422E0645D917CE19375CC2997C2CF6AFD1FC64522B95B270AAC53CFF674CF00257DB33496B310F0AEB4E6263B45C1F9465525CCE75FEB093B3CA345AB46593782421517248B4A1BB86378D99D1304FFBB664735908E166381E95CE7CF18041A8841F05A62A7D4F3CCA94A55032995EF19D404F25692D42A198491A8984477E937A25098B2C11AEB3FCE325C984FD6A3CEF91EB46E5DFDA9BE34877662F938A32D490D8CAFCD030927D5DFB70BB7632392D343C7EB7D403CE850B864C5C";
    RSAKeyGeneration my_key_gen = RSAKeyGeneration(keylength);

    RSAKeyGenerationResult gen_res = my_key_gen.generateRSAKeysUsingProvablePrimesWithAuxPrimes(N1, N2, use_quintuple_form);
    const char *encrypted_message = gen_res.public_key_.encryptionPrimitive(input_message);
    const char *decrypted_message = gen_res.private_key_.decryptionPrimitive(encrypted_message);
    
    EXPECT_NE(strcmp(encrypted_message, input_message), 0);
    EXPECT_EQ(strcmp(decrypted_message, input_message), 0);
}

/// @brief This unit tests generating a random key with bit length 7680 and using it to encrypt and decrypt a message 
TEST(KeyGenerationTests_ProvablyPrimeProvAux, Test_nlen_7680_quint) {
    int keylength = 7680;
    int N1 = 200;
    int N2 = 200;
    bool use_quintuple_form = true;
    const char *input_message = "9BCD6D0F92B6495814E2F5701E051FD8EEEEB98C444CE784662CF27DBD8FFD22EBA7AF50E11FDD737203D6242C812899566E1954825B9F2B2F4EBD475A38DDE51E93D9422E0645D917CE19375CC2997C2CF6AFD1FC64522B95B270AAC53CFF674CF00257DB33496B310F0AEB4E6263B45C1F9465525CCE75FEB093B3CA345AB46593782421517248B4A1BB86378D99D1304FFBB664735908E166381E95CE7CF18041A8841F05A62A7D4F3CCA94A55032995EF19D404F25692D42A198491A8984477E937A25098B2C11AEB3FCE325C984FD6A3CEF91EB46E5DFDA9BE34877662F938A32D490D8CAFCD030927D5DFB70BB7632392D343C7EB7D403CE850B864C5C";
    RSAKeyGeneration my_key_gen = RSAKeyGeneration(keylength);

    RSAKeyGenerationResult gen_res = my_key_gen.generateRSAKeysUsingProvablePrimesWithAuxPrimes(N1, N2, use_quintuple_form);
    const char *encrypted_message = gen_res.public_key_.encryptionPrimitive(input_message);
    const char *decrypted_message = gen_res.private_key_.decryptionPrimitive(encrypted_message);
    
    EXPECT_NE(strcmp(encrypted_message, input_message), 0);
    EXPECT_EQ(strcmp(decrypted_message, input_message), 0);
}

/// @brief This unit tests generating a random key with bit length 15360 and using it to encrypt and decrypt a message 
TEST(KeyGenerationTests_ProvablyPrimeProvAux, Test_nlen_15360_quint) {
    int keylength = 15360;
    int N1 = 200;
    int N2 = 200;
    bool use_quintuple_form = true;
    const char *input_message = "9BCD6D0F92B6495814E2F5701E051FD8EEEEB98C444CE784662CF27DBD8FFD22EBA7AF50E11FDD737203D6242C812899566E1954825B9F2B2F4EBD475A38DDE51E93D9422E0645D917CE19375CC2997C2CF6AFD1FC64522B95B270AAC53CFF674CF00257DB33496B310F0AEB4E6263B45C1F9465525CCE75FEB093B3CA345AB46593782421517248B4A1BB86378D99D1304FFBB664735908E166381E95CE7CF18041A8841F05A62A7D4F3CCA94A55032995EF19D404F25692D42A198491A8984477E937A25098B2C11AEB3FCE325C984FD6A3CEF91EB46E5DFDA9BE34877662F938A32D490D8CAFCD030927D5DFB70BB7632392D343C7EB7D403CE850B864C5C";
    RSAKeyGeneration my_key_gen = RSAKeyGeneration(keylength);

    RSAKeyGenerationResult gen_res = my_key_gen.generateRSAKeysUsingProvablePrimesWithAuxPrimes(N1, N2, use_quintuple_form);
    const char *encrypted_message = gen_res.public_key_.encryptionPrimitive(input_message);
    const char *decrypted_message = gen_res.private_key_.decryptionPrimitive(encrypted_message);

    EXPECT_NE(strcmp(encrypted_message, input_message), 0);
    EXPECT_EQ(strcmp(decrypted_message, input_message), 0);
}
/// @brief This unit tests generating a random key with bit length 2048 and using it to encrypt and decrypt a message 
TEST(KeyGenerationTests_ProvablyPrimeProvAux, Test_nlen_2048_standard) {
    int keylength = 2048;
    int N1 = 200;
    int N2 = 200;
    bool use_quintuple_form = false;
    const char *input_message = "9BCD6D0F92B6495814E2F5701E051FD8EEEEB98C444CE784662CF27DBD8FFD22EBA7AF50E11FDD737203D6242C812899566E1954825B9F2B2F4EBD475A38DDE51E93D9422E0645D917CE19375CC2997C2CF6AFD1FC64522B95B270AAC53CFF674CF00257DB33496B310F0AEB4E6263B45C1F9465525CCE75FEB093B3CA345AB46593782421517248B4A1BB86378D99D1304FFBB664735908E166381E95CE7CF18041A8841F05A62A7D4F3CCA94A55032995EF19D404F25692D42A198491A8984477E937A25098B2C11AEB3FCE325C984FD6A3CEF91EB46E5DFDA9BE34877662F938A32D490D8CAFCD030927D5DFB70BB7632392D343C7EB7D403CE850B864C5C";
    RSAKeyGeneration my_key_gen = RSAKeyGeneration(keylength);

    RSAKeyGenerationResult gen_res = my_key_gen.generateRSAKeysUsingProvablePrimesWithAuxPrimes(N1, N2, use_quintuple_form);
    const char *encrypted_message = gen_res.public_key_.encryptionPrimitive(input_message);
    const char *decrypted_message = gen_res.private_key_.decryptionPrimitive(encrypted_message);
    
    EXPECT_NE(strcmp(encrypted_message, input_message), 0);
    EXPECT_EQ(strcmp(decrypted_message, input_message), 0);
}

/// @brief This unit tests generating a random key with bit length 3076 and using it to encrypt and decrypt a message 
TEST(KeyGenerationTests_ProvablyPrimeProvAux, Test_nlen_3076_standard) {
    int keylength = 3076;
    int N1 = 200;
    int N2 = 200;
    bool use_quintuple_form = false;
    const char *input_message = "9BCD6D0F92B6495814E2F5701E051FD8EEEEB98C444CE784662CF27DBD8FFD22EBA7AF50E11FDD737203D6242C812899566E1954825B9F2B2F4EBD475A38DDE51E93D9422E0645D917CE19375CC2997C2CF6AFD1FC64522B95B270AAC53CFF674CF00257DB33496B310F0AEB4E6263B45C1F9465525CCE75FEB093B3CA345AB46593782421517248B4A1BB86378D99D1304FFBB664735908E166381E95CE7CF18041A8841F05A62A7D4F3CCA94A55032995EF19D404F25692D42A198491A8984477E937A25098B2C11AEB3FCE325C984FD6A3CEF91EB46E5DFDA9BE34877662F938A32D490D8CAFCD030927D5DFB70BB7632392D343C7EB7D403CE850B864C5C";
    RSAKeyGeneration my_key_gen = RSAKeyGeneration(keylength);

    RSAKeyGenerationResult gen_res = my_key_gen.generateRSAKeysUsingProvablePrimesWithAuxPrimes(N1, N2, use_quintuple_form);
    const char *encrypted_message = gen_res.public_key_.encryptionPrimitive(input_message);
    const char *decrypted_message = gen_res.private_key_.decryptionPrimitive(encrypted_message);
    
    EXPECT_NE(strcmp(encrypted_message, input_message), 0);
    EXPECT_EQ(strcmp(decrypted_message, input_message), 0);
}

/// @brief This unit tests generating a random key with bit length 7680 and using it to encrypt and decrypt a message 
TEST(KeyGenerationTests_ProvablyPrimeProvAux, Test_nlen_7680_standard) {
    int keylength = 7680;
    int N1 = 200;
    int N2 = 200;
    bool use_quintuple_form = false;
    const char *input_message = "9BCD6D0F92B6495814E2F5701E051FD8EEEEB98C444CE784662CF27DBD8FFD22EBA7AF50E11FDD737203D6242C812899566E1954825B9F2B2F4EBD475A38DDE51E93D9422E0645D917CE19375CC2997C2CF6AFD1FC64522B95B270AAC53CFF674CF00257DB33496B310F0AEB4E6263B45C1F9465525CCE75FEB093B3CA345AB46593782421517248B4A1BB86378D99D1304FFBB664735908E166381E95CE7CF18041A8841F05A62A7D4F3CCA94A55032995EF19D404F25692D42A198491A8984477E937A25098B2C11AEB3FCE325C984FD6A3CEF91EB46E5DFDA9BE34877662F938A32D490D8CAFCD030927D5DFB70BB7632392D343C7EB7D403CE850B864C5C";
    RSAKeyGeneration my_key_gen = RSAKeyGeneration(keylength);

    RSAKeyGenerationResult gen_res = my_key_gen.generateRSAKeysUsingProvablePrimesWithAuxPrimes(N1, N2, use_quintuple_form);
    const char *encrypted_message = gen_res.public_key_.encryptionPrimitive(input_message);
    const char *decrypted_message = gen_res.private_key_.decryptionPrimitive(encrypted_message);
    
    EXPECT_NE(strcmp(encrypted_message, input_message), 0);
    EXPECT_EQ(strcmp(decrypted_message, input_message), 0);
}

/// @brief This unit tests generating a random key with bit length 15360 and using it to encrypt and decrypt a message 
TEST(KeyGenerationTests_ProvablyPrimeProvAux, Test_nlen_15360_standard) {
    int keylength = 15360;
    int N1 = 200;
    int N2 = 200;
    bool use_quintuple_form = false;
    const char *input_message = "9BCD6D0F92B6495814E2F5701E051FD8EEEEB98C444CE784662CF27DBD8FFD22EBA7AF50E11FDD737203D6242C812899566E1954825B9F2B2F4EBD475A38DDE51E93D9422E0645D917CE19375CC2997C2CF6AFD1FC64522B95B270AAC53CFF674CF00257DB33496B310F0AEB4E6263B45C1F9465525CCE75FEB093B3CA345AB46593782421517248B4A1BB86378D99D1304FFBB664735908E166381E95CE7CF18041A8841F05A62A7D4F3CCA94A55032995EF19D404F25692D42A198491A8984477E937A25098B2C11AEB3FCE325C984FD6A3CEF91EB46E5DFDA9BE34877662F938A32D490D8CAFCD030927D5DFB70BB7632392D343C7EB7D403CE850B864C5C";
    RSAKeyGeneration my_key_gen = RSAKeyGeneration(keylength);

    RSAKeyGenerationResult gen_res = my_key_gen.generateRSAKeysUsingProvablePrimesWithAuxPrimes(N1, N2, use_quintuple_form);
    const char *encrypted_message = gen_res.public_key_.encryptionPrimitive(input_message);
    const char *decrypted_message = gen_res.private_key_.decryptionPrimitive(encrypted_message);

    EXPECT_NE(strcmp(encrypted_message, input_message), 0);
    EXPECT_EQ(strcmp(decrypted_message, input_message), 0);
}