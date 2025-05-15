/// This is my main method for RSA Key Experimentation in C++
///
/// Libaries Used : OpenSSL BIGNUM for dealing with extremely large integers
/// Author        : Jamie Barbour-Moore
/// Created       : 05/11/25
/// Updated       : 05/14/25

#include <openssl/bn.h>
#include <string.h>
#include "RSAPublicKey.hpp"
#include "RSAPrivateKey.hpp"
#include "RSAKeyGeneration.hpp"
#include "BigNumHelpers.hpp"
#include "RSADurationTracking.hpp"

void runDatapointGenerationMultiThreaded(){

    RSADurationTracking duration_tracking = RSADurationTracking();
    int iteration_count = 2;
    vector<RSAGenerationTypes> generation_types = {RSAGenerationTypes::provable};
    vector<RSAPrivateKeyTypes> private_key_types = {RSAPrivateKeyTypes::quintuple, RSAPrivateKeyTypes::standard};
    //vector<int> key_lengths = {2048, 3072, 7680};
    vector<int> key_lengths = {2048, 3072, 7680, 15360};
    
    for (int kl = 0; kl < key_lengths.size(); kl++){
        int key_length = key_lengths[kl];
        for (int i = 0; i < iteration_count; i++){
            // thread prov_quint (&RSADurationTracking::trackSingleGenerationInThread, duration_tracking, key_length, RSAGenerationTypes::provable,RSAPrivateKeyTypes::quintuple);
            // thread prov_stand (&RSADurationTracking::trackSingleGenerationInThread, duration_tracking, key_length, RSAGenerationTypes::provable,RSAPrivateKeyTypes::standard);
            // thread prov_with_aux_quint (&RSADurationTracking::trackSingleGenerationInThread, duration_tracking, key_length, RSAGenerationTypes::provable_with_aux,RSAPrivateKeyTypes::quintuple);
            // thread prov_with_aux_stand (&RSADurationTracking::trackSingleGenerationInThread, duration_tracking, key_length, RSAGenerationTypes::provable_with_aux,RSAPrivateKeyTypes::standard);
            thread prob_quint (&RSADurationTracking::trackSingleGenerationInThread, duration_tracking, key_length, RSAGenerationTypes::probable,RSAPrivateKeyTypes::quintuple);
            thread prob_stand (&RSADurationTracking::trackSingleGenerationInThread, duration_tracking, key_length, RSAGenerationTypes::probable,RSAPrivateKeyTypes::standard);

            // prov_stand.join();
            // prov_quint.join();
            // prov_with_aux_quint.join();
            // prov_with_aux_stand.join();
            prob_quint.join();
            prob_stand.join();
        }
    }

    duration_tracking.printDurations();
};


int main(int argc, char const *argv[])
{
    RSADurationTracking duration_tracking = RSADurationTracking();
    duration_tracking.runDatapointGeneration();
    // runDatapointGenerationMultiThreaded();

    // RSAKeyGeneration my_key_gen = RSAKeyGeneration(2048);
    // my_key_gen.generateRSAKeysUsingProbablePrimes();

    // RSADurationTracking duration_tracking = RSADurationTracking();
    // duration_tracking.runDatapointGeneration();
    
    // const char *input_n = "B29AA1C9D079B6E77E3307E88C8937B5D211D0F7AC79098C3969F1C2A9F8C17A7CFFD15AC76367F694B00D9C673BB142613C44E0778136582B75C9CAE81B03C2C26F029958019620046A840A9DD40A6C5B9313318294AA42C20BBCCD106141FDFA725AD62AD1CF41A8CF12E894A45C602227A765F7159BCC86E3CC8A08EC8B5AA71C81FBF7F84745767DBDA99AED567D5F06A9B30BD0ED5166C61BFCCF49BB340D4DC74359FC965FAD81798CF95987624D7EE361128B69EB594358DDF59298C6DA286BD885F74A62924BAB899AE6A1A25E695FB2B7C194EB35815646CC2D277ED9DDC9463621A43C21A8AA70FD29DEF7163BAAA71C7F1E694D610EFBE3C76EFF";
    // const char *input_e = "3262454CF1B221";
    // const char *input_message = "9BCD6D0F92B6495814E2F5701E051FD8EEEEB98C444CE784662CF27DBD8FFD22EBA7AF50E11FDD737203D6242C812899566E1954825B9F2B2F4EBD475A38DDE51E93D9422E0645D917CE19375CC2997C2CF6AFD1FC64522B95B270AAC53CFF674CF00257DB33496B310F0AEB4E6263B45C1F9465525CCE75FEB093B3CA345AB46593782421517248B4A1BB86378D99D1304FFBB664735908E166381E95CE7CF18041A8841F05A62A7D4F3CCA94A55032995EF19D404F25692D42A198491A8984477E937A25098B2C11AEB3FCE325C984FD6A3CEF91EB46E5DFDA9BE34877662F938A32D490D8CAFCD030927D5DFB70BB7632392D343C7EB7D403CE850B864C5C";
    // const char *input_d = "0B457CB93653C2E2FB1C70F90FC419A2C5E89145300A46342FD89BDD39251806072C5F350A070BDCDE5403FA4737872D6D8BD10F7BAFAB453ED1F20745326D8E4B2E2359A1120B6A419D7F0DDE0469E68665C28C16DFEFEDD11241381BE3E551C9D342263EC9309CCF96CEE9621CEC1FF8746133BA30FD5C20D2BCEF074BEB0F3019CEDACF52987439ADF7959CBE603BD911DCA19389B0B6212424959B57B4460B37011E18C37C9E805F78555D20BF5FCF6752A4BA3FB8A60EEF28EF59FD4DDA92189BEDD1C2200497D415804D133B8CC3CE60C3EACDAD0C33FB433C4157E6273929A67C27E23018808C008A8EDCD30448353D666A9CDBC7DD0BA19B40B11B19";
    // const char *input_cypher = "3A55937F5F38A81F561433D9F3B584D36013DA19FBE23630036F15CBADEB79C8FAD45E9BE8990D7BEE1238BA3128CEBBD706EA9ACF8ED498F17C196CB496318ECE6402C2715CD94AADAAA7D07A27AC1DDBC961DF79482DFC96CFF8C2E4BA2695E2B2E1DD46AA8539E664E2FD8A6B67E93EFE27DA2B1441B042486CF696C0AF90A7313CE110EA1B03A48DF4BBF8704403C58F82944BCDC61E94F2C862AD29C7DA20DB6DCF6E2D78C19272A8F233D6A30BAA1A1F5E9BCF6B1500AA0E89ACAE754C8027929C7BEF1DE5ED1D63B6E3C7C9A37C741023764802B277E9BE8C1266DFF6298BBAFC7A2080BA3D95A69D81E2FEBF3721F08BA49ED83B240CBCFBAA5A7B96";
    // const char *input_p = "E4EC37CD7FF974EFE979BEABA30E2902CF1990056D9895F89F07BB3E7956A7BD279A47F843D3402FAFBECAFA381EFD02D6B8D287DD76CE2CE57AA1BF2924AEB473F7C9A11100BBA2A06D7B3CC47B7240C6E562280B1BB5F13B59F8FE75E09D2BFA8F75AB5EC4E739E0DEA292670985DE7916A0C74FA943E9A32865F93A9B8043";
    // const char *input_q = "C7BAC374F74D4247A6BD3B8ED29AA9DCFCFFBB066667AB8AEB92DA65F105720A86F9C678E53CEB4656D2192F6600521D2ED16A9A9FA0188D32A8B1E393981AC0ECA18F25B8D8AD679A5BA67EF5DD339C766EFE0BC55FAB161E7E5092A486A1FC510E0D9A9DC88C2DDC30F94BB6360B823B566935956BCEFA3B2DED44058A9895";

    // RSAPublicKey my_public_key {};
    // my_public_key.fromHexCharArray(input_n,input_e);
    // my_public_key.printKey();
    // const char *output_n = my_public_key.getHexN();
    // const char *output_e = my_public_key.getHexE();

    // printf("Testing n and e getters\nn: %s\n", output_n);
    // printf("e: %s\n", output_e);
    // printf("Keylength is %i\n", my_public_key.getKeyLength());

    // printf("Inputted Message : %s\n", input_message);
    // const char *encrypted = my_public_key.encryptionPrimitive(input_message);
    // printf("Encrypted Message : %s\n",encrypted);


    // RSAPrivateKey my_private_key {};
    // my_private_key.fromHexCharArray(input_n,input_d);
    // const char *decrypted = my_private_key.decryptionPrimitive(encrypted);
    // printf("Decrypted Message : %s\n",decrypted);
   
    // my_private_key.printKey();

    // RSAPrivateKey my_quint_private_key {};
    // my_quint_private_key.fromHexCharArray_QuintForm(input_n,input_d,input_p,input_q);
    // my_quint_private_key.printKey();

    // const char *decrypted_quint = my_quint_private_key.decryptionPrimitive(encrypted);
    // printf("Decypted Quint %s\n",decrypted_quint);

    // if (strcmp(encrypted, input_cypher) == 0) {
    //     printf("The message was successfully encrypted\n");
    // } else {
    //     printf("The result of the encryption does not match the expected value\n");
    // }

    // if (strcmp(decrypted, input_message) == 0) {
    //     printf("The decryption was successful.\n");
    // } else {
    //     printf("The result of the decryption is not the same as the original message.\n");
    // }

    // if (strcmp(decrypted_quint, input_message) == 0) {
    //     printf("The decryption was successful in quint form.\n");
    // } else {
    //     printf("The result of the decryption in quint form is not the same as the original message.\n");
    // }

    // my_public_key.freeKey();
    // my_quint_private_key.freeKey();
    // my_private_key.freeKey();

    // RSAKeyGeneration my_key_gen = RSAKeyGeneration(2048);

    // int security_strength = my_key_gen.getSecurityStrength();
    // int prime_length = my_key_gen.getPrimeLength();

    // printf("My RSA Key Generation Security Strength Is %d\n",security_strength);
    // printf("My RSA Prime Length Is %d\n",prime_length);

    // my_key_gen.generateRSAKeysUsingProvablePrimes();

    // BIGNUM *first_num = BN_new();
    // BIGNUM *second_num = BN_new();
    // BN_hex2bn(&first_num, "FFF");
    // BN_hex2bn(&second_num, "11");
    // BIGNUM *xor_result = BigNumHelpers::xorBigNums(first_num, second_num);
    return 0;
}