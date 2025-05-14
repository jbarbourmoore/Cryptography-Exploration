/// This file contains the functions to allow tracking the durations for RSA Key generation and logging it to csv
///
/// Libaries Used : OpenSSL BIGNUM for dealing with extremely large integers
/// Author        : Jamie Barbour-Moore
/// Created       : 05/13/25
/// Updated       : 05/14/25

#include "RSADurationTracking.hpp"

RSADurationDatapoint::RSADurationDatapoint(int key_length, RSAGenerationTypes generation_type, RSAPrivateKeyTypes private_key_type, float key_generation_duration, float encryption_duration, float decryption_duration){
    key_length_ = key_length;
    generation_type_ = generation_type;
    private_key_type_ = private_key_type;
    key_generation_duration_ = key_generation_duration;
    encryption_duration_ = encryption_duration;
    decryption_duration_ = decryption_duration;
};

void RSADurationDatapoint::writeToCSV(CSVWriter csv_writer){
    vector<string> data_vector = getContents();
    csv_writer.writeContent(data_vector);
};

string RSADurationDatapoint::getPrivateKeyTypeString(){
    string key_type;
    switch (private_key_type_)
    {
    case RSAPrivateKeyTypes::standard:
        key_type = "Standard";
        break;
    case RSAPrivateKeyTypes::quintuple:
        key_type = "Quintuple";
        break;
    default:
        key_type = "Unknown";
        break;
    }
    return key_type;
};

string RSADurationDatapoint::getGenerationTypeString(){
    string gen_type;
    switch (generation_type_)
    {
    case RSAGenerationTypes::provable:
        gen_type = "Provably Prime";
        break;
    case RSAGenerationTypes::probable:
        gen_type = "Probably Prime";
        break;
    case RSAGenerationTypes::provable_with_aux:
        gen_type = "Provably Prime, Aux Primes";
        break;
    case RSAGenerationTypes::probable_with_aux_prov:
        gen_type = "Probably Prime, Probable Aux Primes";
        break;
    case RSAGenerationTypes::probable_with_auth_prob:
        gen_type = "Probably Prime, Probable Aux Primes";
        break;
    
    default:
        gen_type = "Unknown";
        break;
    }
    return gen_type;
};

vector<string> RSADurationDatapoint::getHeaders(){
    vector<string> headers {"Security Strength","Key Generation Duration","Generation Method","Encryption","Decryption","Private Key Type"};
    return headers;
};

vector<string> RSADurationDatapoint::getContents(){
    int security_strength = 112;
    if (key_length_ == 3072){
        security_strength = 128;
    } else if (key_length_ == 7680){
        security_strength = 192;
    } else if (key_length_ == 10360){
        security_strength = 256;
    } 
    string security_strength_string = to_string(security_strength);
    string gen_dur_string = to_string(key_generation_duration_);
    string en_dur_string = to_string(encryption_duration_);
    string de_dur_string = to_string(decryption_duration_);
    string gen_type_string = getGenerationTypeString();
    string key_type_string = getPrivateKeyTypeString();

    vector<string> data_vector = {security_strength_string,gen_dur_string,gen_type_string,en_dur_string,de_dur_string,key_type_string};
    return data_vector;
};

void RSADurationDatapoint::printToTerminal(){
    vector<string> content_strings = getContents();
    printf("Duration Data For %s Security Strength %s With %s Private Key\n",content_strings[2], content_strings[0],content_strings[5]);
    printf("Generation Duration : %s, Encryption Duration %s, Decryption Duration %s\n",content_strings[1], content_strings[3],content_strings[4]);
};

RSADurationDatapoint generateProvableKeys(int keylength = 2048){
    const char *input_message = "9BCD6D0F92B6495814E2F5701E051FD8EEEEB98C444CE784662CF27DBD8FFD22EBA7AF50E11FDD737203D6242C812899566E1954825B9F2B2F4EBD475A38DDE51E93D9422E0645D917CE19375CC2997C2CF6AFD1FC64522B95B270AAC53CFF674CF00257DB33496B310F0AEB4E6263B45C1F9465525CCE75FEB093B3CA345AB46593782421517248B4A1BB86378D99D1304FFBB664735908E166381E95CE7CF18041A8841F05A62A7D4F3CCA94A55032995EF19D404F25692D42A198491A8984477E937A25098B2C11AEB3FCE325C984FD6A3CEF91EB46E5DFDA9BE34877662F938A32D490D8CAFCD030927D5DFB70BB7632392D343C7EB7D403CE850B864C5C";
    RSAKeyGeneration my_key_gen = RSAKeyGeneration(keylength);

    auto start = std::chrono::high_resolution_clock::now();
    RSAKeyGenerationResult gen_res = my_key_gen.generateRSAKeysUsingProvablePrimes();
    auto stop = std::chrono::high_resolution_clock::now();

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(stop - start);
    int miliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
    float seconds = miliseconds / 1000.0;

    printf("duration : %f seconds\n", seconds);

    start = std::chrono::high_resolution_clock::now();
    const char *encrypted_message = gen_res.public_key_.encryptionPrimitive(input_message);
    stop = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::milliseconds>(stop - start);
    miliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();

    float encryption_seconds = miliseconds / 1000.0;

    start = std::chrono::high_resolution_clock::now();
    const char *decrypted_message = gen_res.private_key_.decryptionPrimitive(encrypted_message);
    stop = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::milliseconds>(stop - start);
    miliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();

    float decryption_seconds = miliseconds / 1000.0;

    if (strcmp(decrypted_message, input_message) == 0) {
        printf("The decryption was successful.\n");
    } else {
        printf("The result of the decryption is not the same as the original message.\n");
    }

    RSADurationDatapoint datapoint = RSADurationDatapoint(keylength, RSAGenerationTypes::provable,RSAPrivateKeyTypes::quintuple, seconds, encryption_seconds, decryption_seconds);
    return datapoint;
}