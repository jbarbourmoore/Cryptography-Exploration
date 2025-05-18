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
        gen_type = "\"Provably Prime, Aux Primes\"";
        break;
    case RSAGenerationTypes::probable_with_aux_prov:
        gen_type = "\"Probably Prime, Probable Aux Primes\"";
        break;
    case RSAGenerationTypes::probable_with_aux_prob:
        gen_type = "\"Probably Prime, Probable Aux Primes\"";
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
    } else if (key_length_ == 15360){
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
    printf("Duration Data For %s Security Strength %s With %s Private Key\n",content_strings[2].c_str(), content_strings[0].c_str(),content_strings[5].c_str());
    printf("Generation Duration : %s, Encryption Duration %s, Decryption Duration %s\n",content_strings[1].c_str(), content_strings[3].c_str(),content_strings[4].c_str());
};

RSADurationTracking::RSADurationTracking(){
    duration_guard_ = new mutex();
    vector<string> headers {"Security Strength","Key Generation Duration","Generation Method","Encryption","Decryption","Private Key Type"};
    csv_writer_ = CSVWriter(headers, "RSA_Durations_C++.csv");
    csv_writer_.writeHeaders();
};

void RSADurationTracking::trackSingleGenerationInThread(int key_length, RSAGenerationTypes gen_type, RSAPrivateKeyTypes key_type){
    RSADurationDatapoint datapoint = generateDatapoint(key_length, gen_type, key_type);
    datapoint.writeToCSV(csv_writer_);
    lock_guard<mutex> lock(*duration_guard_);
    datapoints.push_back(datapoint);
}

void RSADurationTracking::runDatapointGeneration(){
    int iteration_count = 2;
    vector<RSAGenerationTypes> generation_types = {RSAGenerationTypes::probable, RSAGenerationTypes::provable};
    vector<RSAPrivateKeyTypes> private_key_types = {RSAPrivateKeyTypes::quintuple, RSAPrivateKeyTypes::standard};
    vector<int> key_lengths = {2048, 3072};
    // vector<int> key_lengths = {2048, 3072, 7680, 15360};
    
    for (int kl = 0; kl < key_lengths.size(); kl++){
        int key_length = key_lengths[kl];
        for (int i = 0; i < iteration_count; i++){
            for (int gt = 0; gt < generation_types.size(); gt++){
                RSAGenerationTypes gen_type = generation_types[gt];
                for (int pk = 0; pk < private_key_types.size(); pk++){
                    RSAPrivateKeyTypes key_type = private_key_types[pk];
                        RSADurationDatapoint datapoint = generateDatapoint(key_length, gen_type, key_type);
                        datapoint.writeToCSV(csv_writer_);
                        datapoints.push_back(datapoint);
                }
            }
        }
    }

    printDurations();
};

void RSADurationTracking::printDurations(){
    // printf("number of datapoints : %ld\n",datapoints.size());
    for (int dp = 0; dp < datapoints.size(); dp ++){
        datapoints[dp].printToTerminal();
    }
}

RSADurationDatapoint RSADurationTracking::generateDatapoint(int keylength, RSAGenerationTypes generation_type, RSAPrivateKeyTypes private_key_type){

    const char *input_message = "9BCD6D0F92B6495814E2F5701E051FD8EEEEB98C444CE784662CF27DBD8FFD22EBA7AF50E11FDD737203D6242C812899566E1954825B9F2B2F4EBD475A38DDE51E93D9422E0645D917CE19375CC2997C2CF6AFD1FC64522B95B270AAC53CFF674CF00257DB33496B310F0AEB4E6263B45C1F9465525CCE75FEB093B3CA345AB46593782421517248B4A1BB86378D99D1304FFBB664735908E166381E95CE7CF18041A8841F05A62A7D4F3CCA94A55032995EF19D404F25692D42A198491A8984477E937A25098B2C11AEB3FCE325C984FD6A3CEF91EB46E5DFDA9BE34877662F938A32D490D8CAFCD030927D5DFB70BB7632392D343C7EB7D403CE850B864C5C";
    RSAKeyGeneration my_key_gen = RSAKeyGeneration(keylength);
    RSAKeyGenerationResult gen_res;

    bool use_key_quintuple_form = true;
    if (private_key_type == RSAPrivateKeyTypes::standard){
        use_key_quintuple_form = false;
    }

    auto start = std::chrono::high_resolution_clock::now();
    if ( generation_type == RSAGenerationTypes::provable){
        gen_res = my_key_gen.generateRSAKeysUsingProvablePrimes(use_key_quintuple_form);
    } else if ( generation_type == RSAGenerationTypes::provable_with_aux){
        gen_res = my_key_gen.generateRSAKeysUsingProvablePrimesWithAuxPrimes(200,200,use_key_quintuple_form);
    } else if ( generation_type == RSAGenerationTypes::probable){
        gen_res = my_key_gen.generateRSAKeysUsingProbablePrimes(-1,-1,use_key_quintuple_form);
    } else if ( generation_type == RSAGenerationTypes::probable_with_aux_prov){
        gen_res = my_key_gen.generateRSAKeysUsingProbablePrimesWithProvableAux(-1,-1, 200, 200, 200, 200, use_key_quintuple_form);
    } else if ( generation_type == RSAGenerationTypes::probable_with_aux_prob){
        gen_res = my_key_gen.generateRSAKeysUsingProbablePrimesWithProbableAux(-1,-1, 200, 200, 200, 200, use_key_quintuple_form);
    } else {
        throw exception();
    }

    auto stop = std::chrono::high_resolution_clock::now();

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(stop - start);
    int miliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
    float seconds = miliseconds / 1000.0;

    

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

    RSADurationDatapoint datapoint = RSADurationDatapoint(keylength, generation_type, private_key_type, seconds, encryption_seconds, decryption_seconds);
    datapoint.printToTerminal();
    if (strcmp(decrypted_message, input_message) == 0) {
        printf("The decryption was successful.\n");
    } else {
        printf("The result of the decryption is not the same as the original message.\n");
    }
    return datapoint;
}