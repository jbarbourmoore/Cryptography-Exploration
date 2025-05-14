#ifndef RSADurationTracking_HPP
#define RSADurationTracking_HPP

#include <string.h>
#include <vector>
#include <chrono>

#include "RSAPublicKey.hpp"
#include "RSAPrivateKey.hpp"
#include "RSAKeyGeneration.hpp"
#include "IOHelpers.hpp"

using namespace std;

enum class RSAGenerationTypes{
    provable, probable, provable_with_aux, probable_with_aux_prov, probable_with_auth_prob
};

enum class RSAPrivateKeyTypes{
    standard, quintuple
};

class RSADurationDatapoint{

    private :

        /// @brief The length of the key in bits (nlen)
        int key_length_ {2048};

        /// @brief The type of the prime generation used
        RSAGenerationTypes generation_type_ {};

        /// @brief The form of the private key
        RSAPrivateKeyTypes private_key_type_ {};

        /// @brief How long it took to generate a key in seconds
        float key_generation_duration_ {0};

        /// @brief How long it took to encrypt the data in seconds
        float encryption_duration_ {0};

        /// @brief How long it took to decrypt the data in seconds
        float decryption_duration_{0};

    public :

        /// @brief Instantiates a RSADurationDatapoint
        /// @param key_length The length of the RSA key in bits
        /// @param generation_type The type of prime generation that was used for this datapoint
        /// @param private_key_type The form of private key that was used for this datapoint
        /// @param key_generation_duration The duration it took to generate the key in seconds
        /// @param encryption_duration The duration it took to encrypt the data in seconds
        /// @param decryption_duration The duration it took to decrypt the data in seconds 
        RSADurationDatapoint(int key_length = 2048, RSAGenerationTypes generation_type, RSAPrivateKeyTypes private_key_type, float key_generation_duration, float encryption_duration, float decryption_duration);

        /// @brief The method gets the generation method as a string
        /// @return The string of the generation method for primes 'p' and 'q'
        string getGenerationTypeString();

        /// @brief The method gets the private key form as a string
        /// @return The string of the private key form
        string getPrivateKeyTypeString();

        /// @brief This method writes the data point to the CSV
        void writeToCSV(CSVWriter csv_writer);

        /// @brief This method prints the data point to the terminal
        void printToTerminal();

        /// @brief This method gets the headers for the data point as a vector of strings
        /// @return The headers for the datapoint
        vector<string> getHeaders();

        /// @brief This method gets the contents for the data point as a vector of strings
        /// @return The contents for the datapoint
        vector<string> getContents();

};

class RSADurationTracking{

    private :
        CSVWriter csv_writer_ ;

        vector<RSADurationDatapoint> datapoints {};

    public :
        RSADurationTracking();

        RSADurationDatapoint generateDatapoint(int keylength = 2048, RSAGenerationTypes generation_type = RSAGenerationTypes::provable, RSAPrivateKeyTypes private_key_type = RSAPrivateKeyTypes::quintuple);
};

#endif