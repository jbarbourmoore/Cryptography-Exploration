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

/// @brief This enum track the different types of RSA prime generation as laid out in NIST 186-5
enum class RSAGenerationTypes{
    provable, probable, provable_with_aux, probable_with_aux_prov, probable_with_auth_prob
};

/// @brief This enum tracks the private key types
enum class RSAPrivateKeyTypes{
    standard, quintuple
};

/// @brief This class keeps track of the data for a single RSADurationDatapoint
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
        RSADurationDatapoint(int key_length = 2048, RSAGenerationTypes generation_type=RSAGenerationTypes::provable, RSAPrivateKeyTypes private_key_type=RSAPrivateKeyTypes::quintuple, float key_generation_duration=0, float encryption_duration=0, float decryption_duration=0);

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

/// @brief This class run the duration tracking and outputs to CSV
class RSADurationTracking{

    private :

        /// @brief the CSVWriter that the rsa duration tracking shall be using for outputs
        CSVWriter csv_writer_ ;

         /// @brief A mutex to prevent multiple threads from accessing the durations simultaneously
        mutex * duration_guard_ ;

        /// @brief the currently generated datapoints as a vector
        vector<RSADurationDatapoint> datapoints {};

    public :
        /// @brief this instantializes the RSADurationTracking object 
        RSADurationTracking();

        /// @brief This method generates the RSA Keys, and tracks duration data
        /// @param keylength The length of the RSA Key to be generated in bits ('nlen')
        /// @param generation_type How the RSA key primes are to be generated
        /// @param private_key_type Which private key form is being used
        /// @return The datapoint including all the necessary data for the spread sheet
        RSADurationDatapoint generateDatapoint(int keylength = 2048, RSAGenerationTypes generation_type = RSAGenerationTypes::provable, RSAPrivateKeyTypes private_key_type = RSAPrivateKeyTypes::quintuple);

        /// @brief This method runs the datapoint generation for multiple looped types and such to fill in the csv
        void runDatapointGeneration();

        void printDurations();

        void trackSingleGenerationInThread(int key_length, RSAGenerationTypes gen_type, RSAPrivateKeyTypes key_type);

};

#endif