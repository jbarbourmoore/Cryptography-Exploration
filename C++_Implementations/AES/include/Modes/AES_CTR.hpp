#ifndef AES_CTR_HPP
#define AES_CTR_HPP

#include "AES.hpp"

/// @brief This class contains the functions for AES in Counter Mode as defined in NIST SP 800 -38a 
/// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
class AES_CTR{
    public :
        
        /// @brief This method performs the AES cypher in CTR Mode from NIST SP 800 - 38a Section 6.5 "The Counter Mode"
        /// @param input The blocks of input to the cypher
        /// @param expanded_key The key for the AES cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES128Cypher(std::string input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector);
        
        /// @brief This method performs the AES cypher in CTR Mode from NIST SP 800 - 38a Section 6.5 "The Counter Mode"
        /// @param input The blocks of input to the cypher
        /// @param key The key for the AES cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES128Cypher(std::string input, std::string key, AESDataBlock initialization_vector);
        
        /// @brief This method performs the AES cypher in CTR Mode from NIST SP 800 - 38a Section 6.5 "The Counter Mode"
        /// @param input The blocks of input to the cypher
        /// @param key The key for the AES cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES128Cypher(std::string input, unsigned char *key, AESDataBlock initialization_vector);
        
        /// @brief This method performs the AES inverse cypher in CTR Mode from NIST SP 800 - 38a Section 6.5 "The Counter Mode"
        /// @param input The blocks of input to the inverse cypher
        /// @param expanded_key The key for the AES inverse cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @return The decrypted blocks of data from the input
        static std::vector<AESDataBlock> AES128InvCypher(std::string input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector);
        
        /// @brief This method performs the AES inverse cypher in CTR Mode from NIST SP 800 - 38a Section 6.5 "The Counter Mode"
        /// @param input The blocks of input to the inverse cypher
        /// @param key The key for the AES inverse cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @return The decrypted blocks of data from the input
        static std::vector<AESDataBlock> AES128InvCypher(std::string input, std::string key, AESDataBlock initialization_vector);
        
        /// @brief This method performs the AES inverse cypher in CTR Mode from NIST SP 800 - 38a Section 6.5 "The Counter Mode"
        /// @param input The blocks of input to the inverse cypher
        /// @param key The key for the AES inverse cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @return The decrypted blocks of data from the input
        static std::vector<AESDataBlock> AES128InvCypher(std::string input, unsigned char *key, AESDataBlock initialization_vector);
        
        /// @brief This method performs the AES cypher in CTR Mode from NIST SP 800 - 38a Section 6.5 "The Counter Mode"
        /// @param input The blocks of input to the cypher
        /// @param expanded_key The key for the AES cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES128Cypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector);
        
        /// @brief This method performs the AES cypher in CTR Mode from NIST SP 800 - 38a Section 6.5 "The Counter Mode"
        /// @param input The blocks of input to the cypher
        /// @param key The key for the AES cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES128Cypher(std::vector<AESDataBlock> input, std::string key, AESDataBlock initialization_vector);
        
        /// @brief This method performs the AES cypher in CTR Mode from NIST SP 800 - 38a Section 6.5 "The Counter Mode"
        /// @param input The blocks of input to the cypher
        /// @param key The key for the AES cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES128Cypher(std::vector<AESDataBlock> input, unsigned char *key, AESDataBlock initialization_vector);
        
        /// @brief This method performs the AES inverse cypher in CTR Mode from NIST SP 800 - 38a Section 6.5 "The Counter Mode"
        /// @param input The blocks of input to the inverse cypher
        /// @param expanded_key The key for the AES inverse cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @return The decrypted blocks of data from the input
        static std::vector<AESDataBlock> AES128InvCypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector);
        
        /// @brief This method performs the AES inverse cypher in CTR Mode from NIST SP 800 - 38a Section 6.5 "The Counter Mode"
        /// @param input The blocks of input to the inverse cypher
        /// @param key The key for the AES inverse cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @return The decrypted blocks of data from the input
        static std::vector<AESDataBlock> AES128InvCypher(std::vector<AESDataBlock> input, std::string key, AESDataBlock initialization_vector);
        
        /// @brief This method performs the AES inverse cypher in CTR Mode from NIST SP 800 - 38a Section 6.5 "The Counter Mode"
        /// @param input The blocks of input to the inverse cypher
        /// @param key The key for the AES inverse cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @return The decrypted blocks of data from the input
        static std::vector<AESDataBlock> AES128InvCypher(std::vector<AESDataBlock> input, unsigned char *key, AESDataBlock initialization_vector);

        
        
        
        
        /// @brief This method performs the AES cypher in CTR Mode from NIST SP 800 - 38a Section 6.5 "The Counter Mode"
        /// @param input The blocks of input to the cypher
        /// @param expanded_key The key for the AES cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES192Cypher(std::string input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector);
        
        /// @brief This method performs the AES cypher in CTR Mode from NIST SP 800 - 38a Section 6.5 "The Counter Mode"
        /// @param input The blocks of input to the cypher
        /// @param key The key for the AES cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES192Cypher(std::string input, std::string key, AESDataBlock initialization_vector);
        
        /// @brief This method performs the AES cypher in CTR Mode from NIST SP 800 - 38a Section 6.5 "The Counter Mode"
        /// @param input The blocks of input to the cypher
        /// @param key The key for the AES cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES192Cypher(std::string input, unsigned char *key, AESDataBlock initialization_vector);
        
        /// @brief This method performs the AES inverse cypher in CTR Mode from NIST SP 800 - 38a Section 6.5 "The Counter Mode"
        /// @param input The blocks of input to the inverse cypher
        /// @param expanded_key The key for the AES inverse cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @return The decrypted blocks of data from the input
        static std::vector<AESDataBlock> AES192InvCypher(std::string input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector);
        
        /// @brief This method performs the AES inverse cypher in CTR Mode from NIST SP 800 - 38a Section 6.5 "The Counter Mode"
        /// @param input The blocks of input to the inverse cypher
        /// @param key The key for the AES inverse cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @return The decrypted blocks of data from the input
        static std::vector<AESDataBlock> AES192InvCypher(std::string input, std::string key, AESDataBlock initialization_vector);
        
        /// @brief This method performs the AES inverse cypher in CTR Mode from NIST SP 800 - 38a Section 6.5 "The Counter Mode"
        /// @param input The blocks of input to the inverse cypher
        /// @param key The key for the AES inverse cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @return The decrypted blocks of data from the input
        static std::vector<AESDataBlock> AES192InvCypher(std::string input, unsigned char *key, AESDataBlock initialization_vector);
        
        /// @brief This method performs the AES cypher in CTR Mode from NIST SP 800 - 38a Section 6.5 "The Counter Mode"
        /// @param input The blocks of input to the cypher
        /// @param expanded_key The key for the AES cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES192Cypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector);
        
        /// @brief This method performs the AES cypher in CTR Mode from NIST SP 800 - 38a Section 6.5 "The Counter Mode"
        /// @param input The blocks of input to the cypher
        /// @param key The key for the AES cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES192Cypher(std::vector<AESDataBlock> input, std::string key, AESDataBlock initialization_vector);
        
        /// @brief This method performs the AES cypher in CTR Mode from NIST SP 800 - 38a Section 6.5 "The Counter Mode"
        /// @param input The blocks of input to the cypher
        /// @param key The key for the AES cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES192Cypher(std::vector<AESDataBlock> input, unsigned char *key, AESDataBlock initialization_vector);
        
        /// @brief This method performs the AES inverse cypher in CTR Mode from NIST SP 800 - 38a Section 6.5 "The Counter Mode"
        /// @param input The blocks of input to the inverse cypher
        /// @param expanded_key The key for the AES inverse cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @return The decrypted blocks of data from the input
        static std::vector<AESDataBlock> AES192InvCypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector);
        
        /// @brief This method performs the AES inverse cypher in CTR Mode from NIST SP 800 - 38a Section 6.5 "The Counter Mode"
        /// @param input The blocks of input to the inverse cypher
        /// @param key The key for the AES inverse cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @return The decrypted blocks of data from the input
        static std::vector<AESDataBlock> AES192InvCypher(std::vector<AESDataBlock> input, std::string key, AESDataBlock initialization_vector);
        
        /// @brief This method performs the AES inverse cypher in CTR Mode from NIST SP 800 - 38a Section 6.5 "The Counter Mode"
        /// @param input The blocks of input to the inverse cypher
        /// @param key The key for the AES inverse cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @return The decrypted blocks of data from the input
        static std::vector<AESDataBlock> AES192InvCypher(std::vector<AESDataBlock> input, unsigned char *key, AESDataBlock initialization_vector);



        
        
        /// @brief This method performs the AES cypher in CTR Mode from NIST SP 800 - 38a Section 6.5 "The Counter Mode"
        /// @param input The blocks of input to the cypher
        /// @param expanded_key The key for the AES cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES256Cypher(std::string input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector);
        
        /// @brief This method performs the AES cypher in CTR Mode from NIST SP 800 - 38a Section 6.5 "The Counter Mode"
        /// @param input The blocks of input to the cypher
        /// @param key The key for the AES cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES256Cypher(std::string input, std::string key, AESDataBlock initialization_vector);
        
        /// @brief This method performs the AES cypher in CTR Mode from NIST SP 800 - 38a Section 6.5 "The Counter Mode"
        /// @param input The blocks of input to the cypher
        /// @param key The key for the AES cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES256Cypher(std::string input, unsigned char *key, AESDataBlock initialization_vector);
        
        /// @brief This method performs the AES inverse cypher in CTR Mode from NIST SP 800 - 38a Section 6.5 "The Counter Mode"
        /// @param input The blocks of input to the inverse cypher
        /// @param expanded_key The key for the AES inverse cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @return The decrypted blocks of data from the input
        static std::vector<AESDataBlock> AES256InvCypher(std::string input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector);
        
        /// @brief This method performs the AES inverse cypher in CTR Mode from NIST SP 800 - 38a Section 6.5 "The Counter Mode"
        /// @param input The blocks of input to the inverse cypher
        /// @param key The key for the AES inverse cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @return The decrypted blocks of data from the input
        static std::vector<AESDataBlock> AES256InvCypher(std::string input, std::string key, AESDataBlock initialization_vector);
        
        /// @brief This method performs the AES inverse cypher in CTR Mode from NIST SP 800 - 38a Section 6.5 "The Counter Mode"
        /// @param input The blocks of input to the inverse cypher
        /// @param key The key for the AES inverse cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @return The decrypted blocks of data from the input
        static std::vector<AESDataBlock> AES256InvCypher(std::string input, unsigned char *key, AESDataBlock initialization_vector);
        
        /// @brief This method performs the AES cypher in CTR Mode from NIST SP 800 - 38a Section 6.5 "The Counter Mode"
        /// @param input The blocks of input to the cypher
        /// @param expanded_key The key for the AES cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES256Cypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector);
        
        /// @brief This method performs the AES cypher in CTR Mode from NIST SP 800 - 38a Section 6.5 "The Counter Mode"
        /// @param input The blocks of input to the cypher
        /// @param key The key for the AES cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES256Cypher(std::vector<AESDataBlock> input, std::string key, AESDataBlock initialization_vector);
        
        /// @brief This method performs the AES cypher in CTR Mode from NIST SP 800 - 38a Section 6.5 "The Counter Mode"
        /// @param input The blocks of input to the cypher
        /// @param key The key for the AES cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES256Cypher(std::vector<AESDataBlock> input, unsigned char *key, AESDataBlock initialization_vector);
        
        /// @brief This method performs the AES inverse cypher in CTR Mode from NIST SP 800 - 38a Section 6.5 "The Counter Mode"
        /// @param input The blocks of input to the inverse cypher
        /// @param expanded_key The key for the AES inverse cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @return The decrypted blocks of data from the input
        static std::vector<AESDataBlock> AES256InvCypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector);
        
        /// @brief This method performs the AES inverse cypher in CTR Mode from NIST SP 800 - 38a Section 6.5 "The Counter Mode"
        /// @param input The blocks of input to the inverse cypher
        /// @param key The key for the AES inverse cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @return The decrypted blocks of data from the input
        static std::vector<AESDataBlock> AES256InvCypher(std::vector<AESDataBlock> input, std::string key, AESDataBlock initialization_vector);
        
        /// @brief This method performs the AES inverse cypher in CTR Mode from NIST SP 800 - 38a Section 6.5 "The Counter Mode"
        /// @param input The blocks of input to the inverse cypher
        /// @param key The key for the AES inverse cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @return The decrypted blocks of data from the input
        static std::vector<AESDataBlock> AES256InvCypher(std::vector<AESDataBlock> input, unsigned char *key, AESDataBlock initialization_vector);    
};

#endif