#ifndef AES_CFB_HPP
#define AES_CFB_HPP

#include "AES.hpp"

#include <vector>
#include <cstdio>

/// @brief This class contains the functions for AES in Cypher Feedback Mode as defined in NIST SP 800 -38a 
/// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
class AES_CFB{
    public :
        static const int block_size = 128;

        /// @brief This method performs the AES cypher in CFB Mode from NIST SP 800 - 38a Section 6.3 "The Cipher Feedback Mode" 
        /// @param input The blocks of input to the cypher
        /// @param expanded_key The key for the AES cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES128Cypher(std::string input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector, int s_bits);
        
        /// @brief This method performs the AES cypher in CFB Mode from NIST SP 800 - 38a Section 6.3 "The Cipher Feedback Mode" 
        /// @param input The blocks of input to the cypher
        /// @param key The key for the AES cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @param s_bits The number of bits to be encrypted each round
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES128Cypher(std::string input, std::string key, AESDataBlock initialization_vector, int s_bits);
        
        /// @brief This method performs the AES cypher in CFB Mode from NIST SP 800 - 38a Section 6.3 "The Cipher Feedback Mode" 
        /// @param input The blocks of input to the cypher
        /// @param key The key for the AES cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @param s_bits The number of bits to be encrypted each round
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES128Cypher(std::string input, unsigned char *key, AESDataBlock initialization_vector, int s_bits);
        
        /// @brief This method performs the AES inverse cypher in CFB Mode from NIST SP 800 - 38a Section 6.3 "The Cipher Feedback Mode" 
        /// @param input The blocks of input to the inverse cypher
        /// @param expanded_key The key for the AES inverse cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @param s_bits The number of bits to be encrypted each round
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES128InvCypher(std::string input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector, int s_bits);
        
        /// @brief This method performs the AES inverse cypher in CFB Mode from NIST SP 800 - 38a Section 6.3 "The Cipher Feedback Mode" 
        /// @param input The blocks of input to the inverse cypher
        /// @param key The key for the AES inverse cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @param s_bits The number of bits to be encrypted each round
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES128InvCypher(std::string input, std::string key, AESDataBlock initialization_vector, int s_bits);
        
        /// @brief This method performs the AES inverse cypher in CFB Mode from NIST SP 800 - 38a Section 6.3 "The Cipher Feedback Mode" 
        /// @param input The blocks of input to the inverse cypher
        /// @param key The key for the AES inverse cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @param s_bits The number of bits to be encrypted each round
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES128InvCypher(std::string input, unsigned char *key, AESDataBlock initialization_vector, int s_bits);
        
        /// @brief This method performs the AES cypher in CFB Mode from NIST SP 800 - 38a Section 6.3 "The Cipher Feedback Mode" 
        /// @param input The blocks of input to the cypher
        /// @param expanded_key The key for the AES cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @param s_bits The number of bits to be encrypted each round
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES128Cypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector, int s_bits);
        
        /// @brief This method performs the AES cypher in CFB Mode from NIST SP 800 - 38a Section 6.3 "The Cipher Feedback Mode" 
        /// @param input The blocks of input to the cypher
        /// @param key The key for the AES cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @param s_bits The number of bits to be encrypted each round
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES128Cypher(std::vector<AESDataBlock> input, std::string key, AESDataBlock initialization_vector, int s_bits);
        
        /// @brief This method performs the AES cypher in CFB Mode from NIST SP 800 - 38a Section 6.3 "The Cipher Feedback Mode" 
        /// @param input The blocks of input to the cypher
        /// @param key The key for the AES cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @param s_bits The number of bits to be encrypted each round
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES128Cypher(std::vector<AESDataBlock> input, unsigned char *key, AESDataBlock initialization_vector, int s_bits);
        
        /// @brief This method performs the AES inverse cypher in CFB Mode from NIST SP 800 - 38a Section 6.3 "The Cipher Feedback Mode" 
        /// @param input The blocks of input to the inverse cypher
        /// @param expanded_key The key for the AES inverse cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @param s_bits The number of bits to be encrypted each round
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES128InvCypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector, int s_bits);
        
        /// @brief This method performs the AES inverse cypher in CFB Mode from NIST SP 800 - 38a Section 6.3 "The Cipher Feedback Mode" 
        /// @param input The blocks of input to the inverse cypher
        /// @param key The key for the AES inverse cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @param s_bits The number of bits to be encrypted each round
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES128InvCypher(std::vector<AESDataBlock> input, std::string key, AESDataBlock initialization_vector, int s_bits);
        
        /// @brief This method performs the AES inverse cypher in CFB Mode from NIST SP 800 - 38a Section 6.3 "The Cipher Feedback Mode" 
        /// @param input The blocks of input to the inverse cypher
        /// @param key The key for the AES inverse cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @param s_bits The number of bits to be encrypted each round
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES128InvCypher(std::vector<AESDataBlock> input, unsigned char *key, AESDataBlock initialization_vector, int s_bits);

        /// @brief This method performs the AES cypher in CFB Mode from NIST SP 800 - 38a Section 6.3 "The Cipher Feedback Mode" 
        /// @param input The blocks of input to the cypher
        /// @param expanded_key The key for the AES cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @param s_bits The number of bits to be encrypted each round
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES192Cypher(std::string input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector, int s_bits);
        
        /// @brief This method performs the AES cypher in CFB Mode from NIST SP 800 - 38a Section 6.3 "The Cipher Feedback Mode" 
        /// @param input The blocks of input to the cypher
        /// @param key The key for the AES cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @param s_bits The number of bits to be encrypted each round
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES192Cypher(std::string input, std::string key, AESDataBlock initialization_vector, int s_bits);
        
        /// @brief This method performs the AES cypher in CFB Mode from NIST SP 800 - 38a Section 6.3 "The Cipher Feedback Mode" 
        /// @param input The blocks of input to the cypher
        /// @param key The key for the AES cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @param s_bits The number of bits to be encrypted each round
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES192Cypher(std::string input, unsigned char *key, AESDataBlock initialization_vector, int s_bits);
        
        /// @brief This method performs the AES inverse cypher in CFB Mode from NIST SP 800 - 38a Section 6.3 "The Cipher Feedback Mode" 
        /// @param input The blocks of input to the inverse cypher
        /// @param expanded_key The key for the AES inverse cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @param s_bits The number of bits to be encrypted each round
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES192InvCypher(std::string input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector, int s_bits);
        
        /// @brief This method performs the AES inverse cypher in CFB Mode from NIST SP 800 - 38a Section 6.3 "The Cipher Feedback Mode" 
        /// @param input The blocks of input to the inverse cypher
        /// @param key The key for the AES inverse cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @param s_bits The number of bits to be encrypted each round
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES192InvCypher(std::string input, std::string key, AESDataBlock initialization_vector, int s_bits);
        
        /// @brief This method performs the AES inverse cypher in CFB Mode from NIST SP 800 - 38a Section 6.3 "The Cipher Feedback Mode" 
        /// @param input The blocks of input to the inverse cypher
        /// @param key The key for the AES inverse cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @param s_bits The number of bits to be encrypted each round
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES192InvCypher(std::string input, unsigned char *key, AESDataBlock initialization_vector, int s_bits);
        
        /// @brief This method performs the AES cypher in CFB Mode from NIST SP 800 - 38a Section 6.3 "The Cipher Feedback Mode" 
        /// @param input The blocks of input to the cypher
        /// @param expanded_key The key for the AES cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @param s_bits The number of bits to be encrypted each round
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES192Cypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector, int s_bits);
        
        /// @brief This method performs the AES cypher in CFB Mode from NIST SP 800 - 38a Section 6.3 "The Cipher Feedback Mode" 
        /// @param input The blocks of input to the cypher
        /// @param key The key for the AES cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @param s_bits The number of bits to be encrypted each round
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES192Cypher(std::vector<AESDataBlock> input, std::string key, AESDataBlock initialization_vector, int s_bits);
        
        /// @brief This method performs the AES cypher in CFB Mode from NIST SP 800 - 38a Section 6.3 "The Cipher Feedback Mode" 
        /// @param input The blocks of input to the cypher
        /// @param key The key for the AES cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @param s_bits The number of bits to be encrypted each round
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES192Cypher(std::vector<AESDataBlock> input, unsigned char *key, AESDataBlock initialization_vector, int s_bits);
        
        /// @brief This method performs the AES inverse cypher in CFB Mode from NIST SP 800 - 38a Section 6.3 "The Cipher Feedback Mode" 
        /// @param input The blocks of input to the inverse cypher
        /// @param expanded_key The key for the AES inverse cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @param s_bits The number of bits to be encrypted each round
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES192InvCypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector, int s_bits);
        
        /// @brief This method performs the AES inverse cypher in CFB Mode from NIST SP 800 - 38a Section 6.3 "The Cipher Feedback Mode" 
        /// @param input The blocks of input to the inverse cypher
        /// @param key The key for the AES inverse cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @param s_bits The number of bits to be encrypted each round
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES192InvCypher(std::vector<AESDataBlock> input, std::string key, AESDataBlock initialization_vector, int s_bits);
        
        /// @brief This method performs the AES inverse cypher in CFB Mode from NIST SP 800 - 38a Section 6.3 "The Cipher Feedback Mode" 
        /// @param input The blocks of input to the inverse cypher
        /// @param key The key for the AES inverse cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @param s_bits The number of bits to be encrypted each round
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES192InvCypher(std::vector<AESDataBlock> input, unsigned char *key, AESDataBlock initialization_vector, int s_bits);

        
        
        
        
        /// @brief This method performs the AES cypher in CFB Mode from NIST SP 800 - 38a Section 6.3 "The Cipher Feedback Mode" 
        /// @param input The blocks of input to the cypher
        /// @param expanded_key The key for the AES cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @param s_bits The number of bits to be encrypted each round
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES256Cypher(std::string input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector, int s_bits);
        
        /// @brief This method performs the AES cypher in CFB Mode from NIST SP 800 - 38a Section 6.3 "The Cipher Feedback Mode" 
        /// @param input The blocks of input to the cypher
        /// @param key The key for the AES cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @param s_bits The number of bits to be encrypted each round
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES256Cypher(std::string input, std::string key, AESDataBlock initialization_vector, int s_bits);
        
        /// @brief This method performs the AES cypher in CFB Mode from NIST SP 800 - 38a Section 6.3 "The Cipher Feedback Mode" 
        /// @param input The blocks of input to the cypher
        /// @param key The key for the AES cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @param s_bits The number of bits to be encrypted each round
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES256Cypher(std::string input, unsigned char *key, AESDataBlock initialization_vector, int s_bits);
        
        /// @brief This method performs the AES inverse cypher in CFB Mode from NIST SP 800 - 38a Section 6.3 "The Cipher Feedback Mode" 
        /// @param input The blocks of input to the inverse cypher
        /// @param expanded_key The key for the AES inverse cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @param s_bits The number of bits to be encrypted each round
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES256InvCypher(std::string input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector, int s_bits);
        
        /// @brief This method performs the AES inverse cypher in CFB Mode from NIST SP 800 - 38a Section 6.3 "The Cipher Feedback Mode" 
        /// @param input The blocks of input to the inverse cypher
        /// @param key The key for the AES inverse cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @param s_bits The number of bits to be encrypted each round
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES256InvCypher(std::string input, std::string key, AESDataBlock initialization_vector, int s_bits);
        
        /// @brief This method performs the AES inverse cypher in CFB Mode from NIST SP 800 - 38a Section 6.3 "The Cipher Feedback Mode" 
        /// @param input The blocks of input to the inverse cypher
        /// @param key The key for the AES inverse cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @param s_bits The number of bits to be encrypted each round
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES256InvCypher(std::string input, unsigned char *key, AESDataBlock initialization_vector, int s_bits);
        
        
        /// @brief This method performs the AES cypher in CFB Mode from NIST SP 800 - 38a Section 6.3 "The Cipher Feedback Mode" 
        /// @param input The blocks of input to the cypher
        /// @param expanded_key The key for the AES cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @param s_bits The number of bits to be encrypted each round
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES256Cypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector, int s_bits);
        
        /// @brief This method performs the AES cypher in CFB Mode from NIST SP 800 - 38a Section 6.3 "The Cipher Feedback Mode" 
        /// @param input The blocks of input to the cypher
        /// @param key The key for the AES cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @param s_bits The number of bits to be encrypted each round
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES256Cypher(std::vector<AESDataBlock> input, std::string key, AESDataBlock initialization_vector, int s_bits);
        
        /// @brief This method performs the AES cypher in CFB Mode from NIST SP 800 - 38a Section 6.3 "The Cipher Feedback Mode" 
        /// @param input The blocks of input to the cypher
        /// @param key The key for the AES cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @param s_bits The number of bits to be encrypted each round
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES256Cypher(std::vector<AESDataBlock> input, unsigned char *key, AESDataBlock initialization_vector, int s_bits);
        
        /// @brief This method performs the AES inverse cypher in CFB Mode from NIST SP 800 - 38a Section 6.3 "The Cipher Feedback Mode" 
        /// @param input The blocks of input to the inverse cypher
        /// @param expanded_key The key for the AES inverse cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @param s_bits The number of bits to be encrypted each round
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES256InvCypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector, int s_bits);
        
        /// @brief This method performs the AES inverse cypher in CFB Mode from NIST SP 800 - 38a Section 6.3 "The Cipher Feedback Mode" 
        /// @param input The blocks of input to the inverse cypher
        /// @param key The key for the AES inverse cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @param s_bits The number of bits to be encrypted each round
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES256InvCypher(std::vector<AESDataBlock> input, std::string key, AESDataBlock initialization_vector, int s_bits);
        
        /// @brief This method performs the AES inverse cypher in CFB Mode from NIST SP 800 - 38a Section 6.3 "The Cipher Feedback Mode" 
        /// @param input The blocks of input to the inverse cypher
        /// @param key The key for the AES inverse cypher
        /// @param initialization_vector The vector to be used to initialize the mode
        /// @param s_bits The number of bits to be encrypted each round
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES256InvCypher(std::vector<AESDataBlock> input, unsigned char *key, AESDataBlock initialization_vector, int s_bits);
        
};

#endif