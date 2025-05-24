#ifndef AES_ECB_HPP
#define AES_ECB_HPP

#include "AES.hpp"

#include <vector>
#include <cstdio>

/// @brief This class contains the functions for AES in Electronic Cookbook Mode as defined in NIST SP 800 -38a 
/// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
class AES_ECB{
    public :


        /// @brief This method performs the AES cypher in ECB Mode from NIST SP 800 - 38a 6.1 "The Electronic Codebook Mode"
        /// @param input The blocks of input to the cypher
        /// @param expanded_key The key for the AES cypher
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES128Cypher(std::string input, std::vector<AESWord> expanded_key);
        
        /// @brief This method performs the AES cypher in ECB Mode from NIST SP 800 - 38a 6.1 "The Electronic Codebook Mode"
        /// @param input The blocks of input to the cypher
        /// @param key The key for the AES cypher
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES128Cypher(std::string input, std::string key);
        
        /// @brief This method performs the AES cypher in ECB Mode from NIST SP 800 - 38a 6.1 "The Electronic Codebook Mode"
        /// @param input The blocks of input to the cypher
        /// @param key The key for the AES cypher
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES128Cypher(std::string input, unsigned char *key);
        
        /// @brief This method performs the AES inverse cypher in ECB Mode from NIST SP 800 - 38a 6.1 "The Electronic Codebook Mode"
        /// @param input The blocks of input to the inverse cypher
        /// @param expanded_key The key for the AES inverse cypher
        /// @return The decrypted blocks of data from the input
        static std::vector<AESDataBlock> AES128InvCypher(std::string input, std::vector<AESWord> expanded_key);
        
        /// @brief This method performs the AES inverse cypher in ECB Mode from NIST SP 800 - 38a 6.1 "The Electronic Codebook Mode"
        /// @param input The blocks of input to the inverse cypher
        /// @param key The key for the AES inverse cypher
        /// @return The decrypted blocks of data from the input
        static std::vector<AESDataBlock> AES128InvCypher(std::string input, std::string key);
        
        /// @brief This method performs the AES inverse cypher in ECB Mode from NIST SP 800 - 38a 6.1 "The Electronic Codebook Mode"
        /// @param input The blocks of input to the inverse cypher
        /// @param key The key for the AES inverse cypher
        /// @return The decrypted blocks of data from the input
        static std::vector<AESDataBlock> AES128InvCypher(std::string input, unsigned char *key);
        
        /// @brief This method performs the AES cypher in ECB Mode from NIST SP 800 - 38a 6.1 "The Electronic Codebook Mode"
        /// @param input The blocks of input to the cypher
        /// @param expanded_key The key for the AES cypher
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES128Cypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key);
        
        /// @brief This method performs the AES cypher in ECB Mode from NIST SP 800 - 38a 6.1 "The Electronic Codebook Mode"
        /// @param input The blocks of input to the cypher
        /// @param key The key for the AES cypher
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES128Cypher(std::vector<AESDataBlock> input, std::string key);
        
        /// @brief This method performs the AES cypher in ECB Mode from NIST SP 800 - 38a 6.1 "The Electronic Codebook Mode"
        /// @param input The blocks of input to the cypher
        /// @param key The key for the AES cypher
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES128Cypher(std::vector<AESDataBlock> input, unsigned char *key);
        
        /// @brief This method performs the AES inverse cypher in ECB Mode from NIST SP 800 - 38a 6.1 "The Electronic Codebook Mode"
        /// @param input The blocks of input to the inverse cypher
        /// @param expanded_key The key for the AES inverse cypher
        /// @return The decrypted blocks of data from the input
        static std::vector<AESDataBlock> AES128InvCypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key);
        
        /// @brief This method performs the AES inverse cypher in ECB Mode from NIST SP 800 - 38a 6.1 "The Electronic Codebook Mode"
        /// @param input The blocks of input to the inverse cypher
        /// @param key The key for the AES inverse cypher
        /// @return The decrypted blocks of data from the input
        static std::vector<AESDataBlock> AES128InvCypher(std::vector<AESDataBlock> input, std::string key);
        
        /// @brief This method performs the AES inverse cypher in ECB Mode from NIST SP 800 - 38a 6.1 "The Electronic Codebook Mode"
        /// @param input The blocks of input to the inverse cypher
        /// @param key The key for the AES inverse cypher
        /// @return The decrypted blocks of data from the input
        static std::vector<AESDataBlock> AES128InvCypher(std::vector<AESDataBlock> input, unsigned char *key);




        
        /// @brief This method performs the AES cypher in ECB Mode from NIST SP 800 - 38a 6.1 "The Electronic Codebook Mode"
        /// @param input The blocks of input to the cypher
        /// @param expanded_key The key for the AES cypher
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES192Cypher(std::string input, std::vector<AESWord> expanded_key);
        
        /// @brief This method performs the AES cypher in ECB Mode from NIST SP 800 - 38a 6.1 "The Electronic Codebook Mode"
        /// @param input The blocks of input to the cypher
        /// @param key The key for the AES cypher
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES192Cypher(std::string input, std::string key);
        
        /// @brief This method performs the AES cypher in ECB Mode from NIST SP 800 - 38a 6.1 "The Electronic Codebook Mode"
        /// @param input The blocks of input to the cypher
        /// @param key The key for the AES cypher
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES192Cypher(std::string input, unsigned char *key);
        
        /// @brief This method performs the AES inverse cypher in ECB Mode from NIST SP 800 - 38a 6.1 "The Electronic Codebook Mode"
        /// @param input The blocks of input to the inverse cypher
        /// @param expanded_key The key for the AES inverse cypher
        /// @return The decrypted blocks of data from the input
        static std::vector<AESDataBlock> AES192InvCypher(std::string input, std::vector<AESWord> expanded_key);
        
        /// @brief This method performs the AES inverse cypher in ECB Mode from NIST SP 800 - 38a 6.1 "The Electronic Codebook Mode"
        /// @param input The blocks of input to the inverse cypher
        /// @param key The key for the AES inverse cypher
        /// @return The decrypted blocks of data from the input
        static std::vector<AESDataBlock> AES192InvCypher(std::string input, std::string key);
        
        /// @brief This method performs the AES inverse cypher in ECB Mode from NIST SP 800 - 38a 6.1 "The Electronic Codebook Mode"
        /// @param input The blocks of input to the inverse cypher
        /// @param key The key for the AES inverse cypher
        /// @return The decrypted blocks of data from the input
        static std::vector<AESDataBlock> AES192InvCypher(std::string input, unsigned char *key);
        
        /// @brief This method performs the AES cypher in ECB Mode from NIST SP 800 - 38a 6.1 "The Electronic Codebook Mode"
        /// @param input The blocks of input to the cypher
        /// @param expanded_key The key for the AES cypher
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES192Cypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key);
        
        /// @brief This method performs the AES cypher in ECB Mode from NIST SP 800 - 38a 6.1 "The Electronic Codebook Mode"
        /// @param input The blocks of input to the cypher
        /// @param key The key for the AES cypher
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES192Cypher(std::vector<AESDataBlock> input, std::string key);
        
        /// @brief This method performs the AES cypher in ECB Mode from NIST SP 800 - 38a 6.1 "The Electronic Codebook Mode"
        /// @param input The blocks of input to the cypher
        /// @param key The key for the AES cypher
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES192Cypher(std::vector<AESDataBlock> input, unsigned char *key);
        
        /// @brief This method performs the AES inverse cypher in ECB Mode from NIST SP 800 - 38a 6.1 "The Electronic Codebook Mode"
        /// @param input The blocks of input to the inverse cypher
        /// @param expanded_key The key for the AES inverse cypher
        /// @return The decrypted blocks of data from the input
        static std::vector<AESDataBlock> AES192InvCypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key);
        
        /// @brief This method performs the AES inverse cypher in ECB Mode from NIST SP 800 - 38a 6.1 "The Electronic Codebook Mode"
        /// @param input The blocks of input to the inverse cypher
        /// @param key The key for the AES inverse cypher
        /// @return The decrypted blocks of data from the input
        static std::vector<AESDataBlock> AES192InvCypher(std::vector<AESDataBlock> input, std::string key);
        
        /// @brief This method performs the AES inverse cypher in ECB Mode from NIST SP 800 - 38a 6.1 "The Electronic Codebook Mode"
        /// @param input The blocks of input to the inverse cypher
        /// @param key The key for the AES inverse cypher
        /// @return The decrypted blocks of data from the input
        static std::vector<AESDataBlock> AES192InvCypher(std::vector<AESDataBlock> input, unsigned char *key);




        
        /// @brief This method performs the AES cypher in ECB Mode from NIST SP 800 - 38a 6.1 "The Electronic Codebook Mode"
        /// @param input The blocks of input to the cypher
        /// @param expanded_key The key for the AES cypher
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES256Cypher(std::string input, std::vector<AESWord> expanded_key);
        
        /// @brief This method performs the AES cypher in ECB Mode from NIST SP 800 - 38a 6.1 "The Electronic Codebook Mode"
        /// @param input The blocks of input to the cypher
        /// @param key The key for the AES cypher
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES256Cypher(std::string input, std::string key);
        
        /// @brief This method performs the AES cypher in ECB Mode from NIST SP 800 - 38a 6.1 "The Electronic Codebook Mode"
        /// @param input The blocks of input to the cypher
        /// @param key The key for the AES cypher
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES256Cypher(std::string input, unsigned char *key);
        
        /// @brief This method performs the AES inverse cypher in ECB Mode from NIST SP 800 - 38a 6.1 "The Electronic Codebook Mode"
        /// @param input The blocks of input to the inverse cypher
        /// @param expanded_key The key for the AES inverse cypher
        /// @return The decrypted blocks of data from the input
        static std::vector<AESDataBlock> AES256InvCypher(std::string input, std::vector<AESWord> expanded_key);
        
        /// @brief This method performs the AES inverse cypher in ECB Mode from NIST SP 800 - 38a 6.1 "The Electronic Codebook Mode"
        /// @param input The blocks of input to the inverse cypher
        /// @param key The key for the AES inverse cypher
        /// @return The decrypted blocks of data from the input
        static std::vector<AESDataBlock> AES256InvCypher(std::string input, std::string key);
        
        /// @brief This method performs the AES inverse cypher in ECB Mode from NIST SP 800 - 38a 6.1 "The Electronic Codebook Mode"
        /// @param input The blocks of input to the inverse cypher
        /// @param key The key for the AES inverse cypher
        /// @return The decrypted blocks of data from the input
        static std::vector<AESDataBlock> AES256InvCypher(std::string input, unsigned char *key);
        
        /// @brief This method performs the AES cypher in ECB Mode from NIST SP 800 - 38a 6.1 "The Electronic Codebook Mode"
        /// @param input The blocks of input to the cypher
        /// @param expanded_key The key for the AES cypher
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES256Cypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key);
        
        /// @brief This method performs the AES cypher in ECB Mode from NIST SP 800 - 38a 6.1 "The Electronic Codebook Mode"
        /// @param input The blocks of input to the cypher
        /// @param key The key for the AES cypher
        /// @return The encrypted blocks of data from the input
        static std::vector<AESDataBlock> AES256Cypher(std::vector<AESDataBlock> input, std::string key);
        
        /// @brief This method performs the AES cypher in ECB Mode from NIST SP 800 - 38a 6.1 "The Electronic Codebook Mode"
        /// @param input The blocks of input to the cypher
        /// @param key The key for the AES cypher
        /// @return The encrypted blocks of data from the inputt
        static std::vector<AESDataBlock> AES256Cypher(std::vector<AESDataBlock> input, unsigned char *key);
        
        /// @brief This method performs the AES inverse cypher in ECB Mode from NIST SP 800 - 38a 6.1 "The Electronic Codebook Mode"
        /// @param input The blocks of input to the inverse cypher
        /// @param expanded_key The key for the AES inverse cypher
        /// @return The decrypted blocks of data from the input
        static std::vector<AESDataBlock> AES256InvCypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key);
        
        /// @brief This method performs the AES inverse cypher in ECB Mode from NIST SP 800 - 38a 6.1 "The Electronic Codebook Mode"
        /// @param input The blocks of input to the inverse cypher
        /// @param key The key for the AES inverse cypher
        /// @return The decrypted blocks of data from the input
        static std::vector<AESDataBlock> AES256InvCypher(std::vector<AESDataBlock> input, std::string key);
        
        /// @brief This method performs the AES inverse cypher in ECB Mode from NIST SP 800 - 38a 6.1 "The Electronic Codebook Mode"
        /// @param input The blocks of input to the inverse cypher
        /// @param key The key for the AES inverse cypher
        /// @return The decrypted blocks of data from the input
        static std::vector<AESDataBlock> AES256InvCypher(std::vector<AESDataBlock> input, unsigned char *key);
};

#endif