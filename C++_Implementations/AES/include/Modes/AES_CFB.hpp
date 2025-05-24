#ifndef AES_CFB_HPP
#define AES_CFB_HPP

#include "AES.hpp"

#include <vector>
#include <cstdio>

class AES_CFB{
    public :
        static const int block_size = 128;

        static std::vector<AESDataBlock> AES128Cypher(std::string input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector, int s_bits);
        static std::vector<AESDataBlock> AES128Cypher(std::string input, std::string key, AESDataBlock initialization_vector, int s_bits);
        static std::vector<AESDataBlock> AES128Cypher(std::string input, unsigned char *key, AESDataBlock initialization_vector, int s_bits);
        static std::vector<AESDataBlock> AES128InvCypher(std::string input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector, int s_bits);
        static std::vector<AESDataBlock> AES128InvCypher(std::string input, std::string key, AESDataBlock initialization_vector, int s_bits);
        static std::vector<AESDataBlock> AES128InvCypher(std::string input, unsigned char *key, AESDataBlock initialization_vector, int s_bits);
        static std::vector<AESDataBlock> AES128Cypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector, int s_bits);
        static std::vector<AESDataBlock> AES128Cypher(std::vector<AESDataBlock> input, std::string key, AESDataBlock initialization_vector, int s_bits);
        static std::vector<AESDataBlock> AES128Cypher(std::vector<AESDataBlock> input, unsigned char *key, AESDataBlock initialization_vector, int s_bits);
        static std::vector<AESDataBlock> AES128InvCypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector, int s_bits);
        static std::vector<AESDataBlock> AES128InvCypher(std::vector<AESDataBlock> input, std::string key, AESDataBlock initialization_vector, int s_bits);
        static std::vector<AESDataBlock> AES128InvCypher(std::vector<AESDataBlock> input, unsigned char *key, AESDataBlock initialization_vector, int s_bits);

        static std::vector<AESDataBlock> AES192Cypher(std::string input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector, int s_bits);
        static std::vector<AESDataBlock> AES192Cypher(std::string input, std::string key, AESDataBlock initialization_vector, int s_bits);
        static std::vector<AESDataBlock> AES192Cypher(std::string input, unsigned char *key, AESDataBlock initialization_vector, int s_bits);
        static std::vector<AESDataBlock> AES192InvCypher(std::string input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector, int s_bits);
        static std::vector<AESDataBlock> AES192InvCypher(std::string input, std::string key, AESDataBlock initialization_vector, int s_bits);
        static std::vector<AESDataBlock> AES192InvCypher(std::string input, unsigned char *key, AESDataBlock initialization_vector, int s_bits);
        static std::vector<AESDataBlock> AES192Cypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector, int s_bits);
        static std::vector<AESDataBlock> AES192Cypher(std::vector<AESDataBlock> input, std::string key, AESDataBlock initialization_vector, int s_bits);
        static std::vector<AESDataBlock> AES192Cypher(std::vector<AESDataBlock> input, unsigned char *key, AESDataBlock initialization_vector, int s_bits);
        static std::vector<AESDataBlock> AES192InvCypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector, int s_bits);
        static std::vector<AESDataBlock> AES192InvCypher(std::vector<AESDataBlock> input, std::string key, AESDataBlock initialization_vector, int s_bits);
        static std::vector<AESDataBlock> AES192InvCypher(std::vector<AESDataBlock> input, unsigned char *key, AESDataBlock initialization_vector, int s_bits);

        static std::vector<AESDataBlock> AES256Cypher(std::string input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector, int s_bits);
        static std::vector<AESDataBlock> AES256Cypher(std::string input, std::string key, AESDataBlock initialization_vector, int s_bits);
        static std::vector<AESDataBlock> AES256Cypher(std::string input, unsigned char *key, AESDataBlock initialization_vector, int s_bits);
        static std::vector<AESDataBlock> AES256InvCypher(std::string input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector, int s_bits);
        static std::vector<AESDataBlock> AES256InvCypher(std::string input, std::string key, AESDataBlock initialization_vector, int s_bits);
        static std::vector<AESDataBlock> AES256InvCypher(std::string input, unsigned char *key, AESDataBlock initialization_vector, int s_bits);
        static std::vector<AESDataBlock> AES256Cypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector, int s_bits);
        static std::vector<AESDataBlock> AES256Cypher(std::vector<AESDataBlock> input, std::string key, AESDataBlock initialization_vector, int s_bits);
        static std::vector<AESDataBlock> AES256Cypher(std::vector<AESDataBlock> input, unsigned char *key, AESDataBlock initialization_vector, int s_bits);
        static std::vector<AESDataBlock> AES256InvCypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key, AESDataBlock initialization_vector, int s_bits);
        static std::vector<AESDataBlock> AES256InvCypher(std::vector<AESDataBlock> input, std::string key, AESDataBlock initialization_vector, int s_bits);
        static std::vector<AESDataBlock> AES256InvCypher(std::vector<AESDataBlock> input, unsigned char *key, AESDataBlock initialization_vector, int s_bits);
        
};

#endif