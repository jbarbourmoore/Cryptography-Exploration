#ifndef AES_ECB_HPP
#define AES_ECB_HPP

#include "AES.hpp"

#include <vector>
#include <cstdio>

class AES_ECB{
    public :
        static std::vector<AESDataBlock> AES128Cypher(std::string input, std::vector<AESWord> expanded_key);
        static std::vector<AESDataBlock> AES128Cypher(std::string input, std::string key);
        static std::vector<AESDataBlock> AES128Cypher(std::string input, unsigned char *key);
        static std::vector<AESDataBlock> AES128InvCypher(std::string input, std::vector<AESWord> expanded_key);
        static std::vector<AESDataBlock> AES128InvCypher(std::string input, std::string key);
        static std::vector<AESDataBlock> AES128InvCypher(std::string input, unsigned char *key);
        static std::vector<AESDataBlock> AES128Cypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key);
        static std::vector<AESDataBlock> AES128Cypher(std::vector<AESDataBlock> input, std::string key);
        static std::vector<AESDataBlock> AES128Cypher(std::vector<AESDataBlock> input, unsigned char *key);
        static std::vector<AESDataBlock> AES128InvCypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key);
        static std::vector<AESDataBlock> AES128InvCypher(std::vector<AESDataBlock> input, std::string key);
        static std::vector<AESDataBlock> AES128InvCypher(std::vector<AESDataBlock> input, unsigned char *key);

        static std::vector<AESDataBlock> AES192Cypher(std::string input, std::vector<AESWord> expanded_key);
        static std::vector<AESDataBlock> AES192Cypher(std::string input, std::string key);
        static std::vector<AESDataBlock> AES192Cypher(std::string input, unsigned char *key);
        static std::vector<AESDataBlock> AES192InvCypher(std::string input, std::vector<AESWord> expanded_key);
        static std::vector<AESDataBlock> AES192InvCypher(std::string input, std::string key);
        static std::vector<AESDataBlock> AES192InvCypher(std::string input, unsigned char *key);
        static std::vector<AESDataBlock> AES192Cypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key);
        static std::vector<AESDataBlock> AES192Cypher(std::vector<AESDataBlock> input, std::string key);
        static std::vector<AESDataBlock> AES192Cypher(std::vector<AESDataBlock> input, unsigned char *key);
        static std::vector<AESDataBlock> AES192InvCypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key);
        static std::vector<AESDataBlock> AES192InvCypher(std::vector<AESDataBlock> input, std::string key);
        static std::vector<AESDataBlock> AES192InvCypher(std::vector<AESDataBlock> input, unsigned char *key);

        static std::vector<AESDataBlock> AES256Cypher(std::string input, std::vector<AESWord> expanded_key);
        static std::vector<AESDataBlock> AES256Cypher(std::string input, std::string key);
        static std::vector<AESDataBlock> AES256Cypher(std::string input, unsigned char *key);
        static std::vector<AESDataBlock> AES256InvCypher(std::string input, std::vector<AESWord> expanded_key);
        static std::vector<AESDataBlock> AES256InvCypher(std::string input, std::string key);
        static std::vector<AESDataBlock> AES256InvCypher(std::string input, unsigned char *key);
        static std::vector<AESDataBlock> AES256Cypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key);
        static std::vector<AESDataBlock> AES256Cypher(std::vector<AESDataBlock> input, std::string key);
        static std::vector<AESDataBlock> AES256Cypher(std::vector<AESDataBlock> input, unsigned char *key);
        static std::vector<AESDataBlock> AES256InvCypher(std::vector<AESDataBlock> input, std::vector<AESWord> expanded_key);
        static std::vector<AESDataBlock> AES256InvCypher(std::vector<AESDataBlock> input, std::string key);
        static std::vector<AESDataBlock> AES256InvCypher(std::vector<AESDataBlock> input, unsigned char *key);
};

#endif