/// This file contains the methods for my SHA256 Experimentation in C++
///
/// Author        : Jamie Barbour-Moore
/// Created       : 05/20/25

#include "SHA_32bit.hpp"

const word SHA256::K[64] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

const word SHA256::H0_SHA256[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

word SHA256::getH0(int index){
    return H0_SHA256[index];
}

word SHA256::getDigestSize(){
    return MESSAGE_DIGEST_SIZE;
}

word SHA256::bigEpsilonFromZero(word x){
    word result = ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
    return result;
}

word SHA256::bigEpsilonFromOne(word x){
    word result = ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
    return result;
}

string SHA256::hashString(string input_string){
    message string_to_message = padStringToMessage(input_string);
    string hex_result = hashMessageToHex(string_to_message);
    return hex_result;
}

string SHA256::hashHexString(string input_hex){
    message string_to_message = padHexStringToMessage(input_hex);
    string hex_result = hashMessageToHex(string_to_message);
    return hex_result;
}

word SHA256::smallEpsilonFromZero(word x){
    word result = ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3);
    // printf("ROTR(x, 7) : %s, ROTR(x, 18) : %s, SHR(x, 3) : %s, small epsilon from zero : %s\n", wordToHexString(ROTR(x, 7)).c_str(), wordToHexString(ROTR(x, 18)).c_str(), wordToHexString(x>>3).c_str(), wordToHexString(result).c_str());
    return result;
}

word SHA256::smallEpsilonFromOne(word x){
    word result = ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10);
    return result;
}

string SHA256::hashMessageToHex(message input){
    // use the overrided methods to load the appropriate constants
    word H[8];
    H[0] = getH0(0);
    H[1] = getH0(1);
    H[2] = getH0(2);
    H[3] = getH0(3);
    H[4] = getH0(4);
    H[5] = getH0(5);
    H[6] = getH0(6);
    H[7] = getH0(7);

    for (size_t block_num = 0; block_num < input.size(); block_num ++){
        // set the working variables for the iteration
        word a = H[0];
        word b = H[1];
        word c = H[2];
        word d = H[3];
        word e = H[4];
        word f = H[5];
        word g = H[6];
        word h = H[7];
        
        // create the message schedule
        block M = input[block_num];
        word W[80];
        for (size_t t = 0; t < 16; t ++){
            W[t] = M[t];
        }
        for (size_t t = 16; t < ITERATION_COUNT; t ++){
            W[t] = smallEpsilonFromOne(W[t - 2]) + W[t - 7] + smallEpsilonFromZero(W[t - 15]) + W[t - 16];
        }

        // process the message block
        for (size_t t = 0; t < ITERATION_COUNT; t ++){
            word T1 = h + bigEpsilonFromOne(e) + ch(e, f, g) + K[t] + W[t];
            word T2 = bigEpsilonFromZero(a) + maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        // update the hash values
        H[0] = H[0] + a;
        H[1] = H[1] + b;
        H[2] = H[2] + c;
        H[3] = H[3] + d;
        H[4] = H[4] + e;
        H[5] = H[5] + f;
        H[6] = H[6] + g;
        H[7] = H[7] + h;
    }

    // convert the hash to hexadecimal
    string hash_digest = "";
    for ( int i = 0; i < 8; i ++){
        hash_digest += wordToHexString(H[i]) + " ";
    }

    // ensure the hash digest is the appropriate length
    int digest_size = getDigestSize() / 4;
    int digest_length_hex = digest_size + (digest_size / 8);
    if (digest_size % 8 == 0){
        digest_length_hex -= 1;
    }
    if(hash_digest.size() > digest_length_hex){
        hash_digest = hash_digest.substr(0, digest_length_hex);
    }

    // return the hash digest
    return hash_digest;
}