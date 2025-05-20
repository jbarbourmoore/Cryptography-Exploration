/// This file contains the methods for my SHA1 Experimentation in C++
///
/// Author        : Jamie Barbour-Moore
/// Created       : 05/19/25

#include "SHA_32bit.hpp"

const word SHA1::K[4] = {0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6};

const word SHA1::H0[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};

word SHA1::parity(word x, word y, word z){
    word result = x ^ y ^ z;
    return result;
}

string SHA1::hashMessageToHex(message input){
    // set the initial hash values using the constants
    word H[5];
    H[0] = H0[0];
    H[1] = H0[1];
    H[2] = H0[2];
    H[3] = H0[3];
    H[4] = H0[4];

    for (size_t block_num = 0; block_num < input.size(); block_num ++){
        // set the working variables for the iteration
        word a = H[0];
        word b = H[1];
        word c = H[2];
        word d = H[3];
        word e = H[4];

        // create the message schedule
        block M = input[block_num];
        word W[80];
        for (size_t t = 0; t < 16; t ++){
            W[t] = M[t];
        }
        for (size_t t = 16; t < 80; t ++){
            W[t] = W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16];
            W[t] = ROTL(W[t], 1);
        }

        // process the message block
        for (size_t t = 0; t < 80; t ++){
            word Kt;
            word f_bcd;
            if (t < 20){
                Kt = K[0];
                f_bcd = ch(b, c ,d);
            } else if (t < 40) {
                Kt = K[1];
                f_bcd = parity(b, c, d);
            } else if (t < 60) {
                Kt = K[2];
                f_bcd = maj(b, c, d);
            } else {
                Kt = K[3];
                f_bcd = parity(b, c, d);
            }
            word T = ROTL(a, 5);
            T = T + f_bcd + Kt + e + W[t];
            e = d;
            d = c;
            c = ROTL(b, 30);
            b = a;
            a = T;
        }
        // update the hash values
        H[0] = H[0] + a;
        H[1] = H[1] + b;
        H[2] = H[2] + c;
        H[3] = H[3] + d;
        H[4] = H[4] + e;
    }

    // convert the hash digest to hexadecimal string
    string hash_digest = "";
    for ( int i = 0; i < 5; i ++){
        hash_digest += wordToHexString(H[i]);
        if (i < 4){
            hash_digest += " ";
        }
    }

    // return the hash digest as a hexadecimal string
    return hash_digest;
}

string SHA1::hashString(string input_string){
    message string_to_message = padStringToMessage(input_string);
    string hex_result = hashMessageToHex(string_to_message);
    return hex_result;
}

string SHA1::hashHexString(string input_hex){
    message string_to_message = padHexStringToMessage(input_hex);
    string hex_result = hashMessageToHex(string_to_message);
    return hex_result;
}