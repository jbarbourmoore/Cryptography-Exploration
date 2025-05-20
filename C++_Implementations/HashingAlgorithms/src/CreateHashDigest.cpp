#include "CreateHashDigest.hpp"

int CreateHashDigest::getDigestLength(HashType hash_type){
    int digest_length = 0;
    switch(hash_type){
        case HashType::SHA1_DIGEST:
            digest_length = 160;
            break;
        case HashType::SHA224_DIGEST:
            digest_length = 224;
            break;
        case HashType::SHA256_DIGEST:
            digest_length = 256;
            break;
        case HashType::SHA384_DIGEST:
            digest_length = 384;
            break;
        case HashType::SHA512_DIGEST:
            digest_length = 512;
            break;
        case HashType::SHA512_224_DIGEST:
            digest_length = 224;
            break;
        case HashType::SHA512_256_DIGEST:
            digest_length = 256;
            break;
    }
    return digest_length;
}

string CreateHashDigest::fromString(string input_string, HashType hash_type){
    string hash_digest = "";
    switch(hash_type){
        case HashType::SHA1_DIGEST:{
            SHA1 hashing_algorithm = SHA1();
            hash_digest = hashing_algorithm.hashString(input_string);
            break;
        }
        case HashType::SHA224_DIGEST:{
            SHA224 hashing_algorithm = SHA224();
            hash_digest = hashing_algorithm.hashString(input_string);
            break;
        }
        case HashType::SHA256_DIGEST:{
            SHA256 hashing_algorithm = SHA256();
            hash_digest = hashing_algorithm.hashString(input_string);
            break;
        }
        case HashType::SHA384_DIGEST:{
            SHA384 hashing_algorithm = SHA384();
            hash_digest = hashing_algorithm.hashString(input_string);
            break;
        }
        case HashType::SHA512_DIGEST:{
            SHA512 hashing_algorithm = SHA512();
            hash_digest = hashing_algorithm.hashString(input_string);
            break;
        }
        case HashType::SHA512_224_DIGEST:{
            SHA512_224 hashing_algorithm = SHA512_224();
            hash_digest = hashing_algorithm.hashString(input_string);
            break;
        }
        case HashType::SHA512_256_DIGEST:{
            SHA512_256 hashing_algorithm = SHA512_256();
            hash_digest = hashing_algorithm.hashString(input_string);
            break;
        }
    }
    return hash_digest;
}

string CreateHashDigest::fromHexString(string input_hex, HashType hash_type){
    string hash_digest = "";
    switch(hash_type){
        case HashType::SHA1_DIGEST:{
            SHA1 hashing_algorithm = SHA1();
            hash_digest = hashing_algorithm.hashHexString(input_hex);
            break;
        }
        case HashType::SHA224_DIGEST:{
            SHA224 hashing_algorithm = SHA224();
            hash_digest = hashing_algorithm.hashHexString(input_hex);
            break;
        }
        case HashType::SHA256_DIGEST:{
            SHA256 hashing_algorithm = SHA256();
            hash_digest = hashing_algorithm.hashHexString(input_hex);
            break;
        }
        case HashType::SHA384_DIGEST:{
            SHA384 hashing_algorithm = SHA384();
            hash_digest = hashing_algorithm.hashHexString(input_hex);
            break;
        }
        case HashType::SHA512_DIGEST:{
            SHA512 hashing_algorithm = SHA512();
            hash_digest = hashing_algorithm.hashHexString(input_hex);
            break;
        }
        case HashType::SHA512_224_DIGEST:{
            SHA512_224 hashing_algorithm = SHA512_224();
            hash_digest = hashing_algorithm.hashHexString(input_hex);
            break;
        }
        case HashType::SHA512_256_DIGEST:{
            SHA512_256 hashing_algorithm = SHA512_256();
            hash_digest = hashing_algorithm.hashHexString(input_hex);
            break;
        }
    }
    return hash_digest;
}