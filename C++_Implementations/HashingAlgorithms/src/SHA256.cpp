#include "SHA2.hpp"

word SHA256::bigEpsilonFromZero(word x){
    word result = ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
    return result;
}

word SHA256::bigEpsilonFromOne(word x){
    word result = ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
    return result;
}

word SHA256::smallEpsilonFromZero(word x){
    word result = ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3);
    return result;
}

word SHA256::smallEpsilonFromOne(word x){
    word result = ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10);
    return result;
}