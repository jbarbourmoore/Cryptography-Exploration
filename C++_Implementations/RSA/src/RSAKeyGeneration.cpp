#include "RSAKeyGeneration.hpp"

int RSAKeyGeneration::getSecurityStrength(){
    int security_strength = 0;
    if (keylength_ == 2048) {
        security_strength = 112;
    } else if (keylength_ == 3072) {
        security_strength = 128;
    } else if (keylength_ == 7680) {
        security_strength = 192;
    } else if (keylength_ == 15360){
        security_strength = 256;
    }
    return security_strength;
};

int RSAKeyGeneration::getKeyLength(){
    return keylength_;
};