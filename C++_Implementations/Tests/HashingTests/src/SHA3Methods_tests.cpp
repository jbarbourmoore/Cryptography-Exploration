#include <gtest/gtest.h>  
#include <stddef.h>

#include "SHA3.hpp"

TEST(SHA3Methods_Tests, sha3_theta) {
    // test values taken from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-224_Msg5.pdf
    
    std::string before_theta = "D3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";
    
    std::string after_theta = "D3 00 00 00 00 00 00 00 D2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 D2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 D2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 D2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 00 00 00 00 00 80 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 D2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 A6 01 00 00 00 00 00 00";

    before_theta.erase(std::remove(before_theta.begin(), before_theta.end(), ' '), before_theta.end());
    after_theta.erase(std::remove(after_theta.begin(), after_theta.end(), ' '), after_theta.end());

    SHA3_State state = SHA3_State(before_theta);
    state.printHex();
    state.printBits();
    state.theta();
    state.printHex();

    std::string hex_result = state.getValueAsHex();
    
    EXPECT_EQ(after_theta, hex_result);
}

TEST(SHA3Methods_Tests, sha3_rho) {
    // test values taken from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-224_Msg5.pdf
    
    std::string after_rho = "D3 00 00 00 00 00 00 00 A4 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 00 00 00 00 00 00 30 0D 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 0D 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 00 60 1A 00 00 00 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 D3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 1A 00 00 40 00 00 00 00 00 00 00 00 10 00 00 00 00 00 00 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 80 69 00 00 00 00 00 ";
    
    std::string after_theta = "D3 00 00 00 00 00 00 00 D2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 D2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 D2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 D2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 00 00 00 00 00 80 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 D2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 A6 01 00 00 00 00 00 00";

    after_rho.erase(std::remove(after_rho.begin(), after_rho.end(), ' '), after_rho.end());
    after_theta.erase(std::remove(after_theta.begin(), after_theta.end(), ' '), after_theta.end());

    SHA3_State state = SHA3_State(after_theta);
    state.printHex();
    state.printBits();
    state.rho();
    state.printHex();

    std::string hex_result = state.getValueAsHex();
    
    EXPECT_EQ(after_rho, hex_result);
}

TEST(SHA3Methods_Tests, sha3_pi) {
    // test values taken from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-224_Msg5.pdf
    
    std::string after_rho = "D3 00 00 00 00 00 00 00 A4 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 00 00 00 00 00 00 30 0D 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 0D 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 00 60 1A 00 00 00 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 D3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 1A 00 00 40 00 00 00 00 00 00 00 00 10 00 00 00 00 00 00 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 80 69 00 00 00 00 00 ";
    
    std::string after_pi = "D3 00 00 00 00 00 00 00 00 00 00 00 00 20 0D 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00 00 00 00 80 69 00 00 00 00 00 00 00 00 08 00 00 00 00 00 00 60 1A 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 1A 00 00 00 00 00 00 00 00 00 A4 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 30 0D 00 00 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 00 00 00 00 D3 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 00 00 00 ";

    after_rho.erase(std::remove(after_rho.begin(), after_rho.end(), ' '), after_rho.end());
    after_pi.erase(std::remove(after_pi.begin(), after_pi.end(), ' '), after_pi.end());

    SHA3_State state = SHA3_State(after_rho);
    state.printHex();
    state.printBits();
    state.pi();
    state.printHex();

    std::string hex_result = state.getValueAsHex();
    
    EXPECT_EQ(after_pi, hex_result);
}


TEST(SHA3Methods_Tests, sha3_chi) {
    // test values taken from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-224_Msg5.pdf
    
    std::string after_chi = "D3 00 00 00 00 00 00 00 00 00 10 00 00 20 0D 00 00 80 69 00 00 00 00 00 D3 00 10 00 00 00 00 00 00 80 69 00 00 20 0D 00 00 00 00 08 00 00 00 00 00 00 60 1A 00 40 1A 00 00 00 00 00 00 00 00 00 00 00 00 08 00 40 1A 00 00 00 60 12 00 00 00 00 A4 01 00 01 00 00 00 00 00 A6 01 00 00 00 00 00 00 00 00 01 00 00 00 00 A4 A7 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 48 03 30 0D 00 00 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 80 00 00 40 00 30 0D 00 00 00 00 00 00 00 00 00 80 00 00 00 00 00 00 D3 00 00 00 00 00 00 00 00 40 00 48 03 00 00 00 D3 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 00 40 00 ";
    
    std::string after_pi = "D3 00 00 00 00 00 00 00 00 00 00 00 00 20 0D 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00 00 00 00 80 69 00 00 00 00 00 00 00 00 08 00 00 00 00 00 00 60 1A 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 1A 00 00 00 00 00 00 00 00 00 A4 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 30 0D 00 00 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 00 00 00 00 D3 00 00 00 00 00 00 00 00 00 00 48 03 00 00 00 00 00 00 ";

    after_chi.erase(std::remove(after_chi.begin(), after_chi.end(), ' '), after_chi.end());
    after_pi.erase(std::remove(after_pi.begin(), after_pi.end(), ' '), after_pi.end());

    SHA3_State state = SHA3_State(after_pi);
    state.printHex();
    state.printBits();
    state.chi();
    state.printHex();

    std::string hex_result = state.getValueAsHex();
    
    EXPECT_EQ(after_chi, hex_result);
}