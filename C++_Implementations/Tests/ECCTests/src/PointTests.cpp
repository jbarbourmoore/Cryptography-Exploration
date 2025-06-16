#include <gtest/gtest.h>  
#include <stddef.h>

#include "Point.hpp"

TEST(ECC_Tests, DefaultPointOutput) {
    Point point = Point();
    point.print();
    std::string expected = std::string("(0, 0)");
    EXPECT_EQ(expected, point.toString());
}

TEST(ECC_Tests, PointOutput){
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    BN_set_word(x, 7);
    BN_set_word(y, 6);
    Point point = Point(x, y);
    point.print();
    std::string expected = std::string("(07, 06)");
    EXPECT_EQ(expected, point.toString());
}

TEST(ECC_Tests, HexStringToPointOutput){
    std::string hex_x = "A123";
    std::string hex_y = "B4582A";
    Point point = Point(hex_x, hex_y);
    point.print();
    std::string expected = std::string("(A123, B4582A)");
    EXPECT_EQ(expected, point.toString());
}