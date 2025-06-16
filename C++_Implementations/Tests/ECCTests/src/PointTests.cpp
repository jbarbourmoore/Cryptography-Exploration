#include <gtest/gtest.h>  
#include <stddef.h>

#include "Point.hpp"

TEST(ECC_Tests, Point_DefaultOutput) {
    Point point = Point();
    point.print();
    std::string expected = std::string("(0, 0)");
    EXPECT_EQ(expected, point.toString());
}

TEST(ECC_Tests, Point_Output){
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    BN_set_word(x, 7);
    BN_set_word(y, 6);
    Point point = Point(x, y);
    point.print();
    std::string expected = std::string("(07, 06)");
    EXPECT_EQ(expected, point.toString());
}

TEST(ECC_Tests, Point_HexStringOutput){
    std::string hex_x = "A123";
    std::string hex_y = "B4582A";
    Point point = Point(hex_x, hex_y);
    point.print();
    std::string expected = std::string("(A123, B4582A)");
    EXPECT_EQ(expected, point.toString());
}

TEST(ECC_Tests, Point_GetXAsHexString){
    std::string hex_x = "BCDEF1ABAB12";
    std::string hex_y = "514ED226710923";
    Point point = Point(hex_x, hex_y);
    point.print();
    EXPECT_EQ(hex_x, point.getXAsHexStr());
}

TEST(ECC_Tests, Point_GetYAsHexString){
    std::string hex_x = "BCDEF1ABAB12";
    std::string hex_y = "514ED226710923";
    Point point = Point(hex_x, hex_y);
    point.print();
    EXPECT_EQ(hex_y, point.getYAsHexStr());
}

TEST(ECC_Tests, Point_EqualsOperator){
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    BN_set_word(x, 10);
    BN_set_word(y, 17);
    Point p = Point(x, y);
    std::string hex_x = "0A";
    std::string hex_y = "11";
    Point q = Point(hex_x, hex_y);
    EXPECT_EQ(p, q);
}

TEST(ECC_Tests, Point_EqualsOperatorNot){
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    BN_set_word(x, 11);
    BN_set_word(y, 17);
    Point p = Point(x, y);
    std::string hex_x = "0A";
    std::string hex_y = "11";
    Point q = Point(hex_x, hex_y);
    EXPECT_FALSE(p == q);
}