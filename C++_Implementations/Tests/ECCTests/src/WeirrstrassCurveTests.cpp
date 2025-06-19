#include <gtest/gtest.h>  
#include <stddef.h>

#include "EllipticCurve.hpp"

TEST(ECC_Tests, WeirrstrassCurve_GetEquation) {
    std::string a_hex = "ABCD";
    std::string b_hex = "12345678";
    std::string finite_field_hex = "ABCDEF1234567890";
    WeirrstrassCurve curve = WeirrstrassCurve(a_hex, b_hex, finite_field_hex);
    curve.printCurveDetails();
    std::string curve_equation = curve.getEquation();
    std::string expected_equation = "y^2 = x^3 + ABCD x + 12345678";
    EXPECT_EQ(curve_equation, expected_equation);
}

TEST(ECC_Tests, WeirrstrassCurve_getFiniteField){
    std::string a_hex = "ABCD";
    std::string b_hex = "12345678";
    std::string finite_field_hex = "ABCDEF1234567890";
    WeirrstrassCurve curve = WeirrstrassCurve(a_hex, b_hex, finite_field_hex);
    curve.printCurveDetails();
    std::string retrieved_hex = curve.getFiniteFieldAsHex();
    EXPECT_EQ(retrieved_hex, finite_field_hex);
}

TEST(ECC_Tests, WeirrstrassCurve_getA){
    std::string a_hex = "ABCD";
    std::string b_hex = "12345678";
    std::string finite_field_hex = "ABCDEF1234567890";
    WeirrstrassCurve curve = WeirrstrassCurve(a_hex, b_hex, finite_field_hex);
    curve.printCurveDetails();
    std::string retrieved_hex = curve.getAAsHex();
    EXPECT_EQ(retrieved_hex, a_hex);
}

TEST(ECC_Tests, WeirrstrassCurve_getB){
    std::string a_hex = "ABCD";
    std::string b_hex = "12345678";
    std::string finite_field_hex = "ABCDEF1234567890";
    WeirrstrassCurve curve = WeirrstrassCurve(a_hex, b_hex, finite_field_hex);
    curve.printCurveDetails();
    std::string retrieved_hex = curve.getBAsHex();
    EXPECT_EQ(retrieved_hex, b_hex);
}

TEST(ECC_Tests, WeirrstrassCurve_SimpleOriginOnCurve){
    std::string a_hex = "0";
    std::string b_hex = "7";
    std::string finite_field_hex = "11";
    WeirrstrassCurve curve = WeirrstrassCurve(a_hex, b_hex, finite_field_hex);
    Point point = Point("0","0");
    curve.printCurveDetails();
    bool is_point_on_curve = curve.validatePointOnCurve(point);
    EXPECT_TRUE(is_point_on_curve);
}

TEST(ECC_Tests, WeirrstrassCurve_SimplePointOnCurve){
    std::string a_hex = "0";
    std::string b_hex = "7";
    std::string finite_field_hex = "11";
    WeirrstrassCurve curve = WeirrstrassCurve(a_hex, b_hex, finite_field_hex);
    Point point = Point("F","D");
    curve.printCurveDetails();
    bool is_point_on_curve = curve.validatePointOnCurve(point);
    EXPECT_TRUE(is_point_on_curve);
}

TEST(ECC_Tests, WeirrstrassCurve_SimplePointNotOnCurve){
    std::string a_hex = "0";
    std::string b_hex = "7";
    std::string finite_field_hex = "11";
    WeirrstrassCurve curve = WeirrstrassCurve(a_hex, b_hex, finite_field_hex);
    Point point = Point("1","2");
    curve.printCurveDetails();
    bool is_point_on_curve = curve.validatePointOnCurve(point);
    EXPECT_FALSE(is_point_on_curve);
}

TEST(ECC_Tests, WeirrstrassCurve_SimpleAddSamePoints){
    std::string a_hex = "0";
    std::string b_hex = "7";
    std::string finite_field_hex = "11";
    WeirrstrassCurve curve = WeirrstrassCurve(a_hex, b_hex, finite_field_hex);
    Point point_1 = Point("F","D");
    Point point_2 = Point("F","D");
    Point expected = Point("2", "A");
    curve.printCurveDetails();
    Point result = curve.calculatePointAddition(point_1, point_2);
    EXPECT_EQ(result, expected);
}

TEST(ECC_Tests, WeirrstrassCurve_SimpleAddDifferentPoints){
    std::string a_hex = "0";
    std::string b_hex = "7";
    std::string finite_field_hex = "11";
    WeirrstrassCurve curve = WeirrstrassCurve(a_hex, b_hex, finite_field_hex);
    Point point_1 = Point("F","D");
    Point point_2 = Point("2", "A");
    Point expected = Point("8", "3");
    curve.printCurveDetails();
    Point result = curve.calculatePointAddition(point_1, point_2);
    EXPECT_EQ(result, expected);
}

TEST(ECC_Tests, WeirrstrassCurve_SimpleMultiplyByTwo){
    std::string a_hex = "0";
    std::string b_hex = "7";
    std::string finite_field_hex = "11";
    WeirrstrassCurve curve = WeirrstrassCurve(a_hex, b_hex, finite_field_hex);
    Point point = Point("F","D");
    Point expected = Point("2", "A");
    curve.printCurveDetails();
    BIGNUM *k = BN_new();
    BN_set_word(k, 2);
    Point result = curve.calculatePointMultiplicationByConstant(point, k);
    result.print();
    EXPECT_EQ(result, expected);
}

TEST(ECC_Tests, WeirrstrassCurve_SimpleMultiplyByNineteen){
    std::string a_hex = "0";
    std::string b_hex = "7";
    std::string finite_field_hex = "11";
    WeirrstrassCurve curve = WeirrstrassCurve(a_hex, b_hex, finite_field_hex);
    Point point = Point("F","D");
    Point expected = Point("F", "D");
    curve.printCurveDetails();
    BIGNUM *k = BN_new();
    BN_set_word(k, 19);
    Point result = curve.calculatePointMultiplicationByConstant(point, k);
    result.print();
    EXPECT_EQ(result, expected);
}

TEST(ECC_Tests, WeirrstrassCurve_secp129r1Setup){
    WeirrstrassCurve curve = secp192r1();
    std::string result = curve.getEquation();
    std::string expected = "y^2 = x^3 + FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC x + 64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1";
    curve.printCurveDetails();
    EXPECT_EQ(result, expected);
}

TEST(ECC_Tests, WeirrstrassCurve_secp129r1PointOnCurve){
    WeirrstrassCurve curve = secp192r1();
    Point point = Point::getPointFromDecimalStrings("602046282375688656758213480587526111916698976636884684818","174050332293622031404857552280219410364023488927386650641");
    curve.printCurveDetails();
    bool is_point_on_curve = curve.validatePointOnCurve(point);
    EXPECT_TRUE(is_point_on_curve);
}