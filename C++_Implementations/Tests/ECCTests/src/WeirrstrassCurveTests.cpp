#include <gtest/gtest.h>  
#include <stddef.h>

#include "EllipticCurve.hpp"

TEST(ECC_Tests, WeirrstrassCurve_GetEquation) {
    std::string a_hex = "ABCD";
    std::string b_hex = "12345678";
    std::string finite_field_hex = "ABCDEF1234567890";
    std::string gx_hex = "ABC";
    std::string gy_hex = "DEF";
    std::string n_hex = "ABCDEF1234567889";
    WeirrstrassCurve curve = WeirrstrassCurve(a_hex, b_hex, finite_field_hex, gx_hex, gy_hex, n_hex);
    curve.printCurveDetails();
    std::string curve_equation = curve.getEquation();
    std::string expected_equation = "y^2 = x^3 + ABCD x + 12345678";
    EXPECT_EQ(curve_equation, expected_equation);
}

TEST(ECC_Tests, WeirrstrassCurve_getFiniteField){
    std::string a_hex = "ABCD";
    std::string b_hex = "12345678";
    std::string finite_field_hex = "ABCDEF1234567890";
    std::string gx_hex = "ABC";
    std::string gy_hex = "DEF";
    std::string n_hex = "ABCDEF1234567889";
    WeirrstrassCurve curve = WeirrstrassCurve(a_hex, b_hex, finite_field_hex, gx_hex, gy_hex, n_hex);
    curve.printCurveDetails();
    std::string retrieved_hex = curve.getFiniteFieldAsHex();
    EXPECT_EQ(retrieved_hex, finite_field_hex);
}

TEST(ECC_Tests, WeirrstrassCurve_getA){
    std::string a_hex = "ABCD";
    std::string b_hex = "12345678";
    std::string finite_field_hex = "ABCDEF1234567890";
    std::string gx_hex = "ABC";
    std::string gy_hex = "DEF";
    std::string n_hex = "ABCDEF1234567889";
    WeirrstrassCurve curve = WeirrstrassCurve(a_hex, b_hex, finite_field_hex, gx_hex, gy_hex, n_hex);
    curve.printCurveDetails();
    std::string retrieved_hex = curve.getAAsHex();
    EXPECT_EQ(retrieved_hex, a_hex);
}

TEST(ECC_Tests, WeirrstrassCurve_getB){
    std::string a_hex = "ABCD";
    std::string b_hex = "12345678";
    std::string finite_field_hex = "ABCDEF1234567890";
    std::string gx_hex = "ABC";
    std::string gy_hex = "DEF";
    std::string n_hex = "ABCDEF1234567889";
    WeirrstrassCurve curve = WeirrstrassCurve(a_hex, b_hex, finite_field_hex, gx_hex, gy_hex, n_hex);
    curve.printCurveDetails();
    std::string retrieved_hex = curve.getBAsHex();
    EXPECT_EQ(retrieved_hex, b_hex);
}

TEST(ECC_Tests, WeirrstrassCurve_SimpleOriginOnCurve){
    WeirrstrassCurve curve = SimpleWeirrstrassCurve();
    Point point = Point("0","0");
    curve.printCurveDetails();
    bool is_point_on_curve = curve.validatePointOnCurve(point);
    EXPECT_TRUE(is_point_on_curve);
}

TEST(ECC_Tests, WeirrstrassCurve_SimplePointOnCurve){
    WeirrstrassCurve curve = SimpleWeirrstrassCurve();
    Point point = Point("F","D");
    curve.printCurveDetails();
    bool is_point_on_curve = curve.validatePointOnCurve(point);
    EXPECT_TRUE(is_point_on_curve);
}

TEST(ECC_Tests, WeirrstrassCurve_SimplePointNotOnCurve){
    WeirrstrassCurve curve = SimpleWeirrstrassCurve();
    Point point = Point("1","2");
    curve.printCurveDetails();
    bool is_point_on_curve = curve.validatePointOnCurve(point);
    EXPECT_FALSE(is_point_on_curve);
}

TEST(ECC_Tests, WeirrstrassCurve_SimpleAddSamePoints){
    WeirrstrassCurve curve = SimpleWeirrstrassCurve();
    Point point_1 = Point("F","D");
    Point point_2 = Point("F","D");
    Point expected = Point("2", "A");
    curve.printCurveDetails();
    Point result = curve.calculatePointAddition(point_1, point_2);
    EXPECT_EQ(result, expected);
}

TEST(ECC_Tests, WeirrstrassCurve_SimpleAddDifferentPoints){
    WeirrstrassCurve curve = SimpleWeirrstrassCurve();
    Point point_1 = Point("F","D");
    Point point_2 = Point("2", "A");
    Point expected = Point("8", "3");
    curve.printCurveDetails();
    Point result = curve.calculatePointAddition(point_1, point_2);
    EXPECT_EQ(result, expected);
}

TEST(ECC_Tests, WeirrstrassCurve_SimpleMultiplyByTwo){
    WeirrstrassCurve curve = SimpleWeirrstrassCurve();
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
    WeirrstrassCurve curve = SimpleWeirrstrassCurve();
    Point point = Point("F","D");
    Point expected = Point("F", "D");
    curve.printCurveDetails();
    BIGNUM *k = BN_new();
    BN_set_word(k, 19);
    Point result = curve.calculatePointMultiplicationByConstant(point, k);
    result.print();
    EXPECT_EQ(result, expected);
}

TEST(ECC_Tests, WeirrstrassCurve_secp192r1Setup){
    WeirrstrassCurve curve = secp192r1();
    std::string result = curve.getEquation();
    std::string expected = "y^2 = x^3 + FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC x + 64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1";
    curve.printCurveDetails();
    EXPECT_EQ(result, expected);
}

TEST(ECC_Tests, WeirrstrassCurve_secp192r1PointOnCurve){
    WeirrstrassCurve curve = secp192r1();
    Point point = Point::getPointFromDecimalStrings("602046282375688656758213480587526111916698976636884684818","174050332293622031404857552280219410364023488927386650641");
    curve.printCurveDetails();
    bool is_point_on_curve = curve.validatePointOnCurve(point);
    EXPECT_TRUE(is_point_on_curve);
}

TEST(ECC_Tests, WeirrstrassCurve_secp192r1AddSamePoints){
    WeirrstrassCurve curve = secp192r1();
    Point point = Point::getPointFromDecimalStrings("602046282375688656758213480587526111916698976636884684818","174050332293622031404857552280219410364023488927386650641");
    curve.printCurveDetails();
    Point result = curve.calculatePointAddition(point, point);
    Point expected = Point::getPointFromDecimalStrings("5369744403678710563432458361254544170966096384586764429448","5429234379789071039750654906915254128254326554272718558123");
    EXPECT_EQ(result, expected);
}

TEST(ECC_Tests, WeirrstrassCurve_secp192r1MultiplyByTwo){
    WeirrstrassCurve curve = secp192r1();
    Point point = Point::getPointFromDecimalStrings("602046282375688656758213480587526111916698976636884684818","174050332293622031404857552280219410364023488927386650641");
    Point expected = Point::getPointFromDecimalStrings("5369744403678710563432458361254544170966096384586764429448","5429234379789071039750654906915254128254326554272718558123");
    curve.printCurveDetails();
    BIGNUM *k = BN_new();
    BN_set_word(k, 2);
    Point result = curve.calculatePointMultiplicationByConstant(point, k);
    result.print();
    EXPECT_EQ(result, expected);
}

TEST(ECC_Tests, WeirrstrassCurve_secp192r1MultiplyBy104){
    WeirrstrassCurve curve = secp192r1();
    Point point = Point::getPointFromDecimalStrings("602046282375688656758213480587526111916698976636884684818","174050332293622031404857552280219410364023488927386650641");
    Point expected = Point::getPointFromDecimalStrings("5124267969112884640430558489079512598372932209181558738984","5241168070499360885696850377502882660536951875217754938315");
    curve.printCurveDetails();
    BIGNUM *k = BN_new();
    BN_set_word(k, 104);
    Point result = curve.calculatePointMultiplicationByConstant(point, k);
    result.print();
    EXPECT_EQ(result, expected);
}

TEST(ECC_Tests, WeirrstrassCurve_secp192r1MultiplyBy237568){
    WeirrstrassCurve curve = secp192r1();
    Point point = Point::getPointFromDecimalStrings("602046282375688656758213480587526111916698976636884684818","174050332293622031404857552280219410364023488927386650641");
    Point expected = Point::getPointFromDecimalStrings("871023611157170972703611374923345710780774914879018003341","1903816589192018542033229449349641804651012623594677678608");
    curve.printCurveDetails();
    BIGNUM *k = BN_new();
    BN_set_word(k, 237568);
    Point result = curve.calculatePointMultiplicationByConstant(point, k);
    result.print();
    EXPECT_EQ(result, expected);
}