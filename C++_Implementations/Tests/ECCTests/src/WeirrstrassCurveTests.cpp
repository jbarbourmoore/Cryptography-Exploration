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