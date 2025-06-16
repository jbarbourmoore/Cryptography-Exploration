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