#include "EllipticCurve.hpp"

int main(int argc, char const *argv[]) {
    std::string a_hex = "0";
    std::string b_hex = "7";
    std::string finite_field_hex = "11";
    WeirrstrassCurve curve = WeirrstrassCurve(a_hex, b_hex, finite_field_hex);
    Point point_1 = Point("F","D");
    Point point_2 = Point("F","D");
    Point expected = Point("2", "A");
    curve.printCurveDetails();
    Point result = curve.calculatePointAddition(point_1, point_2);
    result.print();
}