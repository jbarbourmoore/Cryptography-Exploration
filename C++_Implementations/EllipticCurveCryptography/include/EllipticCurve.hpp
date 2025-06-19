#ifndef EllipticCurve_HPP
#define EllipticCurve_HPP
#include <openssl/bn.h>
#include "Point.hpp"

class EllipticCurve{

    public:
        virtual std::string getEquation() = 0;
        virtual void deleteCurve() = 0;
        virtual void printCurveDetails() = 0;
        virtual Point calculatePointMultiplicationByConstant(Point p, BIGNUM* k) = 0;
        virtual Point calculatePointInverse(Point p) = 0;
        virtual bool validatePointOnCurve(Point p) = 0;
        virtual Point calculatePointAddition(Point p, Point q) = 0;
        void calculatePositiveMod(BIGNUM *value, BIGNUM *modulus, BN_CTX *calc_ctx);

};

class WeirrstrassCurve : public EllipticCurve{
    private:

        /// @brief The coefficient (a) for x in the equation y^2 = x^3 + ax + b
        BIGNUM* a_;

        /// @brief The constant (b) in the equation y^2 = x^3 + ax + b
        BIGNUM* b_;

        /// @brief The finite field (p) within which all points are (modulus)
        BIGNUM* finite_field_;

        /// @brief The origin point (0,0)
        Point origin_;

        /// @brief The generator point for the curve
        Point g_;

    public:
        /// @brief This method initializes a given elliptic curve in the Weirrstrass form y^2 = x^3 + ax + b
        /// @param a The coefficient for x in the equation y^2 = x^3 + ax + b
        /// @param b The constant in the equation y^2 = x^3 + ax + b
        /// @param finite_field The finite field (p) within which all points are (modulus)
        WeirrstrassCurve(const BIGNUM* a, const BIGNUM* b, const BIGNUM* finite_field, const BIGNUM* gx, const BIGNUM* gy);

        /// @brief This method initializes a given elliptic curve in the Weirrstrass form y^2 = x^3 + ax + b
        /// @param a_hex The coefficient for x in the equation y^2 = x^3 + ax + b as a hexadecimal string
        /// @param b_hex The constant in the equation y^2 = x^3 + ax + b as a hexadecimal string
        /// @param finite_field_hex The finite field (p) within which all points are (modulus) as a hexadecimal string
        /// @param gx_hex The x coordinate of the generator point
        /// @param gy_hex The y coordinate of the generator point
        WeirrstrassCurve(std::string a_hex, std::string b_hex, std::string finite_field_hex, std::string gx_hex, std::string gy_hex);

        /// @brief This method cleans up the WeirrstrassCurve and takes care of the BIGNUMs
        void deleteCurve() override;

        /// @brief This method returns a string containing the the equation for the Weirrstrass curve
        /// @return The equation as a string value (integers are represented in hexadecimal form)
        std::string getEquation() override;

        /// @brief This method prints the details of the curve to the console
        void printCurveDetails() override;

        /// @brief This method validates whether a point exists on the Weirrstrass Curve
        /// @param p The point that is being checked against the curve
        /// @return True if the point is on the curve
        bool validatePointOnCurve(Point p) override;

        /// @brief This method returns the hex string value for the finite field associated with this curve
        /// @return 
        std::string getFiniteFieldAsHex();

        /// @brief This method returns the hex string value for the x coefficient associated with this curve
        /// @return 
        std::string getAAsHex();

        /// @brief This method returns the hex string value for the constant associated with this curve
        /// @return 
        std::string getBAsHex();

        /// @brief This method multiplies a given point by a constant value
        /// @param p The point that is to be multiplied by a given constant
        /// @param k The constant that the point shall be multiplied by
        /// @return The point resulting from the multiplication
        Point calculatePointMultiplicationByConstant(Point p, BIGNUM* k) override;

        /// @brief This method calculates the inverse of a given point on the curve
        /// @param p The point for which we are calculating the inverse
        /// @return The inverse to the given point
        Point calculatePointInverse(Point p) override;

        /// @brief This method adds two point together on a given curve
        /// @param p One of the points to be added together
        /// @param q One of the points to be added together
        /// @return The point resulting from the addition
        Point calculatePointAddition(Point p, Point q) override;
};

class SimpleWeirrstrassCurve : public WeirrstrassCurve{
    public  : 
        SimpleWeirrstrassCurve() : WeirrstrassCurve(
            "0",   // a (x coefficient)
            "7",   // b (y coefficient)
            "11",  // p (finite field)
            "F",   // g_x (The x coordinate of the generator point)
            "D"    // g_y (The y coordinate of the generator point)
        ){};
};

/// @brief The class is the curve secp192r1 as defined in Section 2.2.2 of "SEC 2: Recommended Elliptic Curve Domain Parameters"
/// https://www.secg.org/sec2-v2.pdf
class secp192r1 : public WeirrstrassCurve{
    public  : 
        secp192r1() : WeirrstrassCurve(
            "fffffffffffffffffffffffffffffffefffffffffffffffc",   // a (x coefficient)
            "64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1",   // b (y coefficient)
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF",   // p (finite field)
            "DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D",   // g_x (The x coordinate of the generator point)
            "9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D"    // g_y (The y coordinate of the generator point)
        ){};
};

/// @brief The class is the curve secp224r1 as defined in Section 2.3.2 of "SEC 2: Recommended Elliptic Curve Domain Parameters"
/// https://www.secg.org/sec2-v2.pdf
class secp224r1 : public WeirrstrassCurve{
    public  : 
        secp224r1() : WeirrstrassCurve(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE",   // a (x coefficient)
            "B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4",   // b (y coefficient)
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001",   // p (finite field)
            "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21",   // g_x (The x coordinate of the generator point)
            "BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34"    // g_y (The y coordinate of the generator point)
        ){};
};

/// @brief The class is the curve secp256r1 as defined in Section 2.4.2 of "SEC 2: Recommended Elliptic Curve Domain Parameters"
/// https://www.secg.org/sec2-v2.pdf
class secp256r1 : public WeirrstrassCurve{
    public  : 
        secp256r1() : WeirrstrassCurve(
            "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",   // a (x coefficient)
            "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",   // b (y coefficient)
            "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",   // p (finite field)
            "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",   // g_x (The x coordinate of the generator point)
            "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"    // g_y (The y coordinate of the generator point)
        ){};
};

/// @brief The class is the curve secp384r1 as defined in Section 2.5.1 of "SEC 2: Recommended Elliptic Curve Domain Parameters"
/// https://www.secg.org/sec2-v2.pdf
class secp384r1 : public WeirrstrassCurve{
    public  : 
        secp384r1() : WeirrstrassCurve(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC",   // a (x coefficient)
            "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",   // b (y coefficient)
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",   // p (finite field)
            "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",   // g_x (The x coordinate of the generator point)
            "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F"    // g_y (The y coordinate of the generator point)
        ){};
};

/// @brief The class is the curve secp521r1 as defined in Section 2.6.1 of "SEC 2: Recommended Elliptic Curve Domain Parameters"
/// https://www.secg.org/sec2-v2.pdf
class secp521r1 : public WeirrstrassCurve{
    public  : 
        secp521r1() : WeirrstrassCurve(
            "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC",   // a (x coefficient)
            "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",   // b (y coefficient)
            "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",   // p (finite field)
            "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",   // g_x (The x coordinate of the generator point)
            "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650"    // g_y (The y coordinate of the generator point)
        ){};
};

#endif