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

    public:
        /// @brief This method initializes a given elliptic curve in the Weirrstrass form y^2 = x^3 + ax + b
        /// @param a The coefficient for x in the equation y^2 = x^3 + ax + b
        /// @param b The constant in the equation y^2 = x^3 + ax + b
        /// @param finite_field The finite field (p) within which all points are (modulus)
        WeirrstrassCurve(const BIGNUM* a, const BIGNUM* b, const BIGNUM* finite_field);

        /// @brief This method initializes a given elliptic curve in the Weirrstrass form y^2 = x^3 + ax + b
        /// @param a_hex The coefficient for x in the equation y^2 = x^3 + ax + b as a hexadecimal string
        /// @param b_hex The constant in the equation y^2 = x^3 + ax + b as a hexadecimal string
        /// @param finite_field_hex The finite field (p) within which all points are (modulus) as a hexadecimal string
        WeirrstrassCurve(std::string a_hex, std::string b_hex, std::string finite_field_hex);

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

class secp192r1 : public WeirrstrassCurve{

    public  : 
        secp192r1() : WeirrstrassCurve("fffffffffffffffffffffffffffffffefffffffffffffffc", 
            "64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF"){};

};

#endif