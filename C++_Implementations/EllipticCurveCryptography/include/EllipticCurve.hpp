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

};

class WeirrstrassCurve : public EllipticCurve{
    private:
        BIGNUM* a_;
        BIGNUM* b_;
        BIGNUM* finite_field_;
        Point origin_;

    public:
        WeirrstrassCurve(const BIGNUM* a, const BIGNUM* b, const BIGNUM* finite_field);

        WeirrstrassCurve(std::string a_hex, std::string b_hex, std::string finite_field_hex);

        void deleteCurve() override;

        std::string getEquation() override;

        void printCurveDetails() override;

        bool validatePointOnCurve(Point p) override;

        std::string getFiniteFieldAsHex();

        std::string getAAsHex();

        std::string getBAsHex();

        Point calculatePointMultiplicationByConstant(Point p, BIGNUM* k) override;
        Point calculatePointInverse(Point p) override;
        Point calculatePointAddition(Point p, Point q) override;
};

#endif