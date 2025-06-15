#ifndef EllipticCurve_HPP
#define EllipticCurve_HPP
#include <openssl/bn.h>
#include "Point.hpp"

class EllipticCurve{

    public:
        virtual std::string toString() = 0;
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

        void deleteCurve() override;

        std::string toString() override;

        void printCurveDetails() override;

        bool validatePointOnCurve(Point p) override;
};

#endif