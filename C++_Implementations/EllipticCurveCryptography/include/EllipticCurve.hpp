#ifndef EllipticCurve_HPP
#define EllipticCurve_HPP
#include <openssl/bn.h>

class EllipticCurve{

    public:
        virtual void printCurveDetails() = 0;
        virtual void calculatePointMultiplicationByConstant() = 0;
        virtual void calculatePointInverse() = 0;
        virtual void validatePointOnCurve() = 0;
        virtual void calculatePointAddition() = 0;

};

#endif