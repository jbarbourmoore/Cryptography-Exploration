#include "EllipticCurve.hpp"

WeirrstrassCurve::WeirrstrassCurve(const BIGNUM* a, const BIGNUM* b){
    a_ = BN_new();
    BN_copy(a_, a);
    b_ = BN_new();
    BN_copy(b_, b);
    origin_ = Point();
}

void WeirrstrassCurve::deleteCurve(){
    BN_clear_free(a_);
    BN_clear_free(b_);
    origin_.deletePoint();
}

std::string WeirrstrassCurve::toString(){
    std::string result = std::string("y^2 = x^2 + ");
    result.append(BN_bn2hex(a_));
    result.append(" x + ");
    result.append(BN_bn2hex(b_));
}

void WeirrstrassCurve::printCurveDetails(){
    printf("This is a weirstrass curve with the equation %s\n", toString());
}