#include "EllipticCurve.hpp"

WeirrstrassCurve::WeirrstrassCurve(const BIGNUM* a, const BIGNUM* b){
    a_ = BN_new();
    BN_copy(a_, a);
    b_ = BN_new();
    BN_copy(b_, b);
    origin_ = Point();
}

std::string WeirrstrassCurve::toString(){

}