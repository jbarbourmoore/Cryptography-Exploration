#include "EllipticCurve.hpp"

WeirrstrassCurve::WeirrstrassCurve(const BIGNUM* a, const BIGNUM* b, const BIGNUM* finite_field){
    a_ = BN_new();
    BN_copy(a_, a);
    b_ = BN_new();
    BN_copy(b_, b);
    finite_field_ = BN_new();
    BN_copy(finite_field_, finite_field);
    origin_ = Point();
    
}

void WeirrstrassCurve::deleteCurve(){
    BN_clear_free(a_);
    BN_clear_free(b_);
    BN_clear_free(finite_field_);
    origin_.deletePoint();
}

std::string WeirrstrassCurve::toString(){
    std::string result = std::string("y^2 = x^3 + ");
    result.append(BN_bn2hex(a_));
    result.append(" x + ");
    result.append(BN_bn2hex(b_));
}

void WeirrstrassCurve::printCurveDetails(){
    char* finite_field_str = BN_bn2hex(finite_field_);
    printf("This is a weirstrass curve with the equation %s in the finite field %s\n", toString().c_str(),finite_field_str);
}

bool WeirrstrassCurve::validatePointOnCurve(Point p){
    bool result = false;
    if (p == origin_) {
        result = true;
    } else {
        BIGNUM *x = p.getX();
        BIGNUM *y = p.getY();
        bool x_in_field = BN_cmp(x, finite_field_) == -1;
        bool y_in_field = BN_cmp(y, finite_field_) == -1;
        if (x_in_field && y_in_field) {
            BIGNUM* value = BN_new();
            BN_CTX* calc_ctx = BN_CTX_new();
            BN_CTX_start(calc_ctx);
            BN_mul(value, x, x, calc_ctx);
            
        }
    }
    return result;
}