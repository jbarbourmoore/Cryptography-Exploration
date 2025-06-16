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
        BN_CTX* calc_ctx = BN_CTX_new();
        BN_CTX_start(calc_ctx);
        BIGNUM *x = BN_CTX_get(calc_ctx);
        BIGNUM *y = BN_CTX_get(calc_ctx);
        BN_copy(x, p.getXAsBN());
        BN_copy(y, p.getYAsBN());
        bool x_in_field = BN_cmp(x, finite_field_) == -1;
        bool y_in_field = BN_cmp(y, finite_field_) == -1;
        if (x_in_field && y_in_field) {
            BIGNUM* x_cubed = BN_CTX_get(calc_ctx);
            BIGNUM* a_x = BN_CTX_get(calc_ctx);
            BIGNUM* y_squared = BN_CTX_get(calc_ctx);
            BIGNUM* calculation = BN_CTX_get(calc_ctx);
            BN_mul(x_cubed, x, x, calc_ctx);
            BN_mul(x_cubed, x, x_cubed, calc_ctx);
            BN_mul(a_x, a_, x, calc_ctx);
            BN_mul(y_squared, y, y, calc_ctx);
            BN_add(calculation, x_cubed, a_x);
            BN_add(calculation, calculation, b_);
            BN_sub(calculation, y_squared, calculation);
            BN_mod(calculation, finite_field_, calculation, calc_ctx);
            int is_zero = BN_is_zero(calculation);
            if(is_zero == 1){
                result = true;
            }
        }
        BN_CTX_end(calc_ctx);
        BN_CTX_free(calc_ctx);
    }
    return result;
}