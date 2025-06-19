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

WeirrstrassCurve::WeirrstrassCurve(std::string a_hex, std::string b_hex, std::string finite_field_hex){
    a_ = BN_new();
    BN_hex2bn(&a_, a_hex.c_str());
    b_ = BN_new();
    BN_hex2bn(&b_, b_hex.c_str());
    finite_field_ = BN_new();
    BN_hex2bn(&finite_field_, finite_field_hex.c_str());
    origin_ = Point();
}

void WeirrstrassCurve::deleteCurve(){
    BN_clear_free(a_);
    BN_clear_free(b_);
    BN_clear_free(finite_field_);
    origin_.deletePoint();
}

std::string WeirrstrassCurve::getEquation(){
    std::string result = std::string("y^2 = x^3 + ");
    result.append(BN_bn2hex(a_));
    result.append(" x + ");
    result.append(BN_bn2hex(b_));
    return result;
}

void WeirrstrassCurve::printCurveDetails(){
    char* finite_field_str = BN_bn2hex(finite_field_);
    printf("This is a weirstrass curve with the equation %s in the finite field %s\n", getEquation().c_str(),finite_field_str);
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
            // printf("x^3 = %s\n", BN_bn2dec(x_cubed));
            BN_mul(a_x, a_, x, calc_ctx);
            // printf("a*x = %s\n", BN_bn2dec(a_x));
            BN_mul(y_squared, y, y, calc_ctx);
            // printf("y*2 = %s\n", BN_bn2dec(y_squared));
            BN_add(calculation, x_cubed, a_x);
            BN_add(calculation, calculation, b_);
            BN_sub(calculation, y_squared, calculation);
            // printf("calculation = %s\n", BN_bn2dec(calculation));
            BN_mod(calculation, calculation, finite_field_, calc_ctx);
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

std::string WeirrstrassCurve::getFiniteFieldAsHex(){
    std::string result = std::string(BN_bn2hex(finite_field_));
    return result;
}

std::string WeirrstrassCurve::getAAsHex(){
    std::string result = std::string(BN_bn2hex(a_));
    return result;
}
        
std::string WeirrstrassCurve::getBAsHex(){
    std::string result = std::string(BN_bn2hex(b_));
    return result;
}

Point WeirrstrassCurve::calculatePointMultiplicationByConstant(Point p, BIGNUM* k){
    Point r;

    if (p == origin_ || BN_is_zero(k) == 1) {
        r = Point();
    } else if (BN_is_one(k) == 1){
        r = Point(p);
    } else {
        r = Point(p);
        int bit_length = BN_num_bits(k);
        printf("bit length is %d\n", bit_length);
        for (int i = 1; i < bit_length; i ++){
            int bit_value = BN_is_bit_set(k, bit_length - i - 1);
            printf("bit is %d\n", bit_value);
            r = calculatePointAddition(r, r);
            if(bit_value == 1){
                r = calculatePointAddition(r, p);
            }
        }
    }
    return r;
}

Point WeirrstrassCurve::calculatePointInverse(Point p){
    Point point;
    if (p == origin_) {
        point = Point(origin_);
    } else {
        BN_CTX *calc_ctx = BN_CTX_new();
        BIGNUM *y_r = BN_new();
        BN_copy(y_r, p.getYAsBN());
        if(BN_is_negative(y_r) == 1){
            BN_set_negative(y_r, 0);
        } else {
            BN_set_negative(y_r, 1);
        }
        BN_mod(y_r, y_r, finite_field_, calc_ctx);
        if(BN_is_negative(y_r) == 1){
            BN_add(y_r, finite_field_, y_r);
        }
        calculatePositiveMod(y_r, finite_field_, calc_ctx);
        point = Point(p.getXAsBN(), y_r);
        BN_clear_free(y_r);
        BN_CTX_free(calc_ctx);
    }
    return point;
}

Point WeirrstrassCurve::calculatePointAddition(Point p, Point q){
    printf("starting point addition\n");
    Point point;
    if (validatePointOnCurve(p) && validatePointOnCurve(q)) {
        if(p == origin_){
            point = Point(q);
        } else if (q == origin_){
            point = Point(p);
        } else if (p == calculatePointInverse(q)) {
            point = Point(origin_);
        } else {
            BN_CTX *calc_ctx = BN_CTX_new();
            BN_CTX_start(calc_ctx);

            BIGNUM *x_p = BN_CTX_get(calc_ctx);
            BIGNUM *y_p = BN_CTX_get(calc_ctx);
            BIGNUM *x_q = BN_CTX_get(calc_ctx);
            BIGNUM *y_q = BN_CTX_get(calc_ctx);

            BIGNUM *dydx = BN_CTX_get(calc_ctx);
            BIGNUM *mod_inv = BN_CTX_get(calc_ctx);

            BIGNUM *x_r = BN_CTX_get(calc_ctx);
            BIGNUM *y_r = BN_CTX_get(calc_ctx);

            BN_copy(x_p, p.getXAsBN());
            BN_copy(y_p, p.getYAsBN());
            BN_copy(x_q, q.getXAsBN());
            BN_copy(y_q, q.getYAsBN());

            if (p == q) {
                // dydx = (3 * x_p**2 + a) * ModInv(2 * y_p, finite_field)
                BN_copy(mod_inv, y_p);
                BN_mul_word(mod_inv, 2);
                BN_mod_inverse(mod_inv, mod_inv, finite_field_, calc_ctx);
                printf("mod_inv = %s\n", BN_bn2dec(mod_inv));
                BN_mul(dydx, x_p, x_p, calc_ctx);
                BN_mul_word(dydx, 3);
                BN_add(dydx, dydx, a_);
                BN_mul(dydx, dydx, mod_inv, calc_ctx);
                
            } else {
                // dydx = (y_q - y_p) * ModInv(x_q - x_p, finite_field)
                BN_sub(mod_inv, x_q, x_p);
                BN_mod_inverse(mod_inv, mod_inv, finite_field_, calc_ctx);
                BN_sub(dydx, y_q, y_p);
                BN_mul(dydx, dydx, mod_inv, calc_ctx);
            }
            calculatePositiveMod(dydx, finite_field_, calc_ctx);
            printf("dydx = %s\n", BN_bn2dec(dydx));
            // x_r = (dydx**2 - x_p - x_q) % self.finite_field
            BN_mul(x_r, dydx, dydx, calc_ctx);
            BN_sub(x_r, x_r, x_p);
            BN_sub(x_r, x_r, x_q);
            calculatePositiveMod(x_r, finite_field_, calc_ctx);

            // y_r = (dydx * (x_p - x_r) - y_p) % finite_field
            BN_copy(y_r, x_p);
            printf("y_r = %s\n", BN_bn2dec(y_r));
            BN_sub(y_r, y_r, x_r);
            printf("y_r = %s\n", BN_bn2dec(y_r));
            BN_mul(y_r, y_r, dydx, calc_ctx);
            printf("y_r = %s\n", BN_bn2dec(y_r));
            BN_sub(y_r, y_r, y_p);
            printf("y_r = %s\n", BN_bn2dec(y_r));
            calculatePositiveMod(y_r, finite_field_, calc_ctx);
            
            Point potential = Point(x_r, y_r);
            printf("x_r = %s\n", BN_bn2dec(x_r));
            printf("y_r = %s\n", BN_bn2dec(y_r));
            if(validatePointOnCurve(potential)){
                point = potential;
            }

            BN_CTX_end(calc_ctx);
            BN_CTX_free(calc_ctx);
        }
    }
    return point;
}