#include "EdwardsCurve.hpp"

EdwardsCurve::EdwardsCurve(){
    a_ = BN_new();
    d_ = BN_new();
    finite_field_ = BN_new();
    origin_ = Point();
    g_ = Point();
}

EdwardsCurve::EdwardsCurve(const BIGNUM* a, const BIGNUM* d, const BIGNUM* finite_field, const BIGNUM* gx, const BIGNUM* gy){
    a_ = BN_new();
    BN_copy(a_, a);
    d_ = BN_new();
    BN_copy(d_, d);
    finite_field_ = BN_new();
    BN_copy(finite_field_, finite_field);
    origin_ = Point();
    g_ = Point(gx, gy);
}

EdwardsCurve::EdwardsCurve(std::string a_hex, std::string d_hex, std::string finite_field_hex, std::string gx_hex, std::string gy_hex, std::string n_hex){
    a_ = BN_new();
    BN_hex2bn(&a_, a_hex.c_str());
    d_ = BN_new();
    BN_hex2bn(&d_, d_hex.c_str());
    finite_field_ = BN_new();
    BN_hex2bn(&finite_field_, finite_field_hex.c_str());
    origin_ = Point();
    g_ = Point(gx_hex, gy_hex);
    n_ = BN_new();
    BN_hex2bn(&n_, n_hex.c_str());
}

void EdwardsCurve::deleteCurve(){
    BN_clear_free(a_);
    BN_clear_free(d_);
    BN_clear_free(finite_field_);
    origin_.deletePoint();
    g_.deletePoint();
    BN_clear_free(n_);
}

BIGNUM* EdwardsCurve::getN(){
    return n_;
}

Point EdwardsCurve::getG(){
    return g_;
}

std::string EdwardsCurve::getEquation(){
    std::string result = "";
    result.append(BN_bn2hex(a_));
    result.append("x^2 + y^2 = 1 + ");
    result.append(BN_bn2hex(d_));
    result.append("x^2y^2");
    return result;
}

void EdwardsCurve::printCurveDetails(){
    char* finite_field_str = BN_bn2hex(finite_field_);
    printf("This is an edwards curve with the equation %s in the finite field %s\n", getEquation().c_str(),finite_field_str);
}

bool EdwardsCurve::validatePointOnCurve(Point p){
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
            //ax^2 + y^2 = 1 + dx^2y^2
            BIGNUM* x_squared = BN_CTX_get(calc_ctx);
            BIGNUM* y_squared = BN_CTX_get(calc_ctx);            
            BIGNUM* left_side = BN_CTX_get(calc_ctx);
            BIGNUM* right_side = BN_CTX_get(calc_ctx);

            BN_mul(x_squared, x, x, calc_ctx);
            BN_mul(left_side, x_squared, a_, calc_ctx);
            BN_mul(y_squared, y, y, calc_ctx);
            BN_add(left_side, left_side, y_squared);
            calculatePositiveMod(left_side, finite_field_, calc_ctx);

            BN_mul(right_side, x_squared, y_squared, calc_ctx);
            BN_mul(right_side, d_, right_side, calc_ctx);
            BN_add_word(right_side, 1);
            calculatePositiveMod(right_side, finite_field_, calc_ctx);

            int cmp_result = BN_cmp(left_side, right_side);
            if(cmp_result == 0){
                result = true;
            }
        }
        BN_CTX_end(calc_ctx);
        BN_CTX_free(calc_ctx);
    }
    return result;
}

std::string EdwardsCurve::getFiniteFieldAsHex(){
    std::string result = std::string(BN_bn2hex(finite_field_));
    return result;
}

std::string EdwardsCurve::getAAsHex(){
    std::string result = std::string(BN_bn2hex(a_));
    return result;
}
        
std::string EdwardsCurve::getBAsHex(){
    std::string result = std::string(BN_bn2hex(d_));
    return result;
}

Point EdwardsCurve::calculatePointMultiplicationByConstant(Point p, BIGNUM* k){
    Point r;

    if (p == origin_ || BN_is_zero(k) == 1) {
        r = Point();
    } else if (BN_is_one(k) == 1){
        r = Point(p);
    } else {
        r = Point(p);
        int bit_length = BN_num_bits(k);
        // printf("bit length is %d\n", bit_length);
        for (int i = 1; i < bit_length; i ++){
            int bit_value = BN_is_bit_set(k, bit_length - i - 1);
            // printf("bit is %d\n", bit_value);
            r = calculatePointAddition(r, r);
            if(bit_value == 1){
                r = calculatePointAddition(r, p);
            }
        }
    }
    return r;
}

Point EdwardsCurve::calculatePointInverse(Point p){
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

Point EdwardsCurve::calculatePointAddition(Point p, Point q){
    // printf("starting point addition\n");
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

            BIGNUM *xp_yq = BN_CTX_get(calc_ctx);
            BIGNUM *yp_yq = BN_CTX_get(calc_ctx);

            BIGNUM* d_xp_xq_yp_yq = BN_CTX_get(calc_ctx);

            BIGNUM *x_r = BN_CTX_get(calc_ctx);
            BIGNUM *x_r_d = BN_CTX_get(calc_ctx);
            BIGNUM *y_r = BN_CTX_get(calc_ctx);
            BIGNUM *y_r_d = BN_CTX_get(calc_ctx);

            BN_copy(x_p, p.getXAsBN());
            BN_copy(y_p, p.getYAsBN());
            BN_copy(x_q, q.getXAsBN());
            BN_copy(y_q, q.getYAsBN());

            BN_mul(xp_yq, x_p, y_q, calc_ctx);
            BN_mul(x_r, x_q, y_p, calc_ctx);
            BN_add(x_r, x_r, xp_yq);

            BN_mul(d_xp_xq_yp_yq, x_p, x_q, calc_ctx);
            BN_mul(d_xp_xq_yp_yq, d_xp_xq_yp_yq, y_p, calc_ctx);
            BN_mul(d_xp_xq_yp_yq, d_xp_xq_yp_yq, y_q, calc_ctx);
            BN_mul(d_xp_xq_yp_yq, d_xp_xq_yp_yq, d_, calc_ctx);

            BN_copy(x_r_d, d_xp_xq_yp_yq);
            BN_add_word(x_r_d, 1);
            BN_mod_inverse(x_r_d, x_r_d, finite_field_, calc_ctx);
            BN_mul(x_r, x_r, x_r_d, calc_ctx);
            calculatePositiveMod(x_r, finite_field_, calc_ctx);

            BN_mul(yp_yq, y_p, y_q, calc_ctx);
            BN_mul(y_r, x_p, x_q, calc_ctx);
            BN_add(y_r, y_r, yp_yq);

            BN_set_word(y_r_d, 1);
            BN_sub(y_r_d, y_r_d, d_xp_xq_yp_yq);
            BN_mod_inverse(y_r_d, y_r_d, finite_field_, calc_ctx);
            BN_mul(y_r, y_r, y_r_d, calc_ctx);
            calculatePositiveMod(y_r, finite_field_, calc_ctx);
            
            Point potential = Point(x_r, y_r);
            // printf("x_r = %s\n", BN_bn2dec(x_r));
            // printf("y_r = %s\n", BN_bn2dec(y_r));
            if(validatePointOnCurve(potential)){
                point = potential;
            }

            BN_CTX_end(calc_ctx);
            BN_CTX_free(calc_ctx);
        }
    }
    return point;
}

class edwards25519 : public EdwardsCurve{
    public  : 
        edwards25519() : EdwardsCurve(
            "-1",   // a (x coefficient)
            "52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3",   // d (y coefficient)
            "1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED",   // p (finite field)
            "216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a",   // g_x (The x coordinate of the generator point)
            "6666666666666666666666666666666666666666666666666666666666666658",   // g_y (The y coordinate of the generator point)
            "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED"   // n (The order of the curve)
        ){};
};