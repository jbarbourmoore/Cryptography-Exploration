#include "Point.hpp"

Point::Point(){
    x_ = BN_new();
    BN_set_word(x_, 0);
    y_ = BN_new();
    BN_set_word(y_, 0);
}

Point::Point(BIGNUM *x, BIGNUM *y){
    x_ = BN_new();
    BN_copy(x_, x);
    y_ = BN_new();
    BN_copy(y_, y);
}

void Point::deletePoint(){
    BN_clear_free(x_);
    BN_clear_free(y_);
}