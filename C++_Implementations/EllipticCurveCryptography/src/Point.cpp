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

std::string Point::toString(){
    std::string output = std::string("(");
    output.append(BN_bn2hex(x_));
    output.append(", ");
    output.append(BN_bn2hex(y_));
    output.append(")");
    return output;
}

void Point::print(){
    printf("%s\n", toString());
}

BIGNUM* Point::getY(){
    return y_;
}

BIGNUM* Point::getX(){
    return x_;
}