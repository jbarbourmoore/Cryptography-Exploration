#include "Point.hpp"

Point::Point(){
    x_ = BN_new();
    BN_set_word(x_, 0);
    y_ = BN_new();
    BN_set_word(y_, 0);
}

Point::Point(const BIGNUM *x, const BIGNUM *y){
    x_ = BN_new();
    BN_copy(x_, x);
    y_ = BN_new();
    BN_copy(y_, y);
}

Point::Point(std::string hex_x, std::string hex_y){
    x_ = BN_new();
    BN_hex2bn(&x_, hex_x.c_str());
    y_ = BN_new();
    BN_hex2bn(&y_, hex_y.c_str());
}

Point::Point(const Point &point){
    x_ = BN_new();
    BN_copy(x_, point.x_);
    y_ = BN_new();
    BN_copy(y_, point.y_);
}

Point Point::getPointFromDecimalStrings(std::string x_dec, std::string y_dec){
    BIGNUM *x = BN_new();
    BN_dec2bn(&x, x_dec.c_str());
    BIGNUM *y = BN_new();
    BN_dec2bn(&y, y_dec.c_str());
    Point point = Point(x, y);
    BN_clear_free(x);
    BN_clear_free(y);
    return point;
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
    printf("%s\n", toString().c_str());
}

BIGNUM* Point::getYAsBN(){
    return y_;
}

BIGNUM* Point::getXAsBN(){
    return x_;
}

bool Point::operator==(const Point &input) const{
    int x_comp = BN_cmp(x_, input.x_);
    int y_comp = BN_cmp(y_, input.y_);
    
    bool result = x_comp == 0 && y_comp == 0;
    return result;
}

std::string Point::getXAsHexStr(){
    std::string result = std::string(BN_bn2hex(x_));
    return result;
}

std::string Point::getYAsHexStr(){
    std::string result = std::string(BN_bn2hex(y_));
    return result;
}