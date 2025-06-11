#ifndef Point_HPP
#define Point_HPP
#include <openssl/bn.h>
#include <cstdio>
#include <string>

class Point{
    private:
        BIGNUM *x_;
        BIGNUM *y_;

    public:
        /// @brief This method instantiates a point with cordinates 0,0
        Point();

        /// @brief This method instantiates a point with the given x and y coordinates
        /// @param x The x coordinate for the point
        /// @param y The y coordinate for the point
        Point(BIGNUM *x, BIGNUM *y);

        /// @brief This method returns the value of x for the point
        /// @return The BIGNUM containing X
        BIGNUM* getX();

        /// @brief This method returns the value of y for the point
        /// @return The BIGNUM containing Y
        BIGNUM* getY();

        /// @brief This method prints the point to the console
        void print();

        /// @brief This method returns a string containg the point as hexadecimal values
        /// @return (X,Y) of the point as hexadecimal strings
        std::string toString();
};

#endif