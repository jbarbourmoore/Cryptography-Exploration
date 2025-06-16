#ifndef Point_HPP
#define Point_HPP
#include <openssl/bn.h>
#include <cstdio>
#include <string>

class Point{
    private:
        /// @brief The x coordinate of the point
        BIGNUM *x_;

        /// @brief The y coordinate of the point
        BIGNUM *y_;

    public:
        /// @brief This method instantiates a point with cordinates 0,0
        Point();

        /// @brief This method instantiates a point with the given x and y coordinates
        /// @param x The x coordinate for the point
        /// @param y The y coordinate for the point
        Point(BIGNUM *x, BIGNUM *y);

        Point(std::string hex_x, std::string hex_y);

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

        /// @brief This method cleans up the bignums used for this point
        void deletePoint();

        /// @brief This method overrides the == operator in order to compare two points
        /// @param input The other point that it is being compared to
        /// @return True if the two points are the same;
        bool operator==(const Point &input);
};

#endif