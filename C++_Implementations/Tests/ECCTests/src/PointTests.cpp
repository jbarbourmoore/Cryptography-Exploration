#include <gtest/gtest.h>  
#include <stddef.h>

#include "Point.hpp"

TEST(ECC_Tests, DefaultPointOutput) {
    Point point = Point();
    point.print();
    std::string expected = std::string("(0, 0)");
    EXPECT_EQ(expected, point.toString());
}