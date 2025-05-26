#include "GCMBlock.hpp"

#include <gtest/gtest.h>  
#include <cstdio>

TEST(GCMBlock_Tests, print_test){

    GCMBlock block = GCMBlock("00ffab");
    
    block.print();
}