add_executable(ECC_Tests)

target_sources(ECC_Tests 
    PRIVATE 
        src/PointTests.cpp
        src/WeirrstrassCurveTests.cpp
        src/ECDSATests.cpp
        )

target_link_libraries(ECC_Tests 
    PRIVATE 
        GTest::gtest_main 
        ECC_lib
)

gtest_discover_tests(ECC_Tests)
