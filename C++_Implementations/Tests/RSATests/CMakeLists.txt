add_executable(RSA_Tests)

target_sources(RSA_Tests 
    PRIVATE 
        src/EncryptionPrimitiveTests.cpp)

target_link_libraries(RSA_Tests 
    PRIVATE 
        GTest::gtest_main 
        RSA_lib
        BigNumHelpers_lib
)

gtest_discover_tests(RSA_Tests)
