add_executable(RSA_Tests)

target_sources(RSA_Tests 
    PRIVATE 
        src/EncryptionPrimitiveTests.cpp
        src/KeyGenerationTests.cpp
        )

target_link_libraries(RSA_Tests 
    PRIVATE 
        GTest::gtest_main 
        RSA_lib
)

gtest_discover_tests(RSA_Tests)
