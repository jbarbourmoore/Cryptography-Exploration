add_executable(RSA_Tests)

target_sources(RSA_Tests 
    PRIVATE 
        src/EncryptionPrimitiveTests.cpp
        src/KeyGenTests_ProbablyPrime.cpp
        src/KeyGenTests_ProbablyPrimeProvAux.cpp
        src/KeyGenTests_ProbablyPrimeProbAux.cpp
        src/KeyGenTests_ProvablyPrime.cpp
        src/KeyGenTests_ProvablyPrimeProvAux.cpp
        )

target_link_libraries(RSA_Tests 
    PRIVATE 
        GTest::gtest_main 
        RSA_lib
)

gtest_discover_tests(RSA_Tests)
