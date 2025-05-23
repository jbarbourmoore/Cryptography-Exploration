add_executable(AES_Tests)

target_sources(AES_Tests 
    PRIVATE 
        src/AESStateTests.cpp
        src/AESKeyExpansionTests.cpp
        )

target_link_libraries(AES_Tests 
    PRIVATE 
        GTest::gtest_main 
        AES_lib
)

gtest_discover_tests(AES_Tests)
