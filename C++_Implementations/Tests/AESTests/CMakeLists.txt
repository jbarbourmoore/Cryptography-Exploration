add_executable(AES_Tests)

target_sources(AES_Tests 
    PRIVATE 
        src/AESStateTests.cpp
        src/AESKeyExpansionTests.cpp
        src/AESCypherTests.cpp
        src/AESDataBlockTests.cpp
        src/ModesTests/AES_ECBTests.cpp
        src/ModesTests/AES_CBCTests.cpp
        src/ModesTests/AES_CFBTests.cpp
        src/ModesTests/AES_OFBTests.cpp
        src/ModesTests/AES_CTRTests.cpp
        src/ModesTests/AES_GCMTests.cpp
        src/ModesTests/GCMBlockTests.cpp
        )

target_link_libraries(AES_Tests 
    PRIVATE 
        GTest::gtest_main 
        AES_lib
)

gtest_discover_tests(AES_Tests)
