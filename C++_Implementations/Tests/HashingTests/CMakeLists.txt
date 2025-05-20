add_executable(Hash_Tests)

target_sources(Hash_Tests 
    PRIVATE 
        src/SHA1_tests.cpp
        src/SHA256_tests.cpp
        src/SHA224_tests.cpp
        )

target_link_libraries(Hash_Tests 
    PRIVATE 
        GTest::gtest_main 
        Hash_lib
)

gtest_discover_tests(Hash_Tests)
