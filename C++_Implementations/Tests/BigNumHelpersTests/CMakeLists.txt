add_executable(BigNumHelpers_Tests)

target_sources(BigNumHelpers_Tests 
    PRIVATE 
        src/BigNumPrimeSieveTests.cpp
        src/BigNumXorTests.cpp
        src/BigNumHashTests.cpp
        )

target_link_libraries(BigNumHelpers_Tests 
    PRIVATE 
        GTest::gtest_main 
        BigNumHelpers_lib
)

gtest_discover_tests(BigNumHelpers_Tests)
