enable_testing()

include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.14.0
)

set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

include(GoogleTest)

add_subdirectory(RSATests)
add_subdirectory(BigNumHelpersTests)
add_subdirectory(HashingTests)
add_subdirectory(AESTests)
add_subdirectory(ECCTests)