add_library(BigNumHelpers_lib src/BigNumXOR.cpp)

target_include_directories(BigNumHelpers_lib
    PUBLIC
        include/
)

target_sources(BigNumHelpers_lib
    PRIVATE
        src/BigNumXOR.cpp
        src/BigNumHash.cpp
)

target_link_libraries(BigNumHelpers_lib
        OpenSSL::SSL)

