add_library(BigNumHelpers_lib)

target_include_directories(BigNumHelpers_lib
    PUBLIC
        include/
)

target_sources(BigNumHelpers_lib
    PRIVATE
        src/BigNumXOR.cpp
        src/BigNumHash.cpp
        src/BigNumGCDMin1.cpp
        src/BigNumToLongLong.cpp
        src/BigNumPrimeSieve.cpp
        src/BigNumPrimalityTests.cpp
        src/BigNumHandler.cpp
)

target_link_libraries(BigNumHelpers_lib
        OpenSSL::SSL
        Hash_lib
        )

add_library(IOHelpers_lib)

target_include_directories(IOHelpers_lib
    PUBLIC
        include/
)

target_sources(IOHelpers_lib
    PRIVATE
        src/CSVWriter.cpp
)