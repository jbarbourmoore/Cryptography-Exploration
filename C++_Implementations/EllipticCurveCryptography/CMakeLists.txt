add_executable(ECC_app src/main.cpp)

add_library(ECC_lib)

target_include_directories(ECC_lib
    PUBLIC
        include/
)

target_sources(ECC_lib
    PRIVATE
        src/EllipticCurve.cpp
        src/Point.cpp
        src/WeirrstrassCurve.cpp
        )

target_link_libraries(ECC_lib
        OpenSSL::SSL)

target_link_libraries(ECC_lib
        BigNumHelpers_lib)

target_link_libraries(ECC_app
    PRIVATE 
        ECC_lib
        )   