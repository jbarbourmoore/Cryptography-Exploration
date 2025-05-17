add_executable(RSA_app src/main.cpp)

target_include_directories(RSA_app
    PUBLIC
        include/
)

target_sources(RSA_app
    PRIVATE
        src/RSAPrivateKey.cpp
        src/RSAPublicKey.cpp
        src/main.cpp
        src/RSAKeyGeneration.cpp
        src/RSADurationTracking.cpp
        src/RSAKeyGenerationResultStructures.cpp
        src/RSAKeyGenerationProvablePrimes.cpp
        src/RSAKeyGenerationProbablePrimes.cpp
        src/RSAKeyGenerationShaweTaylorRandomPrime.cpp
)

target_link_libraries(RSA_app
        OpenSSL::SSL)

target_link_libraries(RSA_app
        BigNumHelpers_lib)

target_link_libraries(RSA_app
        IOHelpers_lib)

add_library(RSA_lib)

target_include_directories(RSA_lib
    PUBLIC
        include/
)

target_sources(RSA_lib
    PRIVATE
        src/RSAPrivateKey.cpp
        src/RSAPublicKey.cpp
        src/RSAKeyGeneration.cpp
        src/RSADurationTracking.cpp
        src/RSAKeyGenerationResultStructures.cpp
        src/RSAKeyGenerationProvablePrimes.cpp
        src/RSAKeyGenerationProbablePrimes.cpp
        src/RSAKeyGenerationShaweTaylorRandomPrime.cpp
)

target_link_libraries(RSA_lib
        OpenSSL::SSL)

target_link_libraries(RSA_lib
        BigNumHelpers_lib)
        
target_link_libraries(RSA_lib
        IOHelpers_lib)