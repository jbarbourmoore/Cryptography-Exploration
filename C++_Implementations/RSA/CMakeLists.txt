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
)

target_link_libraries(RSA_app
        OpenSSL::SSL)

