add_executable(Hash_app src/main.cpp)

add_library(Hash_lib)

target_include_directories(Hash_lib
    PUBLIC
        include/
)

target_sources(Hash_lib
    PRIVATE
        src/SHA224.cpp
        src/SHA256.cpp
        src/SHA1.cpp
        src/SHA_32bit.cpp
        src/SHA_64bit.cpp
        src/SHA512_224.cpp
        src/SHA512_256.cpp
        src/SHA512.cpp
        src/SHA384.cpp
        src/CreateHashDigest.cpp
        )

target_link_libraries(Hash_app
    PRIVATE 
        Hash_lib
        )   