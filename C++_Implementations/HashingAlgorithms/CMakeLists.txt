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
        )

target_link_libraries(Hash_app
    PRIVATE 
        Hash_lib
        )   