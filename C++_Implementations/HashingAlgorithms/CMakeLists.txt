add_executable(Hash_app src/main.cpp)

target_include_directories(Hash_app
    PUBLIC
        include/
)

target_sources(Hash_app
    PRIVATE
        src/SHA1.cpp
        src/SHA256.cpp
        src/main.cpp
)

target_link_libraries(Hash_app
        IOHelpers_lib)

add_library(Hash_lib)

target_include_directories(Hash_lib
    PUBLIC
        include/
)

target_sources(Hash_lib
    PRIVATE
        src/SHA256.cpp
        src/SHA1.cpp
)
    
target_link_libraries(Hash_lib
        IOHelpers_lib)