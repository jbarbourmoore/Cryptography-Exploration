add_executable(AES_app src/main.cpp)

add_library(AES_lib)

target_include_directories(AES_lib
    PUBLIC
        include/
)

target_sources(AES_lib
    PRIVATE
        src/AES.cpp
        src/AESConstants.cpp
        )

target_link_libraries(AES_app
    PRIVATE 
        AES_lib
        )   