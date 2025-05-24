add_executable(AES_app src/main.cpp)

add_library(AES_lib)

target_include_directories(AES_lib
    PUBLIC
        include/
        include/Modes/
)

target_sources(AES_lib
    PRIVATE
        src/AESState.cpp
        src/AESConstants.cpp
        src/AESKey.cpp
        src/AES.cpp
        src/AESWord.cpp
        src/AESDataBlock.cpp
        src/Modes/AES_ECB.cpp
        src/Modes/AES_CBC.cpp
        src/Modes/AES_CFB.cpp
        src/Modes/AES_OFB.cpp
        )

target_link_libraries(AES_app
    PRIVATE 
        AES_lib
        )   