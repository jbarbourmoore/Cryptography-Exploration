set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets)
set(CMAKE_AUTOUIC_SEARCH_PATHS include/)
set(CMAKE_AUTOUIC_SEARCH_PATHS resources/)

set(PROJECT_SOURCES
        src/main.cpp
        src/mainwindow.cpp
        include/mainwindow.h
        resources/mainwindow.ui
        resources/resources.qrc
)

if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    qt_add_executable(QT_GUI_Cryptography
        MANUAL_FINALIZATION
        ${PROJECT_SOURCES}
    )
else()
    if(ANDROID)
        add_library(QT_GUI_Cryptography SHARED
            ${PROJECT_SOURCES}
        )
    else()
        add_executable(QT_GUI_Cryptography
            ${PROJECT_SOURCES}
        )
    endif()
endif()

target_include_directories(QT_GUI_Cryptography
    PUBLIC
        include/
        resources/
)

target_link_libraries(QT_GUI_Cryptography 
                            PRIVATE 
                                Qt${QT_VERSION_MAJOR}::Widgets
                                RSA_lib
                                Hash_lib
                                AES_lib)

if(${QT_VERSION} VERSION_LESS 6.1.0)
  set(BUNDLE_ID_OPTION MACOSX_BUNDLE_GUI_IDENTIFIER com.example.QT_GUI_Cryptography)
endif()

set_target_properties(QT_GUI_Cryptography PROPERTIES
    ${BUNDLE_ID_OPTION}
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

include(GNUInstallDirs)
install(TARGETS QT_GUI_Cryptography
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

if(QT_VERSION_MAJOR EQUAL 6)
    qt_finalize_executable(QT_GUI_Cryptography)
endif()
