cmake_minimum_required(VERSION 3.26)
project(WireWhale)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

include_directories(
        ${PROJECT_SOURCE_DIR}/include
        ${PROJECT_SOURCE_DIR}/src/headers
)

find_package(Qt5 COMPONENTS
        Core
        Gui
        Widgets
        REQUIRED)

add_executable(WireWhale
        src/main.cpp
        src/main_window.cpp
        src/headers/main_window.h
        src/forms/main_window.ui
        res/res.qrc
        src/multithread.cpp src/headers/multithread.h src/headers/format.h src/data_unit.cpp src/headers/data_unit.h src/headers/delegate.h)
target_link_libraries(WireWhale
        Qt5::Core
        Qt5::Gui
        Qt5::Widgets
        pcap
        )


