cmake_minimum_required(VERSION 3.30)
project(anticheat LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


add_executable(anticheat
        main.cpp
        src/start.cpp
        loader/loader.cpp
        src/main_class.cpp
)

target_link_libraries(anticheat PRIVATE
        ntdll
)