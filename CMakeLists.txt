cmake_minimum_required(VERSION 3.30)
project(anticheat LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(anticheat
        src/main.cpp
        src/loader/loader.cpp
        src/vac_ctx.cpp

        src/utils/file.cpp
        src/utils/process.cpp
        src/utils/screenshot.cpp
        src/utils/window.cpp
        src/utils/registry.cpp
        src/utils/string.cpp

        src/detections/detections.cpp
)

target_link_libraries(anticheat PRIVATE
        d3d11
        dxgi
        ole32
        oleaut32
        windowscodecs
        gdiplus
        gdi32
        ntdll
        shlwapi
)

target_link_options(anticheat PRIVATE --static -static-libstdc++)