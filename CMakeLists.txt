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
  src/utils/module.cpp

  src/detections/detections.cpp
  src/detections/present_hook.cpp
  src/detections/process_validation.cpp
  src/detections/window_validation.cpp
  src/detections/module_validation.cpp
  src/detections/memory_scan.cpp
  src/detections/developer_tools.cpp
)

#if(WIN32)
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
    uuid
  )

  if(MINGW)
    target_link_options(anticheat PRIVATE -static-libgcc -static-libstdc++ -Wl,-Bstatic,--whole-archive -lwinpthread -Wl,--no-whole-archive)
  else()
    target_link_options(anticheat PRIVATE --static -static-libstdc++)
  endif()
#endif()