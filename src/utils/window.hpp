#ifndef WINDOW_HPP
#define WINDOW_HPP
#include <cstdint>
#include <string>
#include <windows.h>

namespace utils {
  struct window_info {
    HWND window_handle;
    std::wstring process_name;
    std::wstring window_text;
    std::wstring class_name;
    DWORD pid;
    DWORD tid;
    DWORD display_affinity;
    WINDOWINFO wi;
    std::uint32_t index;
    std::int32_t win_width;
    std::int32_t win_height;
    std::int32_t win_left;
    std::int32_t win_top;
    std::int32_t client_width;
    std::int32_t client_height;
    std::int32_t client_left;
    std::int32_t client_top;
    std::string image_path;
  };

  window_info get_window_info(HWND hwnd, std::uint32_t index);
  std::string format_window_geometry_info(const window_info& wi);
  std::string format_window_process_info(const window_info& wi);
} // namespace utils


#endif // WINDOW_HPP
