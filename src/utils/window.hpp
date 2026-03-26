#ifndef WINDOW_HPP
#define WINDOW_HPP
#include <cstdint>
#include <string>
#include <windows.h>

#include "process.hpp"

namespace utils {
  struct window_info {
    process_info process;
    HWND window_handle;
    std::wstring window_text;
    std::wstring class_name;
    DWORD pid;
    DWORD tid;
    DWORD display_affinity;
    WINDOWINFO wi;
    std::int32_t win_width;
    std::int32_t win_height;
    std::int32_t client_width;
    std::int32_t client_height;

    window_info(HWND hwnd, const std::vector<process_info>& processes);
  };

  std::vector<window_info> get_windows(const std::vector<process_info>& processes);
  std::string format_window_geometry_info(const window_info& window);
  std::string format_window_process_info(const window_info& window);
} // namespace utils


#endif // WINDOW_HPP
