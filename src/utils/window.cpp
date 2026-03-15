#include "window.hpp"

#include <cstring>

#include "process.hpp"
#include "string.hpp"

#include <format>
#include <windows.h>
#include <winternl.h>

namespace utils {
  window_info get_window_info(HWND hwnd, std::uint32_t index) {
    window_info wi{};
    wi.window_handle = hwnd;
    wi.index = index;

    wi.tid = GetWindowThreadProcessId(hwnd, &wi.pid);

    wi.process_name = L"EMPTY";
    if (wi.pid) {
      wi.image_path = utils::wide_to_utf8(utils::get_process_image_path(wi.pid));
      auto snapshot = utils::capture_process_snapshot();
      const auto it = std::ranges::find_if(snapshot, [&](const SYSTEM_PROCESS_INFORMATION& p) {
        return p.UniqueProcessId == reinterpret_cast<HANDLE>(wi.pid);
      });

      if (it != snapshot.end() && it->ImageName.Buffer) {
        wi.process_name = std::wstring(it->ImageName.Buffer, it->ImageName.Length / sizeof(wchar_t));
      }
    }

    wchar_t temp_buf[512]{};
    wi.window_text = L"EMPTY";
    if (InternalGetWindowText(hwnd, temp_buf, std::size(temp_buf)))
      wi.window_text = temp_buf;

    std::memset(temp_buf, 0, sizeof(temp_buf));
    wi.class_name = L"EMPTY";
    if (GetClassNameW(hwnd, temp_buf, std::size(temp_buf)))
      wi.class_name = temp_buf;

    wi.wi.cbSize = sizeof(WINDOWINFO);
    GetWindowInfo(hwnd, &wi.wi);

    wi.display_affinity = 0;
    GetWindowDisplayAffinity(hwnd, &wi.display_affinity);

    wi.client_left = wi.wi.rcClient.left;
    wi.client_top = wi.wi.rcClient.top;
    wi.client_width = wi.wi.rcClient.right - wi.wi.rcClient.left;
    wi.client_height = wi.wi.rcClient.bottom - wi.wi.rcClient.top;

    wi.win_left = wi.wi.rcWindow.left;
    wi.win_top = wi.wi.rcWindow.top;
    wi.win_width = wi.wi.rcWindow.right - wi.wi.rcWindow.left;
    wi.win_height = wi.wi.rcWindow.bottom - wi.wi.rcWindow.top;

    return wi;
  }

  std::string format_window_geometry_info(const window_info& wi) {
    std::string result = std::format(
            "class={} text={} rcWindow=[{},{},{},{}] rcClient=[{},{},{},{}] style=0x{:X} exstyle=0x{:X}", wi.class_name,
            wi.window_text, wi.wi.rcWindow.left, wi.wi.rcWindow.top, wi.wi.rcWindow.right - wi.wi.rcWindow.left,
            wi.wi.rcWindow.bottom - wi.wi.rcWindow.top, wi.wi.rcClient.left, wi.wi.rcClient.top,
            wi.wi.rcClient.right - wi.wi.rcClient.left, wi.wi.rcClient.bottom - wi.wi.rcClient.top, wi.wi.dwStyle,
            wi.wi.dwExStyle
    );

    if (wi.display_affinity)
      result += std::format(" affinity={}", wi.display_affinity);

    return result;
  }

  std::string format_window_process_info(const window_info& wi) {
    std::string result = std::format("index={} pid={} path='{}'", wi.index, wi.pid, wi.image_path);

    if (wi.display_affinity)
      result += std::format(" affinity={}", wi.display_affinity);

    return result;
  }
} // namespace utils
