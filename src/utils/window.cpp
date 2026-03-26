#include "window.hpp"

#include <cstring>

#include "process.hpp"
#include "string.hpp"

#include <format>
#include <windows.h>
#include <winternl.h>

namespace utils {
  window_info::window_info(HWND hwnd, const std::vector<process_info>& processes) :
      process(), window_handle(hwnd), pid(0), tid(0), display_affinity(0), wi() {
    tid = GetWindowThreadProcessId(hwnd, &pid);

    if (pid) {
      if (const auto it = std::ranges::find_if(
                  processes,
                  [&](const process_info& p) {
                    return p.pid == pid;
                  }
          );
          it != processes.end())
        process = *it;
    }

    std::array<wchar_t, 1024> buf{};
    if (InternalGetWindowText(hwnd, buf.data(), buf.size()))
      window_text = std::wstring(buf.data(), buf.size());

    std::memset(buf.data(), 0, sizeof(buf));
    if (GetClassNameW(hwnd, buf.data(), buf.size()))
      class_name = std::wstring(buf.data(), buf.size());

    wi.cbSize = sizeof(WINDOWINFO);
    GetWindowInfo(hwnd, &wi);

    client_width = wi.rcClient.right - wi.rcClient.left;
    client_height = wi.rcClient.bottom - wi.rcClient.top;
    win_width = wi.rcWindow.right - wi.rcWindow.left;
    win_height = wi.rcWindow.bottom - wi.rcWindow.top;

    GetWindowDisplayAffinity(hwnd, &display_affinity);
  }

  std::string format_window_geometry_info(const window_info& window) {
    std::string result = std::format(
            "class={} text={} rcWindow=[{},{},{},{}] rcClient=[{},{},{},{}] style=0x{:X} exstyle=0x{:X}",
            wide_to_utf8(window.class_name), utils::wide_to_utf8(window.window_text), window.wi.rcWindow.left,
            window.wi.rcWindow.top, window.wi.rcWindow.right - window.wi.rcWindow.left,
            window.wi.rcWindow.bottom - window.wi.rcWindow.top, window.wi.rcClient.left, window.wi.rcClient.top,
            window.wi.rcClient.right - window.wi.rcClient.left, window.wi.rcClient.bottom - window.wi.rcClient.top,
            window.wi.dwStyle, window.wi.dwExStyle
    );

    if (window.display_affinity)
      result += std::format(" affinity={}", window.display_affinity);

    return result;
  }

  std::string format_window_process_info(const window_info& window) {
    std::string result = std::format("index=0 pid={} path='{}'", window.pid, window.process.path);

    if (window.display_affinity)
      result += std::format(" affinity={}", window.display_affinity);

    return result;
  }

  std::vector<window_info> get_windows(const std::vector<process_info>& processes) {
    std::vector<window_info> result;

    for (HWND hwnd = GetTopWindow(nullptr);; hwnd = GetWindow(hwnd, GW_HWNDNEXT)) {
      if (IsWindow(hwnd))
        result.emplace_back(hwnd, processes);
    }

    return result;
  }
} // namespace utils
