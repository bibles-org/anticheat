#include "window.hpp"
#include "process.hpp"

#include <format>
#include <windows.h>
#include <winternl.h>

namespace utils {
    window_info get_window_info(HWND hwnd, std::uint32_t index) {
        window_info wi = {};
        wi.window_handle = hwnd;
        wi.index = index;

        wi.pid = 0;
        wi.tid = GetWindowThreadProcessId(hwnd, &wi.pid);

        wi.process_name = "EMPTY";
        if (wi.pid) {
            auto snapshot = utils::capture_process_snapshot();
            const auto it = std::ranges::find_if(snapshot, [&](const SYSTEM_PROCESS_INFORMATION& p) {
                return p.UniqueProcessId == reinterpret_cast<HANDLE>(wi.pid);
            });

            if (it != snapshot.end() && it->ImageName.Buffer)
                wi.process_name = std::string(
                        it->ImageName.Buffer, it->ImageName.Buffer + it->ImageName.Length / sizeof(wchar_t)
                );
        }
        wi.window_text = "EMPTY";
        wchar_t window_text_buf[260] = {};
        if (InternalGetWindowText(hwnd, window_text_buf, 260))
            wi.window_text = std::string(window_text_buf, window_text_buf + wcslen(window_text_buf));

        wi.class_name = "EMPTY";
        wchar_t class_name_buf[260] = {};
        if (GetClassNameW(hwnd, class_name_buf, 260))
            wi.class_name = std::string(class_name_buf, class_name_buf + wcslen(class_name_buf));

        wi.wi.cbSize = sizeof(WINDOWINFO);
        GetWindowInfo(hwnd, &wi.wi);

        wi.display_affinity = 0;
        GetWindowDisplayAffinity(hwnd, &wi.display_affinity);

        wi.win_left = wi.wi.rcClient.left;
        wi.win_top = wi.wi.rcClient.top;
        wi.win_width = wi.wi.rcClient.right - wi.wi.rcClient.left;
        wi.win_height = wi.wi.rcClient.bottom - wi.wi.rcClient.top;

        wi.client_left = wi.wi.rcWindow.left;
        wi.client_top = wi.wi.rcWindow.top;
        wi.client_width = wi.wi.rcWindow.right - wi.wi.rcWindow.left;
        wi.client_height = wi.wi.rcWindow.bottom - wi.wi.rcWindow.top;

        return wi;
    }

    std::string format_window_process_info(const window_info& wi) {
        return std::format(
                "pid={} tid={} process={} affinity=0x{:x} style=0x{:x} exstyle=0x{:x}", wi.pid, wi.tid, wi.process_name,
                wi.display_affinity, wi.wi.dwStyle, wi.wi.dwExStyle
        );
    }

    std::string format_window_geometry_info(const window_info& wi) {
        return std::format(
                "hwnd={} class={} text={} win=[left={},top={},width={},height={}] "
                "client=[left={},top={},width={},height={}] index={}",
                reinterpret_cast<std::uintptr_t>(wi.window_handle), wi.class_name, wi.window_text, wi.win_left,
                wi.win_top, wi.win_width, wi.win_height, wi.client_left, wi.client_top, wi.client_width,
                wi.client_height, wi.index
        );
    }
} // namespace utils
