#ifndef SCREENSHOT_HPP
#define SCREENSHOT_HPP

#include <cstdint>
#include <vector>
#include <string>
#include <windows.h>

namespace utils {
    std::vector<std::uint8_t> capture_primary_monitor_dxgi();
    std::vector<std::uint8_t> capture_game_monitor_gdi(HWND target_window = nullptr);
    void submit_screenshot_report(const std::string& reason);

} // namespace utils


#endif // SCREENSHOT_HPP
