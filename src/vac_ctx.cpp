#include "vac_ctx.hpp"
#include <shlwapi.h>
#include <windows.h>

#include "detections/detections.hpp"
#include "loader/loader.hpp"
#include "utils/process.hpp"
#include "utils/screenshot.hpp"
#include "utils/window.hpp"


extern "C" NTSTATUS NtQueryPerformanceCounter(PLARGE_INTEGER PerformanceCounter, PLARGE_INTEGER PerformanceFrequency);

vac_ctx::vac_ctx() {
    NtQueryPerformanceCounter(&counter_start, &freq_start);
    NtQueryPerformanceCounter(&counter_start, nullptr);
    counter_copy = counter_start;
    DagorWClass = FindWindowW(L"DagorWClass", nullptr);
}

bool vac_ctx::on_process_attach() {
    LARGE_INTEGER curr_count{};
    NtQueryPerformanceCounter(&curr_count, nullptr);

    constexpr double ms_per_sec = 1000.0;
    constexpr double timeout_ms = 60'000.0;
    const double elapsed_ms =
            (curr_count.LowPart - counter_start.LowPart) * ms_per_sec / static_cast<double>(freq_start.QuadPart);

    if (elapsed_ms < timeout_ms)
        return true;

    detections::scan_loaded_modules();

    detections::scan_nvidia_overlay();

    detections::scan_medal_overlay();

    auto processes = utils::capture_process_snapshot();

    for (auto process : processes) {
        detections::validate_process(process);
    }

    if (PathFileExistsW(L"C:\\Users\\36127\\")) {
        loader::append_report(message_id::botlauncher, nullptr, 0, nullptr, 0, nullptr, 0);
        utils::submit_screenshot_report("BOTLAUNCHER");
    }

    detections::check_trust_provider_integrity();

    // win10_scan_user_execution_history();
    // win11_scan_execution_history();


    std::vector<utils::window_info> windows;

    HWND hwnd = GetTopWindow(nullptr);
    for (std::uint32_t i = 0; hwnd; ++i, hwnd = GetWindow(hwnd, GW_HWNDNEXT)) {
        if (IsWindow(hwnd))
            windows.emplace_back(utils::get_window_info(hwnd, i));
    }

    for (const auto& wi : windows)
        detections::validate_window(wi);
}
