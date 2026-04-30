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
  NtQueryPerformanceCounter(&begin_time, &counter_freq);
  NtQueryPerformanceCounter(&begin_time, nullptr);
  end_time = begin_time;
  dagor_window_handle = FindWindowW(L"DagorWClass", nullptr);
}

vac_ctx::~vac_ctx() {
  NtQueryPerformanceCounter(&end_time, nullptr);
}

bool vac_ctx::on_process_attach() {
  LARGE_INTEGER curr_time{};
  NtQueryPerformanceCounter(&curr_time, nullptr);

  constexpr double ms_per_sec = 1000.0;
  constexpr double timeout_ms = 60'000.0;
  const double elapsed_ms =
          (curr_time.LowPart - begin_time.LowPart) * ms_per_sec / static_cast<double>(counter_freq.QuadPart);

  if (elapsed_ms < timeout_ms)
    return true;


  std::vector<utils::module_info> modules = utils::get_modules();
  std::vector<utils::process_info> processes = utils::get_processes();
  std::vector<utils::window_info> windows = utils::get_windows(processes);

  detections::check_present_hook(modules);
  detections::validate_modules(modules);
  detections::validate_processes(processes);
  detections::validate_windows(windows);

  if (PathFileExistsW(L"C:\\Users\\36127\\")) {
    loader::append_report(message_id::botlauncher, nullptr, 0, nullptr, 0, nullptr, 0);
    utils::submit_screenshot_report("BOTLAUNCHER");
  }

  detections::check_sip_hijack_and_appinit_injection();

  //void scan_shimcache_execution_history();
  //void scan_compat_assistant_execution_history();


  NtQueryPerformanceCounter(&end_time, nullptr);
  return false;
}
