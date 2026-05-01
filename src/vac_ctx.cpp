#include "vac_ctx.hpp"

#include <algorithm>
#include <shlwapi.h>
#include <windows.h>

#include "detections/detections.hpp"
#include "loader/loader.hpp"
#include "utils/module.hpp"
#include "utils/process.hpp"
#include "utils/registry.hpp"
#include "utils/screenshot.hpp"
#include "utils/string.hpp"
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
  if (!utils::is_win10_or_greater()) {
    return false;
  }

  // exports and modules resolved by their hash manually
  HMODULE ntdll = GetModuleHandleA("ntdll.dll");
  if (ntdll) {
    USHORT process_machine{};
    USHORT native_machine{};

    if (GetProcAddress(ntdll, "wine_get_version") ||
        (IsWow64Process2(GetCurrentProcess(), &process_machine, &native_machine) &&
         native_machine == IMAGE_FILE_MACHINE_ARM64)) {
      loader::append_report(message_id::wine, "Wine", "Wine", nullptr, 0);
    }
  }

  // Not to worry, we value your privacy.
  // How do you think we figured out these paths in the first place? Take a guess :D
  std::unordered_map<std::wstring, std::vector<std::wstring>> blacklisted_paths_by_name{
          {L"BCDEV",                {L"D:\\Projects\\keRenderProj_WT\\", L"E:\\HACK_Proj\\", L"D:\\HackProjects\\"}                  },
          {L"AADEV",                {L"E:\\Projects\\ArtificialReClass\\"}                                                           },
          {L"CHDEV",                {L"E:\\Projects\\CVMV5\\"}                                                                       },
          {L"HYMER",                {L"C:\\Users\\hymer\\Desktop\\"}                                                                 },
          {L"BARKIE",               {L"C:\\Users\\Barkie\\Source\\"}                                                                 },
          {L"PR1M",                 {L"D:\\EasyCheats\\"}                                                                            },
          {L"WARMOD",               {L"C:\\Users\\Alex\\Desktop\\WM\\", L"C:\\Users\\Alex\\Desktop\\WarmodEAC\\"}                    },
          {L"VIPPROTH",             {L"C:\\Users\\L1ney\\Desktop\\"}                                                                 },
          {L"LEAN_WAREAC",          {L"D:\\PROJECT\\HAVAL\\"}                                                                        },
          {L"MASON",                {L"D:\\storage\\dumplings\\", L"C:\\Users\\Итальянец\\"}                                         },
          {L"AIMACE",               {L"C:\\Users\\taxi1\\"}                                                                          },
          {L"MIRA",                 {L"C:\\Users\\Woody\\Documents\\Проекты MS VS\\", L"C:\\Users\\xisma\\Documents\\Repositories\\"}},
          {L"CALC_NGCLIENT",        {L"D:\\Users\\a9521\\Desktop\\"}                                                                 },
          {L"CYBER",                {L"C:\\Users\\Gamzat\\source\\"}                                                                 },
          {L"oyuncusteroidi",       {L"C:\\Users\\T72\\Desktop\\"}                                                                   },
          {L"HADES",                {L"E:\\c++\\读写源码\\UC\\AA\\"}                                                                 },
          {L"OMEGA",                {L"C:\\Users\\Vanushka\\Desktop\\"}                                                              },
          {L"MONKREL",              {L"E:\\Sources LEAN\\", L"D:\\GIT\\WT_EX_2.0\\"}                                                 },
          {L"MEVAS",                {L"C:\\Users\\Mevas\\source\\repos\\"}                                                           },
          {L"despair",              {L"C:\\Users\\Administrator\\Desktop\\thunderhack\\"}                                            },
          {L"test",                 {L"F:\\war\\war-thunder-new-warehouse\\"}                                                        },
          {L"LabCore",              {L"F:\\Source Codes\\Aspect-Rust-External\\"}                                                    },
          {L"XLoader Dev??",        {L"D:\\Users\\PC\\Desktop\\xloader\\XLoader - Internal\\"}                                       },
          {L"SKRIPT.GG",            {L"C:\\Users\\poli\\Documents\\GitHub\\"}                                                        },
          {L"Iron Fury / memez.ru", {L"E:\\kd\\Valorant\\"}                                                                          },
          {L"CHOD?",                {L"E:\\WorkV5\\"}                                                                                },
          {L"BAUNTICHEATS",         {L"Z:\\VS Projects\\Baunti\\"}                                                                   },
          {L"CHOD",                 {L"C:\\Users\\Mate\\Desktop\\ReClass.NET-master\\", L"C:\\Users\\Mate\\Work\\"}                  },
          {L"i4tool",               {L"F:\\WT上线\\"}                                                                                },
          {L"ChineseCheatDev",      {L"E:\\项目\\雷霆战争\\"}                                                                        }
  };

  for (const auto& [name, paths] : blacklisted_paths_by_name) {
    for (const auto& path : paths) {
      if (PathIsDirectoryW(path.c_str())) {
        loader::append_report(
                message_id::blacklisted_paths, utils::wide_to_utf8(name), utils::wide_to_utf8(path), nullptr, 0
        );
      }
    }
  }

  // is it the first time were are running
  bool first_instance = []() {
    // created once, released never
    const HANDLE mutex = CreateMutexW(nullptr, TRUE, L"WT_MAIN_000001");
    if (!mutex)
      return false;

    if (GetLastError() == ERROR_ALREADY_EXISTS) {
      CloseHandle(mutex);
      return false;
    }

    return true;
  }();

  if (!first_instance)
    return true;

  if (detections::check_if_scary_processes_are_running(utils::get_processes())) {
    return true;
  }

  // no scary processes were found
  // we can continue our adventure through the user's files :D
  detections::check_visual_studio_projects();
  detections::check_ida_history();

  // module integrity checks (one-shot, attach-time)
  std::vector<utils::module_info> modules = utils::get_modules();
  detections::check_module_image_size_mismatch(modules);
  detections::check_hash_integrity();
  detections::scan_self_process_memory_for_imgui();

  return true;
}

bool vac_ctx::on_thread_attach() {
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

  // void scan_shimcache_execution_history();
  // void scan_compat_assistant_execution_history();


  NtQueryPerformanceCounter(&end_time, nullptr);
  return false;
}
