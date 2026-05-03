#include "../loader/loader.hpp"
#include "../utils/screenshot.hpp"
#include "../utils/string.hpp"
#include "detections.hpp"

#include <algorithm>
#include <format>

namespace detections {
  void validate_processes(const std::vector<utils::process_info>& processes) {
    const bool rust_desk_exists = std::ranges::any_of(processes, [](const utils::process_info& process) {
      return utils::str_icontains(process.name_w, L"rustdesk.exe");
    });

    const bool powershell_exists = std::ranges::any_of(processes, [](const utils::process_info& process) {
      return utils::str_icontains(process.name_w, L"powershell.exe");
    });

    if (rust_desk_exists && powershell_exists) {
      loader::append_report(message_id::rdesk, nullptr, 0, nullptr, 0, nullptr, 0);
      utils::submit_screenshot_report("RDESK");
    }


    for (const auto& process : processes) {
      const std::string formatted_process_path = std::format("(PID: {}) path={}", process.pid, process.path);
      const std::string formatted_image_size = std::format("PID: {}, Size:{}", process.pid, process.file_size);

      if (utils::str_icontains(process.name_w, L"vmconnect.exe")) {
        loader::append_report(message_id::vmware2, nullptr, 0, nullptr, 0, nullptr, 0);
        utils::submit_screenshot_report("VMWARE2");
      }

      if (utils::str_icontains(process.name_w, L"wmv2.bin")) {
        loader::append_report(message_id::war_overlay, "WarOverlay", formatted_process_path, nullptr, 0);
        utils::submit_screenshot_report("WarOverlay");
      }

      if (process.name_w.contains(L"脚本") || process.name_w.contains(L"动化")) {
        loader::append_report(message_id::china_script, "ChinaScript", formatted_process_path, nullptr, 0);
        utils::submit_screenshot_report("ChinaScript");
      }

      if (utils::str_iequals(process.name_w, L"test.exe")) {
        if (FindWindowW(nullptr, L"test")) {
          loader::append_report(message_id::test_window, "test", formatted_process_path, nullptr, 0);
          utils::submit_screenshot_report("test");
        }
      }

      if (utils::str_icontains(process.name_w, L"Air Bot")) {
        loader::append_report(message_id::air_bot, "AirBot", formatted_process_path, nullptr, 0);
        utils::submit_screenshot_report("AirBot");
      }

      if (utils::str_icontains(process.name_w, L"Farm Bot")) {
        loader::append_report(message_id::farm_bot, "FarmBot", formatted_process_path, nullptr, 0);
        utils::submit_screenshot_report("FarmBot");
      }

      if (utils::str_icontains(process.path_w, L"boosteroid") || utils::str_iequals(process.name_w, L"main.exe")) {
        constexpr std::wstring_view chinese_fellas[]{L"HongHai", L"Webzen", L"bwupdate", L"Xrelay"};

        if (std::ranges::any_of(chinese_fellas, [&process](std::wstring_view fella) -> bool {
              return utils::str_icontains(process.path_w, fella);
            })) {
          loader::append_report(message_id::ccip_main, formatted_image_size, formatted_process_path, nullptr, 0);
          utils::submit_screenshot_report("CCIP(main)");
        }
      }

      if (utils::str_iequals(process.name_w, L"hong2.exe")) {
        loader::append_report(message_id::hong2, "hong2", formatted_process_path, nullptr, 0);
        utils::submit_screenshot_report("CCIP(main)");
      }

      if (process.name_w.contains(L"投弹镜")) {
        loader::append_report(message_id::bombscope, "BOMBSCOPE", formatted_process_path, nullptr, 0);
        utils::submit_screenshot_report("BOMBSCOPE");
      }

      if (utils::str_icontains(process.name_w, L"._cache_")) {
        loader::append_report(message_id::cachebot, "CACHEBOT", formatted_process_path, nullptr, 0);
        utils::submit_screenshot_report("CACHEBOT");
      }

      if (utils::str_icontains(process.name_w, L"ccrp7")) {
        loader::append_report(message_id::ccrp7, "CCRP7", formatted_process_path, nullptr, 0);
        utils::submit_screenshot_report("CCRP7");
      }

      if (utils::str_icontains(process.name_w, L"地图测距V13.exe")) {
        loader::append_report(message_id::v13bot, "V13BOT", formatted_process_path, nullptr, 0);
        utils::submit_screenshot_report("V13BOT");
      }

      if (process.name_w.contains(L"起降刷研发")) {
        loader::append_report(message_id::takeoff_bot, "TAKEOFFBOT", formatted_process_path, nullptr, 0);
        utils::submit_screenshot_report("TAKEOFFBOT");
      }

      if (process.name_w.contains(L"通用")) {
        loader::append_report(message_id::macro1, "MACRO1", formatted_process_path, nullptr, 0);
        utils::submit_screenshot_report("MACRO1");
      }

      if (utils::str_icontains(process.name_w, L"j6.exe")) {
        loader::append_report(message_id::j6, "J6", formatted_process_path, nullptr, 0);
        utils::submit_screenshot_report("J6");
      }

      if (utils::str_icontains(process.path_w, L"\\001\\svchost.exe") ||
          utils::str_icontains(process.name_w, L"MK.exe") ||
          utils::str_icontains(process.name_w, L"Thunder_Hook.exe") ||
          (utils::str_icontains(process.name_w, L"thunder") && process.name_w.contains(L"注册"))) {
        loader::append_report(message_id::exemix, "EXEMIX", formatted_process_path, nullptr, 0);
        utils::submit_screenshot_report("EXEMIX");
      }

      detections::scan_process_for_xml_manifest(process);
    }
  }

  // NOTE: this has been removed in newer versions because we dont care
  bool check_if_scary_processes_are_running(const std::vector<utils::process_info>& processes) {
    // we dont want to do anything suspicious when these applications are actively running
    // since the user can easily see what we are trying to do
    constexpr std::string_view super_scary_processes[] = {
            "procexp.exe",
            "procexp64.exe",
            "Procmon.exe",
            "Procmon64.exe",
    };

    return std::ranges::any_of(super_scary_processes, [&](std::string_view scary_process_name) {
      return std::ranges::any_of(processes, [&](const utils::process_info& pi) {
        return utils::str_iequals(pi.name, scary_process_name);
      });
    });
  }
} // namespace detections
