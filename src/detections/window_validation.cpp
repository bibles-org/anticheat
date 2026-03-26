#include "../loader/loader.hpp"
#include "../utils/screenshot.hpp"
#include "../utils/string.hpp"
#include "detections.hpp"

#include <algorithm>

namespace detections {
  // unfinished
  void validate_windows(const std::vector<utils::window_info>& windows) {
    std::pair screen_size{GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN)};

    for (const auto& window : windows) {
      const auto window_process_info = utils::format_window_process_info(window);
      const auto window_geometry_info = utils::format_window_geometry_info(window);


      if (window.class_name == L"CEF-OSC-WIDGET" && window.window_text == L"NVIDIA GeForce Overlay") {
        if (window.wi.dwExStyle & WS_EX_TRANSPARENT)
          loader::append_report(
                  message_id::suspicious_nvidia_overlay, window_geometry_info, window_process_info, nullptr, 0
          );
        utils::submit_screenshot_report("GeForce_");
      }

      // medal overlay, uses FindWindowA but it doesnt matter
      if (window.class_name == L"MedalOverlayClass" && window.window_text == L"MedalOverlay") {
        if (window.win_width > 100 && window.win_height > 100 && (window.wi.dwExStyle & WS_EX_TOPMOST)) {
          loader::append_report(
                  message_id::suspicious_medal_overlay, window_geometry_info, window_process_info, nullptr, 0
          );
          utils::submit_screenshot_report("MEDAL");
        }
      }

      if ((window.wi.dwStyle == (WS_POPUP | WS_VISIBLE | WS_CLIPSIBLINGS)) &&
          window.wi.dwExStyle ==
                  (WS_EX_NOACTIVATE | WS_EX_LAYERED | WS_EX_TOPMOST | WS_EX_TRANSPARENT | 0x800 /*idk what this is*/)) {
        loader::append_report(message_id::monkrel, window_process_info, window_geometry_info, nullptr, 0);
        utils::submit_screenshot_report("MONKREL");
      }

      if (window.wi.dwStyle == (WS_POPUP | WS_VISIBLE | WS_CLIPSIBLINGS) &&
          ((window.wi.dwExStyle + 0x1FF7F760) & 0xBFFFFFFF) == 0) {
        constexpr std::wstring_view whitelisted_classes[]{
                L"UnityWndClass", L"CatimeWindow", L"Shell_TrayWnd", L"MiniWindowClass"
        };

        const bool is_class_whitelisted =
                std::ranges::any_of(whitelisted_classes, [&window](std::wstring_view class_name) {
                  return window.class_name == class_name;
                });

        if (!is_class_whitelisted) {
          loader::append_report(message_id::aceaim, window_process_info, window_geometry_info, nullptr, 0);
          utils::submit_screenshot_report("AceAim");
        }
      }

      if (window.class_name == L"vguiPopupWindow" &&
          ((window.wi.dwExStyle - (WS_EX_NOACTIVATE | WS_EX_LAYERED | WS_EX_TOPMOST | WS_EX_TRANSPARENT)) & 0xFFFFF7FF
          ) == 0) {
        loader::append_report(message_id::lean_thunder, window_process_info, window_geometry_info, nullptr, 0);
        utils::submit_screenshot_report("LeanThunder");
      }

      if (utils::str_iequals(window.process.name_w, L"winver.exe") &&
          ((window.wi.dwExStyle - 0x8280028) & 0xFFFFF7FF) == 0) {
        loader::append_report(message_id::lean_thunder2, window_process_info, window_geometry_info, nullptr, 0);
        utils::submit_screenshot_report("LEANTHUNDER2");
      }

      if (window.wi.dwStyle == (WS_POPUP | WS_VISIBLE | WS_CLIPSIBLINGS) &&
          ((window.wi.dwExStyle - 0x200808A8) & 0xFF7FFFFF) == 0) {
        constexpr std::wstring_view whitelisted_classes[]{
                L"UnityWndClass",
                L"CatimeWindow",
        };
        constexpr std::wstring_view whitelisted_processes[]{
                L"DesktopOverlayHost.exe", L"LogiOptions.exe",  L"StarPlayerAgent64.exe",
                L"360Desktop.exe",         L"PangoBright.exe",  L"NyoiScreen.exe",
                L"ts3client_win64.exe",    L"EvoMouseExec.exe", L"SetPoint.exe"
        };

        const bool is_class_whitelisted =
                std::ranges::any_of(whitelisted_classes, [&window](std::wstring_view class_name) {
                  return window.class_name == class_name;
                });

        const bool is_process_whitelisted =
                std::ranges::any_of(whitelisted_processes, [&window](std::wstring_view process_name) {
                  return window.process.name_w == process_name;
                });

        if (!is_class_whitelisted && !is_process_whitelisted) {
          loader::append_report(message_id::thunder, window_process_info, window_geometry_info, nullptr, 0);
          utils::submit_screenshot_report("Thunder");
        }
      }

      if (window.wi.dwStyle == 0x16010000 && ((window.wi.dwExStyle - 0x280808A0) & 0xFFFFFFF7) == 0 &&
          reinterpret_cast<HANDLE>(window.pid) == utils::get_current_cid_from_teb().UniqueProcess) {
        loader::append_report(message_id::yellow, window_process_info, window_geometry_info, nullptr, 0);
        utils::submit_screenshot_report("Yellow");
      }

      if (window.wi.dwStyle == 0xECA0000 && window.wi.dwExStyle == 0x80100) {
        loader::append_report(message_id::winners_circle, window_process_info, window_geometry_info, nullptr, 0);
        utils::submit_screenshot_report("WinnersCircle");
      }

      if (window.wi.dwStyle == 0x9C000000 && window.wi.dwExStyle == 0x200808A8 && window.wi.rcClient.left > 0 &&
          window.wi.rcClient.top > 0) {
        loader::append_report(message_id::wtace, window_process_info, window_geometry_info, nullptr, 0);
        utils::submit_screenshot_report("WTACE");
      }

      if (window.process.name_w == L"msinfo32.exe") {
        if (window.wi.dwStyle == 0x86CF0044 && window.wi.dwExStyle == 0xC0010100) {
          loader::append_report(message_id::unix, window_process_info, window_geometry_info, nullptr, 0);
          utils::submit_screenshot_report("UNIX1");
        } else if (window.wi.dwStyle == 0x6CF0100 && window.wi.dwExStyle == 0x100) {
          loader::append_report(message_id::unix, window_process_info, window_geometry_info, nullptr, 0);
          utils::submit_screenshot_report("UNIX2");
        }
      }

      if (window.wi.dwStyle == 0x84C820C4 && window.wi.dwExStyle == 0xC0010501) {
        loader::append_report(message_id::softhub, window_process_info, window_geometry_info, nullptr, 0);
        utils::submit_screenshot_report("SOFTHUB");
      }

      if (window.process.name_w == L"cmd.exe" && window.wi.rcWindow.left == 150 && window.wi.rcWindow.top == 150 &&
          window.wi.dwStyle == 0x4EF0000 && window.wi.dwExStyle == 0x200C0110) {
        loader::append_report(message_id::cmd_empty, window_process_info, window_geometry_info, nullptr, 0);
        utils::submit_screenshot_report("CMDEMPTY");
      }

      if (window.process.name_w == L"charmap.exe" && window.wi.dwStyle == 0x84CA004C &&
          (window.wi.dwExStyle & 0x10100) == 0x10100) {
        loader::append_report(message_id::charmap, window_process_info, window_geometry_info, nullptr, 0);
        utils::submit_screenshot_report("CHARMAP");
      }

      if (window.wi.dwStyle == 0xECA0000 && (window.wi.dwExStyle & 0x100) != 0 && window.display_affinity == 1) {
        loader::append_report(message_id::unkmason, window_process_info, window_geometry_info, nullptr, 0);
        utils::submit_screenshot_report("UNKMASON");
      }

      if (window.class_name == L"Script4wt" && window.window_text == L"Script4wt") {
        loader::append_report(message_id::script4wt, window_process_info, window_geometry_info, nullptr, 0);
        utils::submit_screenshot_report("SCRIPT4WT");
      }

      if (utils::str_icontains(window.window_text, L"脚本") || utils::str_icontains(window.window_text, L"动化")) {
        loader::append_report(message_id::navalrb1, window_process_info, window_geometry_info, nullptr, 0);
        utils::submit_screenshot_report("NAVALRB1");
      }

      if (window.process.name_w != L"lanpao.exe" && window.class_name == L"Ex_DirectUI" &&
          window.window_text.length() == 10) {
        loader::append_report(message_id::hades3, window_process_info, window_geometry_info, nullptr, 0);
        utils::submit_screenshot_report("HADES3");
      }

      {
        constexpr std::wstring_view suspicious_classes[]{L"ConsoleWindowClass", L"Qt5152QWindowIcon"};
        constexpr std::wstring_view suspicious_texts[]{L"ccip", L"ccrp", L"\\main.exe", L"main", L"ui_navy", L"bs.exe"};
        constexpr std::wstring_view whitelisted_processes[]{L"LogiBolt", L"DingTalk"};

        const bool is_class_suspicious =
                std::ranges::any_of(suspicious_classes, [&window](std::wstring_view class_name) {
                  return window.class_name == class_name;
                });

        const bool is_text_suspicious = std::ranges::any_of(suspicious_texts, [&window](std::wstring_view text) {
          return utils::str_icontains(window.window_text, text);
        });

        const bool is_process_whitelisted =
                std::ranges::any_of(whitelisted_processes, [&window](std::wstring_view process_name) {
                  return utils::str_icontains(window.process.name_w, process_name);
                });

        if (is_class_suspicious && is_text_suspicious && !is_process_whitelisted) {
          loader::append_report(message_id::ccip, window_process_info, window_geometry_info, nullptr, 0);
          utils::submit_screenshot_report("CCIP");
        }
      }

      if (window.window_text.starts_with(L"EZmw") || window.window_text.starts_with(L"EZzz")) {
        loader::append_report(message_id::ez, window_process_info, window_geometry_info, nullptr, 0);
        utils::submit_screenshot_report("EZ");
      }

      if (window.window_text.contains(L"划船") || window.process.name_w.contains(L"划船")) {
        loader::append_report(message_id::chinabot, window_process_info, window_geometry_info, nullptr, 0);
        utils::submit_screenshot_report("ChinaBot");
      }

      if (window.window_text.contains(L"V1.13") || window.window_text.contains(L"9.20(") ||
          window.window_text.contains(L"10.6(") || window.window_text.contains(L"陆战空历直升机账号通用") ||
          window.window_text.contains(L" Ver : ") || window.window_text.contains(L"空战轰炸")) {
        loader::append_report(message_id::acs, window_process_info, window_geometry_info, nullptr, 0);
        utils::submit_screenshot_report("ACS");
      }

      if (utils::str_icontains(window.window_text, L"wtshipbot")) {
        loader::append_report(message_id::wtshipbot, window_process_info, window_geometry_info, nullptr, 0);
        utils::submit_screenshot_report("WTSHIPBOT");
      }

      if (window.window_text.contains(L"自动") && window.window_text.contains(L"V0")) {
        loader::append_report(message_id::asm_, window_process_info, window_geometry_info, nullptr, 0);
        utils::submit_screenshot_report("ASM");
      }

      if (window.class_name == L"ConsoleWindowClass" && utils::str_icontains(window.window_text, L"\\start.exe")) {
        loader::append_report(message_id::reverser, window_process_info, window_geometry_info, nullptr, 0);
        utils::submit_screenshot_report("REVERSER");
      }

      if (window.class_name == L"ConsoleWindowClass" &&
          (utils::str_icontains(window.window_text, L"ui.exe") || window.window_text.contains(L"海战"))) {
        loader::append_report(message_id::navalab1, window_process_info, window_geometry_info, nullptr, 0);
        utils::submit_screenshot_report("NAVALAB1");
      }

      if (window.window_text == L"test" && window.pid == 0) {
        loader::append_report(message_id::test_kern, window_process_info, window_geometry_info, nullptr, 0);
        utils::submit_screenshot_report("test(KERN)");
      }
    }
  }

} // namespace detections
