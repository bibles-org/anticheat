#include "detections.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <experimental/scope>
#include <format>
#include <string>
#include <vector>
#include <windows.h>
#include <winternl.h>

#include "../loader/loader.hpp"
#include "../utils/file.hpp"
#include "../utils/process.hpp"
#include "../utils/registry.hpp"
#include "../utils/screenshot.hpp"
#include "../utils/string.hpp"


extern "C" NTSTATUS NtQueryVirtualMemory(HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T);

namespace {
  IMAGE_SECTION_HEADER* find_rwx_section(std::uint8_t* base) {
    const auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
      return nullptr;

    const auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
      return nullptr;

    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
      if (const DWORD c = sections[i].Characteristics;
          (c & IMAGE_SCN_MEM_READ) && (c & IMAGE_SCN_MEM_WRITE) && (c & IMAGE_SCN_MEM_EXECUTE))
        return &sections[i];
    }

    return nullptr;
  }

  // for some reason the guid and age arent used..
  bool extract_pdb_info(std::uint8_t* base, std::string& out_filename, std::string& out_guid, std::uint32_t& out_age) {
    const auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
      return false;

    const auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
      return false;

    const auto& [VirtualAddress, Size] = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    if (!VirtualAddress || !Size)
      return false;

    const auto* dbg_entries = reinterpret_cast<IMAGE_DEBUG_DIRECTORY*>(base + VirtualAddress);
    const int count = Size / sizeof(IMAGE_DEBUG_DIRECTORY);

    for (int i = 0; i < count; i++) {
      if (dbg_entries[i].Type != IMAGE_DEBUG_TYPE_CODEVIEW)
        continue;

      const auto* cv = reinterpret_cast<const std::uint32_t*>(base + dbg_entries[i].AddressOfRawData);
      const std::uint32_t signature = cv[0];

      if (signature == 'SDSR') { // RSDS PDB 7.0
        const auto* guid = reinterpret_cast<const GUID*>(&cv[1]);
        const auto age = cv[5];
        auto pdbname = reinterpret_cast<const char*>(&cv[6]);

        out_filename = pdbname;
        out_guid = std::format(
                "{:08X}{:04X}{:04X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}", guid->Data1, guid->Data2,
                guid->Data3, guid->Data4[0], guid->Data4[1], guid->Data4[2], guid->Data4[3], guid->Data4[4],
                guid->Data4[5], guid->Data4[6], guid->Data4[7]
        );
        out_age = age;
        return true;

      } else if (signature == '01BN' || signature == '90BN') { // NB10/NB09  PDB 2.0
        const auto age = cv[3];
        auto pdbname = reinterpret_cast<const char*>(&cv[4]);

        out_filename = pdbname;
        out_guid = std::format("{:08X}", cv[2]);
        out_age = age;
        return true;
      }
    }

    return false;
  }
} // namespace

namespace detections {
  void validate_process(const SYSTEM_PROCESS_INFORMATION& process) {
    auto process_id = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(process.UniqueProcessId));
    std::wstring image_path_w = utils::get_process_image_path(process_id);

    const std::wstring image_name{process.ImageName.Buffer, process.ImageName.Length / sizeof(wchar_t)};

    if (image_path_w.empty())
      image_path_w = image_name;

    const std::string image_path = utils::wide_to_utf8(image_path_w);

    const std::string formatted_process_path = std::format("(PID: {}) path={}", process_id, image_path);


    const std::size_t file_size = image_path_w.empty() ? 0 : utils::timestomp_and_get_file_size(image_path_w);
    const std::string formatted_image_size = std::format("PID: {}, Size:{}", process_id, file_size);


    if (utils::str_icontains(image_name, L"rustdesk.exe") && utils::str_icontains(image_name, L"powershell.exe")) {
      loader::append_report(message_id::rdesk, nullptr, 0, nullptr, 0, nullptr, 0);
      utils::submit_screenshot_report("RDESK");
    }

    if (utils::str_icontains(image_name, L"vmconnect.exe")) {
      loader::append_report(message_id::vmware2, nullptr, 0, nullptr, 0, nullptr, 0);
      utils::submit_screenshot_report("VMWARE2");
    }

    if (utils::str_icontains(image_name, L"wmv2.bin")) {
      loader::append_report(message_id::war_overlay, "WarOverlay", formatted_process_path, nullptr, 0);
      utils::submit_screenshot_report("WarOverlay");
    }

    if (image_name.contains(L"脚本") ||image_name.contains(L"动化")) {
      loader::append_report(message_id::china_script, "ChinaScript", formatted_process_path, nullptr, 0);
      utils::submit_screenshot_report("ChinaScript");
    }

    /*
     * if (image_name.data() == L"test.exe")
     *   - Gaijin 2026
     */

    if (utils::str_iequals(image_name, L"test.exe")) {
      if (FindWindowW(nullptr, L"test")) {
        loader::append_report(message_id::test_window, "test", formatted_process_path, nullptr, 0);
        utils::submit_screenshot_report("test");
      }
    }

    if (utils::str_icontains(image_name, L"Air Bot")) {
      loader::append_report(message_id::air_bot, "AirBot", formatted_process_path, nullptr, 0);
      utils::submit_screenshot_report("AirBot");
    }

    if (utils::str_icontains(image_name, L"Farm Bot")) {
      loader::append_report(message_id::air_bot, "FarmBot", formatted_process_path, nullptr, 0);
      utils::submit_screenshot_report("FarmBot");
    }

    /*
     * if (image_name.data() == L"main.exe")
     *   - Gaijin 2026
     */

    if (utils::str_icontains(image_path_w, L"boosteroid") || utils::str_iequals(image_name, L"main.exe")) {
      constexpr std::wstring_view chinese_fellas[]{L"HongHai", L"Webzen", L"bwupdate", L"Xrelay"};

      if (std::ranges::any_of(chinese_fellas, [&image_path_w](std::wstring_view fella) -> bool {
            return utils::str_icontains(image_path_w, fella);
          })) {
        loader::append_report(message_id::ccip_main, formatted_image_size, formatted_process_path, nullptr, 0);
        utils::submit_screenshot_report("CCIP(main)");
      }
    }

    if (utils::str_iequals(image_name, L"hong2.exe")) {
      loader::append_report(message_id::hong2, "hong2", formatted_process_path, nullptr, 0);
      utils::submit_screenshot_report("CCIP(main)");
    }

    if (image_name.contains(L"投弹镜")) {
      loader::append_report(message_id::bombscope, "BOMBSCOPE", formatted_process_path, nullptr, 0);
      utils::submit_screenshot_report("BOMBSCOPE");
    }

    if (utils::str_icontains(image_name, L"._cache_")) {

      loader::append_report(message_id::cachebot, "CACHEBOT", formatted_process_path, nullptr, 0);
      utils::submit_screenshot_report("CACHEBOT");
    }

    if (utils::str_icontains(image_name, L"ccrp7")) {
      loader::append_report(message_id::cachebot, "CCRP7", formatted_process_path, nullptr, 0);
      utils::submit_screenshot_report("CCRP7");
    }

    if (utils::str_icontains(image_name, L"地图测距V13.exe")) {
      loader::append_report(message_id::v13bot, "V13BOT", formatted_process_path, nullptr, 0);
      utils::submit_screenshot_report("V13BOT");
    }

    if (image_name.contains(L"起降刷研发")) {
      loader::append_report(message_id::takeoff_bot, "TAKEOFFBOT", formatted_process_path, nullptr, 0);
      utils::submit_screenshot_report("TAKEOFFBOT");
    }

    if (image_name.contains(L"通用")) {
      loader::append_report(message_id::macro1, "MACRO1", formatted_process_path, nullptr, 0);
      utils::submit_screenshot_report("MACRO1");
    }

    if (utils::str_icontains(image_name, L"j6.exe")) {
      loader::append_report(message_id::j6, "J6", formatted_process_path, nullptr, 0);
      utils::submit_screenshot_report("J6");
    }

    if (utils::str_icontains(image_path_w, L"\\001\\svchost.exe") || utils::str_icontains(image_name, L"MK.exe") ||
        utils::str_icontains(image_name, L"Thunder_Hook.exe") ||
        (utils::str_icontains(image_name, L"thunder") && utils::str_icontains(image_name, L"注册"))) {
      loader::append_report(message_id::exemix, "EXEMIX", formatted_process_path, nullptr, 0);
      utils::submit_screenshot_report("EXEMIX");
    }
  }

  void scan_loaded_modules() {
    const PEB* peb = NtCurrentTeb()->ProcessEnvironmentBlock;
    if (!peb || !peb->Ldr)
      return;

    const LIST_ENTRY* head = &peb->Ldr->InMemoryOrderModuleList;
    LIST_ENTRY* entry = head->Flink;
    while (entry != head) {
      const LDR_DATA_TABLE_ENTRY* mod = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
      entry = entry->Flink;

      if (!mod->DllBase)
        continue;

      auto base = static_cast<std::uint8_t*>(mod->DllBase);
      const auto full_path_w = std::wstring(mod->FullDllName.Buffer, mod->FullDllName.Length / sizeof(wchar_t));
      const auto full_path = utils::wide_to_utf8(full_path_w);

      if (IMAGE_SECTION_HEADER* rwx_section = find_rwx_section(base)) {
        char raw_name[9] = {};
        for (int j = 0; j < 8; j++) { // normalize
          const std::uint8_t c = rwx_section->Name[j];
          if (!c)
            break;
          raw_name[j] = (c >= ' ' && c <= '~') ? static_cast<char>(c) : '?';
        }

        std::string section_tag = std::format(
                "{} [Va=0x{:x}, Pa=0x{:x}, RawSize=0x{:x}]", raw_name, rwx_section->VirtualAddress,
                rwx_section->Misc.PhysicalAddress, rwx_section->SizeOfRawData
        );

        std::vector<std::uint8_t> file_buf = utils::read_file_contents(full_path_w);

        loader::append_report(
                message_id::rwx_section, section_tag.c_str(), section_tag.size(), full_path.c_str(), full_path.size(),
                file_buf.empty() ? nullptr : file_buf.data(), file_buf.size()
        );

        if (!file_buf.empty()) {
          std::memset(file_buf.data(), 0, file_buf.size());
          file_buf.clear();
        }

        utils::submit_screenshot_report("EXECSECTION");

        const std::uintptr_t section_va = reinterpret_cast<std::uintptr_t>(base) + rwx_section->VirtualAddress;
        MEMORY_BASIC_INFORMATION mbi = {};
        SIZE_T return_len = 0;
        if (NtQueryVirtualMemory(
                    reinterpret_cast<HANDLE>(-1LL), reinterpret_cast<void*>(section_va), 0, &mbi, sizeof(mbi),
                    &return_len
            ) < 0)
          std::memset(&mbi, 0, sizeof(mbi));

        if (mbi.Protect && !(mbi.Protect & PAGE_GUARD) && !(mbi.Protect & PAGE_NOACCESS)) {
          loader::append_report(
                  message_id::accessible_rwx_section, section_tag.c_str(), section_tag.size(), full_path.c_str(),
                  full_path.size(), reinterpret_cast<std::uint8_t*>(&mbi), sizeof(mbi)
          );
        }
      }

      std::string pdb_filename, pdb_guid;
      std::uint32_t pdb_age = 0;
      if (extract_pdb_info(base, pdb_filename, pdb_guid, pdb_age) && !pdb_filename.empty()) {
        std::wstring pdb_path_w(pdb_filename.begin(), pdb_filename.end());

        if (utils::touch_file(pdb_path_w)) {
          std::vector<std::uint8_t> pdb_buf = utils::read_file_contents(pdb_path_w);

          loader::append_report(
                  message_id::pdb, "PDB", 3, pdb_filename.c_str(), pdb_filename.size(),
                  pdb_buf.empty() ? nullptr : pdb_buf.data(), pdb_buf.size()
          );
        }
      }
    }
  }

  void scan_nvidia_overlay() {
    HWND hwnd = FindWindowA("CEF-OSC-WIDGET", "NVIDIA GeForce Overlay");
    if (!hwnd)
      return;

    if (const utils::window_info wi = utils::get_window_info(hwnd, 0xFFFFFFFF); wi.wi.dwExStyle & WS_EX_TRANSPARENT) {
      const std::string process_info = utils::format_window_process_info(wi);
      const std::string geometry_info = utils::format_window_geometry_info(wi);

      loader::append_report(
              message_id::suspicious_nvidia_overlay, geometry_info.c_str(), geometry_info.size(), process_info.c_str(),
              process_info.size(), nullptr, 0
      );

      utils::submit_screenshot_report("GeForce_");
    }
  }

  void scan_medal_overlay() {
    const HWND hwnd = FindWindowA("MedalOverlayClass", "MedalOverlay");
    if (!hwnd)
      return;

    if (const utils::window_info wi = utils::get_window_info(hwnd, 0xFFFFFFFF);
        wi.win_width > 100 && wi.win_height > 100 && (wi.wi.dwExStyle & WS_EX_TOPMOST)) {
      const std::string process_info = format_window_process_info(wi);
      const std::string geometry_info = format_window_geometry_info(wi);

      loader::append_report(
              message_id::suspicious_medal_overlay, geometry_info.c_str(), geometry_info.size(), process_info.c_str(),
              process_info.size(), nullptr, 0
      );

      utils::submit_screenshot_report("MEDAL");
    }
  }

  void check_trust_provider_integrity() {
    HKEY sip_handle = nullptr;
    if (RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\WOW6432Node\\Microsoft\\Cryptography\\OID\\EncodingType "
                L"0\\CryptSIPDllVerifyIndirectData\\{C689AAB8-8E78-11D0-8C47-00C04FC295EE}",
                0, KEY_READ | KEY_WOW64_64KEY, &sip_handle
        ) == ERROR_SUCCESS) {

      std::experimental::scope_exit sip_guard([&] {
        RegCloseKey(sip_handle);
      });

      const std::wstring sip_dll_w = utils::read_registry_string(sip_handle, L"Dll");
      const std::wstring sip_func_w = utils::read_registry_string(sip_handle, L"FuncName");

      if (!sip_dll_w.empty() && !sip_func_w.empty()) {
        const bool dll_ok = utils::str_icontains(sip_dll_w, L"WINTRUST.DLL");
        const bool func_ok = utils::str_iequals(sip_func_w, L"CryptSIPVerifyIndirectData");

        if (!dll_ok || !func_ok) {
          loader::append_report(
                  message_id::sip_tampered, utils::wide_to_utf8(sip_dll_w), utils::wide_to_utf8(sip_func_w), nullptr, 0
          );
        }
      }
    }

    HKEY win_handle = nullptr;
    if (RegOpenKeyExW(
                HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", 0,
                KEY_READ | KEY_WOW64_64KEY, &win_handle
        ) == ERROR_SUCCESS) {

      std::experimental::scope_exit win_guard([&] {
        RegCloseKey(win_handle);
      });

      DWORD load_appinit = 0;
      DWORD size = sizeof(load_appinit);
      DWORD type = 0;
      RegQueryValueExW(win_handle, L"LoadAppInit_DLLs", nullptr, &type, reinterpret_cast<LPBYTE>(&load_appinit), &size);

      if (load_appinit == 1) {
        const std::wstring appinit_dlls_w = utils::read_registry_string(win_handle, L"AppInit_DLLs");
        if (!appinit_dlls_w.empty()) {
          loader::append_report(
                  message_id::appinit_dlls, "AppInit_DLLs", utils::wide_to_utf8(appinit_dlls_w), nullptr, 0
          );
        }
      }
    }
  }

  void validate_window(const utils::window_info& wi) {
    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);

    auto window_process_info = utils::format_window_process_info(wi);
    auto window_geometry_info = utils::format_window_geometry_info(wi);

    if ((wi.wi.dwStyle == (WS_POPUP | WS_VISIBLE | WS_CLIPSIBLINGS)) &&
        wi.wi.dwExStyle ==
                (WS_EX_NOACTIVATE | WS_EX_LAYERED | WS_EX_TOPMOST | WS_EX_TRANSPARENT | 0x800 /*idk what this is*/)) {
      loader::append_report(message_id::monkrel, window_process_info, window_geometry_info, nullptr, 0);
      utils::submit_screenshot_report("MONKREL");
    }

    if (wi.wi.dwStyle == (WS_POPUP | WS_VISIBLE | WS_CLIPSIBLINGS) &&
        ((wi.wi.dwExStyle + 0x1FF7F760) & 0xBFFFFFFF) == 0) {
      constexpr std::wstring_view whitelisted_classes[]{
              L"UnityWndClass", L"CatimeWindow", L"Shell_TrayWnd", L"MiniWindowClass"
      };

      const bool is_class_whitelisted = std::ranges::any_of(whitelisted_classes, [&wi](std::wstring_view class_name) {
        return wi.class_name == class_name;
      });

      if (!is_class_whitelisted) {
        loader::append_report(message_id::aceaim, window_process_info, window_geometry_info, nullptr, 0);
        utils::submit_screenshot_report("AceAim");
      }
    }

    if (wi.class_name == L"vguiPopupWindow" &&
        ((wi.wi.dwExStyle - (WS_EX_NOACTIVATE | WS_EX_LAYERED | WS_EX_TOPMOST | WS_EX_TRANSPARENT)) & 0xFFFFF7FF) ==
                0) {
      loader::append_report(message_id::lean_thunder, window_process_info, window_geometry_info, nullptr, 0);
      utils::submit_screenshot_report("LeanThunder");
    }

    if (utils::str_iequals(wi.process_name, L"winver.exe") && ((wi.wi.dwExStyle - 0x8280028) & 0xFFFFF7FF) == 0) {
      loader::append_report(message_id::lean_thunder2, window_process_info, window_geometry_info, nullptr, 0);
      utils::submit_screenshot_report("LEANTHUNDER2");
    }

    if (wi.wi.dwStyle == (WS_POPUP | WS_VISIBLE | WS_CLIPSIBLINGS) &&
        ((wi.wi.dwExStyle - 0x200808A8) & 0xFF7FFFFF) == 0) {
      constexpr std::wstring_view whitelisted_classes[]{
              L"UnityWndClass",
              L"CatimeWindow",
      };
      constexpr std::wstring_view whitelisted_processes[]{
              L"DesktopOverlayHost.exe", L"LogiOptions.exe",  L"StarPlayerAgent64.exe",
              L"360Desktop.exe",         L"PangoBright.exe",  L"NyoiScreen.exe",
              L"ts3client_win64.exe",    L"EvoMouseExec.exe", L"SetPoint.exe"
      };

      const bool is_class_whitelisted = std::ranges::any_of(whitelisted_classes, [&wi](std::wstring_view class_name) {
        return wi.class_name == class_name;
      });

      const bool is_process_whitelisted = std::ranges::any_of(whitelisted_processes, [&wi](std::wstring_view process) {
        return wi.process_name == process;
      });

      if (!is_class_whitelisted && !is_process_whitelisted) {
        loader::append_report(message_id::thunder, window_process_info, window_geometry_info, nullptr, 0);
        utils::submit_screenshot_report("Thunder");
      }
    }

    if (wi.wi.dwStyle == 0x16010000 && ((wi.wi.dwExStyle - 0x280808A0) & 0xFFFFFFF7) == 0 &&
        reinterpret_cast<HANDLE>(wi.pid) == utils::get_current_cid_from_teb().UniqueProcess) {
      loader::append_report(message_id::yellow, window_process_info, window_geometry_info, nullptr, 0);
      utils::submit_screenshot_report("Yellow");
    }

    if (wi.wi.dwStyle == 0xECA0000 && wi.wi.dwExStyle == 0x80100) {
      loader::append_report(message_id::winners_circle, window_process_info, window_geometry_info, nullptr, 0);
      utils::submit_screenshot_report("WinnersCircle");
    }

    if (wi.wi.dwStyle == 0x9C000000 && wi.wi.dwExStyle == 0x200808A8 && wi.wi.rcClient.left > 0 &&
        wi.wi.rcClient.top > 0) {
      loader::append_report(message_id::wtace, window_process_info, window_geometry_info, nullptr, 0);
      utils::submit_screenshot_report("WTACE");
    }

    if (wi.process_name == L"msinfo32.exe") {
      if (wi.wi.dwStyle == 0x86CF0044 && wi.wi.dwExStyle == 0xC0010100) {
        loader::append_report(message_id::unix, window_process_info, window_geometry_info, nullptr, 0);
        utils::submit_screenshot_report("UNIX1");
      } else if (wi.wi.dwStyle == 0x6CF0100 && wi.wi.dwExStyle == 0x100) {
        loader::append_report(message_id::unix, window_process_info, window_geometry_info, nullptr, 0);
        utils::submit_screenshot_report("UNIX2");
      }
    }

    if (wi.wi.dwStyle == 0x84C820C4 && wi.wi.dwExStyle == 0xC0010501) {
      loader::append_report(message_id::softhub, window_process_info, window_geometry_info, nullptr, 0);
      utils::submit_screenshot_report("SOFTHUB");
    }

    if (wi.process_name == L"cmd.exe" && wi.wi.rcWindow.left == 150 && wi.wi.rcWindow.top == 150 &&
        wi.wi.dwStyle == 0x4EF0000 && wi.wi.dwExStyle == 0x200C0110) {
      loader::append_report(message_id::cmd_empty, window_process_info, window_geometry_info, nullptr, 0);
      utils::submit_screenshot_report("CMDEMPTY");
    }

    if (wi.process_name == L"charmap.exe" && wi.wi.dwStyle == 0x84CA004C && (wi.wi.dwExStyle & 0x10100) == 0x10100) {
      loader::append_report(message_id::charmap, window_process_info, window_geometry_info, nullptr, 0);
      utils::submit_screenshot_report("CHARMAP");
    }

    if (wi.wi.dwStyle == 0xECA0000 && (wi.wi.dwExStyle & 0x100) != 0 && wi.display_affinity == 1) {
      loader::append_report(message_id::unkmason, window_process_info, window_geometry_info, nullptr, 0);
      utils::submit_screenshot_report("UNKMASON");
    }

    if (wi.class_name == L"Script4wt" && wi.window_text == L"Script4wt") {
      loader::append_report(message_id::script4wt, window_process_info, window_geometry_info, nullptr, 0);
      utils::submit_screenshot_report("SCRIPT4WT");
    }

    if (utils::str_icontains(wi.window_text, L"脚本") || utils::str_icontains(wi.window_text, L"动化")) {
      loader::append_report(message_id::navalrb1, window_process_info, window_geometry_info, nullptr, 0);
      utils::submit_screenshot_report("NAVALRB1");
    }

    if (wi.process_name != L"lanpao.exe" && wi.class_name == L"Ex_DirectUI" && wi.window_text.length() == 10) {
      loader::append_report(message_id::hades3, window_process_info, window_geometry_info, nullptr, 0);
      utils::submit_screenshot_report("HADES3");
    }

    {
      constexpr std::wstring_view suspicious_classes[]{L"ConsoleWindowClass", L"Qt5152QWindowIcon"};
      constexpr std::wstring_view suspicious_texts[]{L"ccip", L"ccrp", L"\\main.exe", L"main", L"ui_navy", L"bs.exe"};
      constexpr std::wstring_view whitelisted_processes[]{L"LogiBolt", L"DingTalk"};

      const bool is_class_suspicious = std::ranges::any_of(suspicious_classes, [&wi](std::wstring_view c) {
        return wi.class_name == c;
      });

      const bool is_text_suspicious = std::ranges::any_of(suspicious_texts, [&wi](std::wstring_view t) {
        return utils::str_icontains(wi.window_text, t);
      });

      const bool is_process_whitelisted = std::ranges::any_of(whitelisted_processes, [&wi](std::wstring_view p) {
        return utils::str_icontains(wi.process_name, p);
      });

      if (is_class_suspicious && is_text_suspicious && !is_process_whitelisted) {
        loader::append_report(message_id::ccip, window_process_info, window_geometry_info, nullptr, 0);
        utils::submit_screenshot_report("CCIP");
      }
    }

    if (wi.window_text.starts_with(L"EZmw") || wi.window_text.starts_with(L"EZzz")) {
      loader::append_report(message_id::ez, window_process_info, window_geometry_info, nullptr, 0);
      utils::submit_screenshot_report("EZ");
    }

    if (utils::str_icontains(wi.window_text, L"划船") || utils::str_icontains(wi.process_name, L"划船")) {
      loader::append_report(message_id::chinabot, window_process_info, window_geometry_info, nullptr, 0);
      utils::submit_screenshot_report("ChinaBot");
    }

    if (wi.window_text.contains(L"V1.13") || wi.window_text.contains(L"9.20(") || wi.window_text.contains(L"10.6(") ||
        wi.window_text.contains(L"陆战空历直升机账号通用") || wi.window_text.contains(L" Ver : ") ||
        wi.window_text.contains(L"空战轰炸")) {
      loader::append_report(message_id::acs, window_process_info, window_geometry_info, nullptr, 0);
      utils::submit_screenshot_report("ACS");
    }

    if (utils::str_icontains(wi.window_text, L"wtshipbot")) {
      loader::append_report(message_id::wtshipbot, window_process_info, window_geometry_info, nullptr, 0);
      utils::submit_screenshot_report("WTSHIPBOT");
    }

    if (wi.window_text.contains(L"自动") && wi.window_text.contains(L"V0")) {
      loader::append_report(message_id::asm_, window_process_info, window_geometry_info, nullptr, 0);
      utils::submit_screenshot_report("ASM");
    }

    if (wi.class_name == L"ConsoleWindowClass" && utils::str_icontains(wi.window_text, L"\\start.exe")) {
      loader::append_report(message_id::reverser, window_process_info, window_geometry_info, nullptr, 0);
      utils::submit_screenshot_report("REVERSER");
    }

    if (wi.class_name == L"ConsoleWindowClass" &&
        (utils::str_icontains(wi.window_text, L"ui.exe") || wi.window_text.contains(L"海战"))) {
      loader::append_report(message_id::navalab1, window_process_info, window_geometry_info, nullptr, 0);
      utils::submit_screenshot_report("NAVALAB1");
    }

    if (wi.window_text == L"test" && wi.pid == 0) {
      loader::append_report(message_id::test_kern, window_process_info, window_geometry_info, nullptr, 0);
      utils::submit_screenshot_report("test(KERN)");
    }
  }

} // namespace detections
