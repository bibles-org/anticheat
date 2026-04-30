#include "detections.hpp"

#include <algorithm>
#include <experimental/scope>
#include <format>
#include <string>
#include <windows.h>

#include "../loader/loader.hpp"
#include "../utils/file.hpp"
#include "../utils/registry.hpp"
#include "../utils/string.hpp"


namespace detections {
  void check_sip_hijack_and_appinit_injection() {
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
} // namespace detections
