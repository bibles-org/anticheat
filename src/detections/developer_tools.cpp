#include "../loader/loader.hpp"
#include "../utils/file.hpp"
#include "../utils/registry.hpp"
#include "../utils/screenshot.hpp"
#include "../utils/string.hpp"
#include "detections.hpp"

#include <experimental/scope>
#include <format>
#include <shlobj.h>

namespace {
  bool report_visual_studio_private_settings(std::wstring_view subkey_name) {
    // yep, we do this everytime for no reason.
    wchar_t* folder_path_raw = nullptr;
    std::wstring folder_path;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &folder_path_raw))) {
      if (folder_path_raw)
        folder_path = folder_path_raw;

      CoTaskMemFree(folder_path_raw);
    }

    const std::wstring full_path =
            std::format(L"{}\\Microsoft\\VisualStudio\\{}\\ApplicationPrivateSettings.xml", folder_path, subkey_name);

    const std::vector<std::uint8_t> file_buf = utils::read_file_contents(full_path);

    loader::append_report(
            message_id::visual_studio_private_settings, utils::wide_to_utf8(subkey_name), {},
            file_buf.empty() ? nullptr : file_buf.data(), file_buf.size()
    );
    return true;
  } // namespace

  bool report_visual_studio_project(
          std::string_view version_label, DWORD, std::wstring_view, const std::vector<std::uint8_t>& data
  ) {
    std::wstring_view blob(reinterpret_cast<const wchar_t*>(data.data()), data.size() / sizeof(wchar_t));
    std::wstring path(blob.substr(0, blob.find(L'|')));

    if (path.empty())
      return true;

    std::wstring expanded(MAX_PATH, L'\0');
    if (!ExpandEnvironmentStringsW(path.c_str(), expanded.data(), expanded.size())) {
      return true;
    }
    expanded.shrink_to_fit();

    if (!utils::touch_file(expanded))
      return true;

    const HANDLE hfile = CreateFileW(
            expanded.c_str(), GENERIC_READ, FILE_SHARE_VALID_FLAGS, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
            nullptr
    );
    if (hfile == INVALID_HANDLE_VALUE)
      return true;

    std::experimental::scope_exit h_guard([&] {
      CloseHandle(hfile);
    });

    FILETIME ft{};
    SYSTEMTIME st{};
    if (GetFileTime(hfile, nullptr, &ft, nullptr) && FileTimeToSystemTime(&ft, &st) && st.wYear >= 2025) {
      const std::string report = std::format("({}) {:02}/{:02}/{:04}", version_label, st.wDay, st.wMonth, st.wYear);
      loader::append_report(message_id::visual_studio_project_entry, report, utils::wide_to_utf8(expanded), nullptr, 0);
    }

    return true;
  }
} // namespace

namespace detections {
  void check_visual_studio_projects() {
    // legacy format
    for (int i = 6; i < 16; ++i) {
      const std::string version_label = std::format("VS{}", i);
      const std::wstring subkey = std::format(L"Software\\Microsoft\\VisualStudio\\{}.0\\ProjectMRUList", i);

      HKEY hkey = nullptr;
      if (RegOpenKeyExW(HKEY_CURRENT_USER, subkey.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &hkey) != ERROR_SUCCESS)
        continue;

      utils::enumerate_registry_content(hkey, std::bind_front(report_visual_studio_project, version_label));

      RegCloseKey(hkey);
    }

    // new format
    {
      HKEY hkey = nullptr;
      if (RegOpenKeyExW(
                  HKEY_CURRENT_USER,
                  L"SOFTWARE\\Microsoft\\VisualStudio\\14.0\\MRUItems\\{a9c4a31f-f9cb-47a9-abc0-49ce82d0b3ac}\\Items",
                  0, KEY_READ | KEY_WOW64_64KEY, &hkey
          ) == ERROR_SUCCESS) {

        utils::enumerate_registry_content(hkey, std::bind_front(report_visual_studio_project, "VS15"));

        RegCloseKey(hkey);
      }
    }

    // private settings
    {
      HKEY hkey = nullptr;
      if (RegOpenKeyExW(
                  HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\VisualStudio", 0, KEY_READ | KEY_WOW64_64KEY, &hkey
          ) == ERROR_SUCCESS) {

        utils::enumerate_registry_content(hkey, nullptr, &report_visual_studio_private_settings);

        RegCloseKey(hkey);
      }
    }
  }

  void check_ida_history() {
    for (const auto& [subkey, label] : {
                 std::pair{L"Software\\Hex-Rays\\IDA\\History64", L"IDA64"},
                 std::pair{L"Software\\Hex-Rays\\IDA\\History",   L"IDA86"},
    }) {
      HKEY hkey = nullptr;
      if (RegOpenKeyExW(HKEY_CURRENT_USER, subkey, 0, KEY_READ, &hkey) != ERROR_SUCCESS)
        continue;
      std::experimental::scope_exit key_guard([&] {
        RegCloseKey(hkey);
      });

      utils::enumerate_registry_content(
              hkey,
              [&](DWORD type, std::wstring_view, const std::vector<std::uint8_t>& data) {
                const std::wstring path(reinterpret_cast<const wchar_t*>(data.data()), data.size() / 2);
                if (!path.empty())
                  loader::append_report(
                          message_id::ida_history_entry, utils::wide_to_utf8(label), utils::wide_to_utf8(path), nullptr,
                          0
                  );

                return true;
              },
              nullptr
      );
    }
  }

} // namespace detections
