#ifndef MAIN_CLASS_HPP
#define MAIN_CLASS_HPP
#include <winternl.h>

class vac_ctx {
  LARGE_INTEGER freq_start{};
  LARGE_INTEGER counter_start{};
  LARGE_INTEGER counter_copy{};
  HWND DagorWClass{};

  public:
  vac_ctx();
  virtual ~vac_ctx() = default;

  virtual bool on_process_attach();
};

#endif // MAIN_CLASS_HPP

/*
 *void win10_scan_execution_history() {
    std::vector<utils::executable_file_info> entries;

    HKEY hkey = nullptr;
    if (RegOpenKeyExW(
                HKEY_CURRENT_USER,
                L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store", 0,
                KEY_READ, &hkey
        ) != ERROR_SUCCESS) {
      std::cout << std::format("\n[win10] failed to open registry key (error: {})", GetLastError());
      return;
    }

    std::cout << "\n[win10] opened registry key";
    std::experimental::scope_exit key_guard([&] {
      RegCloseKey(hkey);
    });

    utils::enumerate_registry_content(
            hkey,
            [&](DWORD type, std::wstring_view name, const std::vector<std::uint8_t>& data) -> bool {
              std::cout << std::format("\n[win10] found value: {}", utils::wide_to_utf8(name));
              entries.emplace_back(name, nullptr);
              std::cout << std::format("\n[win10] entry result: {}", entries.back().as_string);
              return true;
            }
    );

    std::cout << std::format("\n[win10] total entries before sort: {}", entries.size());

    std::ranges::sort(entries, [](const utils::executable_file_info& a, const utils::executable_file_info& b) {
      return CompareFileTime(&a.last_accessed_file_time, &b.last_accessed_file_time) == 1;
    });

    std::cout << std::format("\n[win10] sorted {} entries", entries.size());

    for (const auto& entry : entries) {
      std::cout << std::format("\n[win10] validating: {}", entry.as_string);
    }
  }

  //   void win11_scan_execution_history() {
  //     std::vector<utils::execution_history_entry> entries;
  //
  //     HKEY hkey = nullptr;
  //     if (RegOpenKeyExW(
  //             HKEY_LOCAL_MACHINE,
  //             L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache",
  //             0, KEY_READ | KEY_WOW64_64KEY, &hkey) != ERROR_SUCCESS) {
  //         std::cout << "\n[win11] failed to open AppCompatCache registry key";
  //         return;
  //     }
  //
  //     std::experimental::scope_exit key_guard([&] { RegCloseKey(hkey); });
  //
  //     DWORD blob_size = 0;
  //     if (RegQueryValueExW(hkey, L"AppCompatCache", nullptr, nullptr, nullptr, &blob_size) != ERROR_SUCCESS ||
  //     blob_size <= 0x60) {
  //         std::cout << std::format("\n[win11] blob too small or query failed (size: {})", blob_size);
  //         return;
  //     }
  //
  //     std::vector<uint8_t> blob(blob_size);
  //     if (RegQueryValueExW(hkey, L"AppCompatCache", nullptr, nullptr, blob.data(), &blob_size) != ERROR_SUCCESS) {
  //         std::cout << "\n[win11] failed to read blob";
  //         return;
  //     }
  //
  //     std::cout << std::format("\n[win11] blob size: {}", blob_size);
  //
  //     const uint8_t* pos = blob.data();
  //     const uint8_t* end = blob.data() + blob_size;
  //
  //     const auto can_read = [&](size_t n) {
  //         return pos + n <= end;
  //     };
  //     const auto read_u16 = [&]() -> uint16_t {
  //         uint16_t v; std::memcpy(&v, pos, 2); pos += 2; return v;
  //     };
  //     const auto read_u32 = [&]() -> uint32_t {
  //         uint32_t v; std::memcpy(&v, pos, 4); pos += 4; return v;
  //     };
  //
  //     // entry_count at offset 0x28 (40), cursor starts at 0x34 (52)
  //     if (!can_read(52)) {
  //         std::cout << "\n[win11] blob too small for header";
  //         return;
  //     }
  //     uint32_t entry_count = *reinterpret_cast<const uint32_t*>(blob.data() + 40);
  //     pos = blob.data() + 52;
  //
  //     std::cout << std::format("\n[win11] entry_count: {}", entry_count);
  //
  //     for (uint32_t i = 0; i < entry_count; i++) {
  //         std::cout << std::format("\n[win11] --- entry {} (offset: {}) ---", i, pos - blob.data());
  //
  //         if (!can_read(4)) { std::cout << "\n[win11] overflow unk0"; break; }
  //         uint32_t unk0 = read_u32();
  //
  //         if (!can_read(4)) { std::cout << "\n[win11] overflow unk1"; break; }
  //         uint32_t unk1 = read_u32();
  //
  //         if (!can_read(4)) { std::cout << "\n[win11] overflow unk2"; break; }
  //         uint32_t unk2 = read_u32();
  //
  //         if (!can_read(2)) { std::cout << "\n[win11] overflow path_byte_len"; break; }
  //         uint16_t path_byte_len = read_u16();
  //
  //         std::cout << std::format("\n[win11] entry {} unk0: {:#010x} unk1: {:#010x} unk2: {:#010x} path_byte_len:
  //         {}",
  //             i, unk0, unk1, unk2, path_byte_len);
  //
  //         if (!can_read(path_byte_len)) { std::cout << std::format("\n[win11] overflow path ({} bytes)",
  //         path_byte_len); break; } std::wstring path(reinterpret_cast<const wchar_t*>(pos), path_byte_len /
  //         sizeof(wchar_t)); pos += path_byte_len;
  //
  //         std::cout << std::format("\n[win11] entry {} path: {}", i, utils::wide_to_utf8(path));
  //
  //         if (!can_read(8)) { std::cout << "\n[win11] overflow filetime"; break; }
  //         FILETIME ft{};
  //         std::memcpy(&ft, pos, 8); pos += 8;
  //
  //         SYSTEMTIME st{};
  //         FileTimeToSystemTime(&ft, &st);
  //         std::cout << std::format("\n[win11] entry {} last_modified: {}-{}-{}", i, st.wDay, st.wMonth, st.wYear);
  //
  //         if (!can_read(4)) { std::cout << "\n[win11] overflow remaining_size"; break; }
  //         uint32_t remaining_size = read_u32();
  //         uint32_t to_skip = remaining_size > 4 ? remaining_size - 4 : 0;
  //         std::cout << std::format("\n[win11] entry {} remaining_size: {}, skipping: {}", i, remaining_size,
  //         to_skip); if (!can_read(to_skip)) { std::cout << std::format("\n[win11] overflow skipping {} bytes",
  //         to_skip); break; } pos += to_skip;
  //
  //         if (!can_read(4)) { std::cout << "\n[win11] overflow is_valid"; break; }
  //         uint32_t is_valid = read_u32();
  //         std::cout << std::format("\n[win11] entry {} is_valid: {}", i, is_valid);
  //
  //         if (is_valid == 1) {
  //             std::cout << std::format("\n[win11] entry {} valid, adding", i);
  //             entries.emplace_back(path, &ft);
  //         } else {
  //             std::cout << std::format("\n[win11] entry {} skipped (is_valid={})", i, is_valid);
  //         }
  //     }
  //
  //     std::cout << std::format("\n[win11] parsed {} valid entries", entries.size());
  //
  //     std::ranges::sort(entries, [](const utils::execution_history_entry& a, const utils::execution_history_entry& b)
  //     {
  //         return CompareFileTime(&a.last_accessed_file_time, &b.last_accessed_file_time) == 1;
  //     });
  //
  //     for (const auto& entry : entries) {
  //         std::cout << std::format("\n[win11] entry: {}", entry.as_string);
  //         validate_execution_history_entry(entry);
  //     }
  // }
  */
