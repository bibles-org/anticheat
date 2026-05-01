#include "../loader/loader.hpp"
#include "../utils/screenshot.hpp"
#include "../utils/string.hpp"
#include "detections.hpp"

#include <cstring>
#include <format>
#include <windows.h>

namespace {
  // " Size=%" (ImGui debug string from ShowMetricsWindow)
  constexpr std::uint8_t imgui_pattern[] = {0x20, 0x53, 0x69, 0x7a, 0x65, 0x3d, 0x25};

  // XML manifest header signature
  constexpr char manifest_signature[] = "<?xml version='1.0' encodin";

  // like in original binary
  bool match_xor66_pattern(
          const std::uint8_t* buffer, std::size_t buffer_size,
          const std::uint8_t* pattern, std::size_t pattern_size
  ) {
    if (pattern_size == 0 || buffer_size < pattern_size)
      return false;

    const std::uint8_t first_xored = pattern[0] ^ 0x66;

    for (std::size_t i = 0; i <= buffer_size - pattern_size; ++i) {
      if (buffer[i] != first_xored)
        continue;

      bool matched = true;
      for (std::size_t j = 1; j < pattern_size; ++j) {
        if (buffer[i + j] != (pattern[j] ^ 0x66)) {
          matched = false;
          break;
        }
      }

      if (matched)
        return true;
    }

    return false;
  }

  bool find_manifest_in_buffer(const std::uint8_t* buffer, std::size_t buffer_size) {
    constexpr std::size_t sig_len = sizeof(manifest_signature) - 1;
    if (buffer_size < sig_len)
      return false;

    for (std::size_t i = 0; i <= buffer_size - sig_len; ++i) {
      if (std::memcmp(&buffer[i], manifest_signature, sig_len) == 0)
        return true;
    }

    return false;
  }
} // namespace

namespace detections {
  void scan_self_process_memory_for_imgui() {
    SYSTEM_INFO si{};
    GetSystemInfo(&si);

    auto* addr = static_cast<std::uint8_t*>(si.lpMinimumApplicationAddress);
    const auto* max_addr = static_cast<std::uint8_t*>(si.lpMaximumApplicationAddress);

    while (addr < max_addr) {
      MEMORY_BASIC_INFORMATION mbi{};
      if (!VirtualQueryEx(GetCurrentProcess(), addr, &mbi, sizeof(mbi)))
        break;

      if (mbi.State == MEM_COMMIT &&
          mbi.Type != MEM_IMAGE &&
          (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_EXECUTE_READWRITE)) {

        std::vector<std::uint8_t> buffer(mbi.RegionSize);
        SIZE_T bytes_read = 0;

        if (ReadProcessMemory(GetCurrentProcess(), mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytes_read) &&
            bytes_read > 0) {

          if (match_xor66_pattern(buffer.data(), bytes_read, imgui_pattern, sizeof(imgui_pattern))) {
            std::string region_info = std::format(
                    "0x{:X} size=0x{:X}",
                    reinterpret_cast<std::uintptr_t>(mbi.BaseAddress), mbi.RegionSize
            );

            loader::append_report(message_id::imgui_region, "IMGUI", region_info, nullptr, 0);
            utils::submit_screenshot_report("IMGUI");
            return;
          }
        }
      }

      addr = static_cast<std::uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
    }
  }

  // only targets charmap.exe
  void scan_remote_process_for_manifest(const utils::process_info& process) {
    if (!utils::str_icontains(process.name_w, L"charmap"))
      return;

    HANDLE hprocess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, process.pid);
    if (!hprocess)
      return;

    loader::append_report(message_id::remote_scan_start, process.name, process.path, nullptr, 0);

    SYSTEM_INFO si{};
    GetSystemInfo(&si);

    auto* addr = static_cast<std::uint8_t*>(si.lpMinimumApplicationAddress);
    const auto* max_addr = static_cast<std::uint8_t*>(si.lpMaximumApplicationAddress);

    while (addr < max_addr) {
      MEMORY_BASIC_INFORMATION mbi{};
      if (!VirtualQueryEx(hprocess, addr, &mbi, sizeof(mbi)))
        break;

      if (mbi.State == MEM_COMMIT && mbi.Protect == PAGE_EXECUTE_READWRITE) {
        std::vector<std::uint8_t> buffer(mbi.RegionSize);
        SIZE_T bytes_read = 0;

        if (ReadProcessMemory(hprocess, mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytes_read) &&
            bytes_read > 0) {

          if (find_manifest_in_buffer(buffer.data(), bytes_read)) {
            std::string region_info = std::format(
                    "0x{:X}+0x{:X} in {}",
                    reinterpret_cast<std::uintptr_t>(mbi.BaseAddress), mbi.RegionSize, process.path
            );

            loader::append_report(message_id::manifest2, "MANIFEST2", region_info, nullptr, 0);
            utils::submit_screenshot_report("MANIFEST2");

            CloseHandle(hprocess);
            return;
          }
        }
      }

      addr = static_cast<std::uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
    }

    CloseHandle(hprocess);
  }
} // namespace detections
