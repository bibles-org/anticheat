#include "../loader/loader.hpp"
#include "../utils/screenshot.hpp"
#include "../utils/string.hpp"
#include "detections.hpp"

#include <cstring>
#include <experimental/scope>
#include <format>
#include <windows.h>

namespace {
  // " Size=%"
  constexpr auto imgui_pattern = std::to_array<std::uint8_t>({0x20, 0x53, 0x69, 0x7a, 0x65, 0x3d, 0x25});
  // "<?xml version='1.0' encodin"
  constexpr auto xml_manifest_pattern =
          std::to_array<std::uint8_t>({0x3C, 0x3F, 0x78, 0x6D, 0x6C, 0x20, 0x76, 0x65, 0x72,
                                       0x73, 0x69, 0x6F, 0x6E, 0x3D, 0x27, 0x31, 0x2E, 0x30,
                                       0x27, 0x20, 0x65, 0x6E, 0x63, 0x6F, 0x64, 0x69, 0x6E});

  bool match_pattern(const std::span<const std::uint8_t>& buffer, const std::span<const std::uint8_t>& pattern) {
    if (pattern.empty() || buffer.size() < pattern.size())
      return false;

    for (std::size_t i = 0; i <= buffer.size() - pattern.size(); ++i) {
      if (buffer[i] == pattern[0] && std::memcmp(&buffer[i], pattern.data(), pattern.size()) == 0)
        return true;
    }

    return false;
  }
} // namespace

namespace detections {
  void scan_for_imgui_region() {
    SYSTEM_INFO si{};
    GetSystemInfo(&si);

    auto* addr = static_cast<std::uint8_t*>(si.lpMinimumApplicationAddress);
    const auto* max_addr = static_cast<std::uint8_t*>(si.lpMaximumApplicationAddress);

    while (addr < max_addr) {
      MEMORY_BASIC_INFORMATION mbi{};
      if (!VirtualQueryEx(GetCurrentProcess(), addr, &mbi, sizeof(mbi)))
        break;

      if (mbi.State == MEM_COMMIT && mbi.Type != MEM_IMAGE &&
          (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_EXECUTE_READWRITE)) {

        std::vector<std::uint8_t> buffer(mbi.RegionSize);
        SIZE_T bytes_read = 0;

        if (ReadProcessMemory(GetCurrentProcess(), mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytes_read) &&
            bytes_read > 0) {

          if (match_pattern(buffer, imgui_pattern)) {
            std::string region_info = std::format("Base={}, Size={:#x}", mbi.BaseAddress, mbi.RegionSize);

            loader::append_report(message_id::imgui_region, "IMGUI", region_info, nullptr, 0);
            utils::submit_screenshot_report("IMGUI");
            return;
          }
        }
      }

      addr = static_cast<std::uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
    }
  }

  void scan_process_for_xml_manifest(const utils::process_info& process) {
    if (!utils::str_icontains(process.name_w, L"charmap"))
      return;

    HANDLE hprocess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, process.pid);
    if (!hprocess)
      return;
    std::experimental::scope_exit process_guard{[&] {
      CloseHandle(hprocess);
    }};

    loader::append_report(message_id::remote_scan_start, process.name, process.path, nullptr, 0);

    SYSTEM_INFO si{};
    GetSystemInfo(&si);

    const auto* addr = static_cast<std::uint8_t*>(si.lpMinimumApplicationAddress);
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

          if (match_pattern(buffer, xml_manifest_pattern)) {
            std::string region_info =
                    std::format("Base={:}+Size={:#x} in '{}'", mbi.BaseAddress, mbi.RegionSize, process.path);

            loader::append_report(message_id::manifest2, "MANIFEST2", region_info, nullptr, 0);
            utils::submit_screenshot_report("MANIFEST2");

            CloseHandle(hprocess);
            return;
          }
        }
      }

      addr = static_cast<std::uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
    }
  }
} // namespace detections
