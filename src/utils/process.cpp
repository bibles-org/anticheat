#include "process.hpp"
#include <cstdint>
#include <experimental/scope>
#include <windows.h>

namespace utils {
  std::vector<SYSTEM_PROCESS_INFORMATION> capture_process_snapshot() {
    std::vector<std::uint8_t> buffer{};
    std::uint32_t size{};

    NTSTATUS status{};
    while ((status = NtQuerySystemInformation(
                    SystemProcessInformation, buffer.data(), static_cast<std::uint32_t>(buffer.size()),
                    reinterpret_cast<ULONG*>(&size)
            )) == 0xC0000004) { // STATUS_INFO_LENGTH_MISMATCH
      buffer.resize(size);
    }

    std::vector<SYSTEM_PROCESS_INFORMATION> process_snapshot{};
    auto process = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
            buffer.data() + reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(buffer.data())->NextEntryOffset
    );
    while (process->NextEntryOffset) {
      process_snapshot.emplace_back(*process);
      process = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
              reinterpret_cast<std::uint8_t*>(process) + process->NextEntryOffset
      );
    }
    return process_snapshot;
  }

  std::wstring get_process_image_path(DWORD pid) {
    const bool is_self = (reinterpret_cast<HANDLE>(pid) == get_current_cid_from_teb().UniqueProcess);
    const HANDLE process = is_self ? GetCurrentProcess() : OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);

    if (!is_self && !process)
      return {};

    std::experimental::scope_exit proc_guard([&] {
      if (!is_self)
        CloseHandle(process);
    });

    wchar_t path_buf[512]{};
    auto size = static_cast<DWORD>(std::size(path_buf));
    if (!QueryFullProcessImageNameW(process, 0, path_buf, &size))
      return {};

    return {path_buf, size};
  }

  CLIENT_ID get_current_cid_from_teb() {
    const auto teb = NtCurrentTeb();
    return *reinterpret_cast<CLIENT_ID*>(reinterpret_cast<std::uint8_t*>(teb) + 0x40);
  }
} // namespace utils
