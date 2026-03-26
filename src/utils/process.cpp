#include "process.hpp"
#include <cstdint>
#include <experimental/scope>
#include <windows.h>

#include "file.hpp"
#include "string.hpp"

namespace utils {
  process_info::process_info(const SYSTEM_PROCESS_INFORMATION& process) {
    pid = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(process.UniqueProcessId));
    name_w = process.ImageName.Buffer
                     ? std::wstring{process.ImageName.Buffer, process.ImageName.Length / sizeof(wchar_t)}
                     : std::wstring{};
    path_w = get_process_image_path(pid);

    if (path_w.empty())
      path_w = name_w;

    name = wide_to_utf8(name_w);
    path = wide_to_utf8(path_w);
    file_size = path_w.empty() ? 0 : timestomp_and_get_file_size(path_w);
  }

  std::vector<process_info> get_processes() {
    std::vector<std::uint8_t> buffer{};
    std::uint32_t size{};

    NTSTATUS status{};
    while ((status = NtQuerySystemInformation(
                    SystemProcessInformation, buffer.data(), static_cast<std::uint32_t>(buffer.size()),
                    reinterpret_cast<ULONG*>(&size)
            )) == 0xC0000004) {
      buffer.resize(size);
    }

    if (!NT_SUCCESS(status))
      return {};

    std::vector<process_info> snapshot{};
    auto* process = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(buffer.data());

    while (true) {
      snapshot.emplace_back(*process);
      if (!process->NextEntryOffset)
        break;
      process = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
              reinterpret_cast<std::uint8_t*>(process) + process->NextEntryOffset
      );
    }

    return snapshot;
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
