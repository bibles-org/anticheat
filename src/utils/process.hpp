#ifndef PROCESS_HPP
#define PROCESS_HPP
#include <cstdint>
#include <string>
#include <vector>
#include <winternl.h>

namespace utils {
  struct process_info {
    std::uint32_t pid;
    std::wstring name_w;
    std::wstring path_w;
    std::string name;
    std::string path;
    std::size_t file_size;

    explicit process_info(const SYSTEM_PROCESS_INFORMATION&);
    process_info() = default;
  };


  std::vector<process_info> get_processes();
  std::wstring get_process_image_path(DWORD pid);
  CLIENT_ID get_current_cid_from_teb();
} // namespace utils

#endif // PROCESS_HPP
