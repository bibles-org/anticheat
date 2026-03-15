#ifndef PROCESS_HPP
#define PROCESS_HPP
#include <string>
#include <vector>
#include <winternl.h>

namespace utils {
  std::vector<SYSTEM_PROCESS_INFORMATION> capture_process_snapshot();
  std::wstring get_process_image_path(DWORD pid);
  CLIENT_ID get_current_cid_from_teb();
} // namespace utils

#endif // PROCESS_HPP
