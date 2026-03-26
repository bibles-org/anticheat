#ifndef MODULE_HPP
#define MODULE_HPP
#include <cstdint>
#include <string>
#include <vector>
#include <winternl.h>

namespace utils {
  struct module_info {
    std::wstring name_w;
    std::string name;
    std::wstring path_w;
    std::string path;
    std::uint8_t* base;

    module_info(const LDR_DATA_TABLE_ENTRY& ldr_entry);
    PIMAGE_DOS_HEADER get_dos_header() const;
    PIMAGE_NT_HEADERS get_nt_headers() const;
  };

  std::vector<module_info> get_modules();
} // namespace utils
#endif // MODULE_HPP
