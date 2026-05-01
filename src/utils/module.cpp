#include "module.hpp"

#include "string.hpp"

namespace utils {
  module_info::module_info(const LDR_DATA_TABLE_ENTRY& ldr_entry) {
    base = static_cast<std::uint8_t*>(ldr_entry.DllBase);

    const _UNICODE_STRING* strings = &ldr_entry.FullDllName;

    if (const UNICODE_STRING& dll_name_ = strings[1]; dll_name_.Buffer)
      name_w = std::wstring{dll_name_.Buffer, dll_name_.Length / sizeof(wchar_t)};

    if (const UNICODE_STRING& dll_path_ = strings[0]; dll_path_.Buffer)
      path_w = std::wstring{dll_path_.Buffer, dll_path_.Length / sizeof(wchar_t)};

    name = utils::wide_to_utf8(name_w);
    path = utils::wide_to_utf8(path_w);
  }

  PIMAGE_DOS_HEADER module_info::get_dos_header() const {
    return reinterpret_cast<PIMAGE_DOS_HEADER>(base);
  }
  PIMAGE_NT_HEADERS module_info::get_nt_headers() const {
    return reinterpret_cast<PIMAGE_NT_HEADERS>(get_dos_header()->e_lfanew + base);
  }

  std::vector<module_info> get_modules() {
    std::vector<module_info> result{};
    const PEB* peb = NtCurrentTeb()->ProcessEnvironmentBlock;
    if (!peb || !peb->Ldr)
      return result;

    const LIST_ENTRY* head = &peb->Ldr->InMemoryOrderModuleList;
    LIST_ENTRY* entry = head->Flink;
    while (entry != head) {
      const LDR_DATA_TABLE_ENTRY* mod = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
      result.emplace_back(*mod);
      entry = entry->Flink;
    }

    return result;
  }
} // namespace utils
