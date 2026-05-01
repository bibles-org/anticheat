#include "../loader/loader.hpp"
#include "../utils/file.hpp"
#include "../utils/screenshot.hpp"
#include "detections.hpp"

#include <cstring>
#include <experimental/scope>
#include <format>
#include <windows.h>

extern "C" NTSTATUS NtQueryVirtualMemory(HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T);

namespace {
  IMAGE_SECTION_HEADER* find_rwx_section(const utils::module_info& module) {
    auto dos = module.get_dos_header();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
      return nullptr;

    auto nt = module.get_nt_headers();
    if (nt->Signature != IMAGE_NT_SIGNATURE)
      return nullptr;

    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
      if (const DWORD c = sections[i].Characteristics;
          (c & IMAGE_SCN_MEM_READ) && (c & IMAGE_SCN_MEM_WRITE) && (c & IMAGE_SCN_MEM_EXECUTE))
        return &sections[i];
    }

    return nullptr;
  }

  // for some reason the guid and age arent used..
  bool extract_pdb_info(
          const utils::module_info module, std::string& out_filename, std::string& out_guid, std::uint32_t& out_age
  ) {
    auto dos = module.get_dos_header();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
      return false;

    auto nt = module.get_nt_headers();
    if (nt->Signature != IMAGE_NT_SIGNATURE)
      return false;

    const auto& [debug_rva, debug_size] = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    if (!debug_rva || !debug_size)
      return false;

    const auto* debug_entries = reinterpret_cast<IMAGE_DEBUG_DIRECTORY*>(module.base + debug_rva);
    const int count = debug_size / sizeof(IMAGE_DEBUG_DIRECTORY);

    for (int i = 0; i < count; i++) {
      if (debug_entries[i].Type != IMAGE_DEBUG_TYPE_CODEVIEW)
        continue;

      const auto* code_view = reinterpret_cast<const std::uint32_t*>(module.base + debug_entries[i].AddressOfRawData);
      const std::uint32_t signature = code_view[0];

      if (signature == 'SDSR') { // RSDS PDB 7.0
        const auto* guid = reinterpret_cast<const GUID*>(&code_view[1]);
        const auto age = code_view[5];
        auto pdbname = reinterpret_cast<const char*>(&code_view[6]);

        out_filename = pdbname;
        out_guid = std::format(
                "{:08X}{:04X}{:04X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}", guid->Data1, guid->Data2,
                guid->Data3, guid->Data4[0], guid->Data4[1], guid->Data4[2], guid->Data4[3], guid->Data4[4],
                guid->Data4[5], guid->Data4[6], guid->Data4[7]
        );
        out_age = age;
        return true;
      }
      if (signature == '01BN' || signature == '90BN') { // NB10/NB09  PDB 2.0
        const auto age = code_view[3];
        auto pdbname = reinterpret_cast<const char*>(&code_view[4]);

        out_filename = pdbname;
        out_guid = std::format("{:08X}", code_view[2]);
        out_age = age;
        return true;
      }
    }

    return false;
  }
} // namespace


namespace detections {
  void validate_modules(const std::vector<utils::module_info>& modules) {
    for (const auto& module : modules) {
      if (IMAGE_SECTION_HEADER* rwx_section = find_rwx_section(module)) {
        char raw_name[9] = {};
        for (int j = 0; j < 8; j++) { // normalize
          const std::uint8_t c = rwx_section->Name[j];
          if (!c)
            break;
          raw_name[j] = (c >= ' ' && c <= '~') ? static_cast<char>(c) : '?';
        }

        std::string section_tag = std::format(
                "{} [Va={:#x}, Pa={:#x}, RawSize={:#x}]", raw_name, rwx_section->VirtualAddress,
                rwx_section->Misc.PhysicalAddress, rwx_section->SizeOfRawData
        );

        std::vector<std::uint8_t> file_buf = utils::read_file_contents(module.path_w);

        loader::append_report(
                message_id::rwx_section, section_tag, module.path, file_buf.empty() ? nullptr : file_buf.data(),
                file_buf.size()
        );
        utils::submit_screenshot_report("EXECSECTION");

        std::uint8_t* section_va = module.base + rwx_section->VirtualAddress;
        MEMORY_BASIC_INFORMATION mbi{};
        SIZE_T return_len = 0;
        if (NtQueryVirtualMemory(reinterpret_cast<HANDLE>(-1LL), section_va, 0, &mbi, sizeof(mbi), &return_len) < 0)
          std::memset(&mbi, 0, sizeof(mbi));

        if (mbi.Protect && !(mbi.Protect & PAGE_GUARD) && !(mbi.Protect & PAGE_NOACCESS)) {
          loader::append_report(
                  message_id::accessible_rwx_section, section_tag, module.path, reinterpret_cast<std::uint8_t*>(&mbi),
                  sizeof(mbi)
          );
        }
      }

      std::string pdb_filename, pdb_guid;
      std::uint32_t pdb_age = 0;
      if (extract_pdb_info(module, pdb_filename, pdb_guid, pdb_age) && !pdb_filename.empty()) {
        std::wstring pdb_path_w(pdb_filename.begin(), pdb_filename.end());

        if (utils::touch_file(pdb_path_w)) {
          std::vector<std::uint8_t> pdb_buf = utils::read_file_contents(pdb_path_w);

          loader::append_report(
                  message_id::pdb, "PDB", pdb_filename, pdb_buf.empty() ? nullptr : pdb_buf.data(), pdb_buf.size()
          );
        }
      }
    }
  }

  void check_module_image_size_mismatch(const std::vector<utils::module_info>& modules) {
    for (const auto& module : modules) {
      auto dos = module.get_dos_header();
      if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        continue;

      auto nt = module.get_nt_headers();
      if (nt->Signature != IMAGE_NT_SIGNATURE)
        continue;

      if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        continue;

      const DWORD memory_image_size = nt->OptionalHeader.SizeOfImage;

      const HANDLE hfile = CreateFileW(
              module.path_w.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
              nullptr
      );
      if (hfile == INVALID_HANDLE_VALUE)
        continue;

      std::experimental::scope_exit file_guard([&] {
        CloseHandle(hfile);
      });

      IMAGE_DOS_HEADER disk_dos{};
      DWORD bytes_read = 0;
      if (!ReadFile(hfile, &disk_dos, sizeof(disk_dos), &bytes_read, nullptr) || bytes_read != sizeof(disk_dos))
        continue;

      if (disk_dos.e_magic != IMAGE_DOS_SIGNATURE)
        continue;

      if (SetFilePointer(hfile, disk_dos.e_lfanew, nullptr, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
        continue;

      IMAGE_NT_HEADERS64 disk_nt{};
      if (!ReadFile(hfile, &disk_nt, sizeof(disk_nt), &bytes_read, nullptr) || bytes_read < sizeof(disk_nt))
        continue;

      if (disk_nt.Signature != IMAGE_NT_SIGNATURE)
        continue;

      if (disk_nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        continue;

      const DWORD disk_image_size = disk_nt.OptionalHeader.SizeOfImage;

      if (memory_image_size != disk_image_size) {
        std::string size_info = std::format("MEMORY={:#x}, DISK={:#x}", memory_image_size, disk_image_size);

        loader::append_report(message_id::module_image_size_mismatch, size_info, module.path, nullptr, 0);
      }
    }
  }

  void check_ntdll_exception_dispatcher() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll)
      return;

    auto ki_user_exception_dispatcher = GetProcAddress(ntdll, "KiUserExceptionDispatcher");
    if (!ki_user_exception_dispatcher)
      return;

    constexpr std::uint32_t expected_prologue = 0x058B48FC;
    const auto prologue = *reinterpret_cast<std::uint32_t*>(ki_user_exception_dispatcher);

    if (prologue != expected_prologue) {
      std::string path_buf(MAX_PATH, '\0');
      GetModuleFileNameA(ntdll, path_buf.data(), MAX_PATH);

      loader::append_report(message_id::exception_dispatcher_mismatch, "ntdll.dll", path_buf, nullptr, 0);
    }
  }
} // namespace detections
