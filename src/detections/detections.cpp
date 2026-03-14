#include "detections.hpp"

#include <cstdint>
#include <cstring>
#include <format>
#include <iostream>
#include <string>
#include <vector>
#include <windows.h>

#include "../loader/loader.hpp"
#include "../utils/file.hpp"
#include "../utils/screenshot.hpp"
#include "../utils/window.hpp"

#include <bits/ostream.tcc>
#include <winternl.h>

extern "C" NTSTATUS NtQueryVirtualMemory(HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T);

namespace {
    IMAGE_SECTION_HEADER* find_rwx_section(std::uint8_t* base) {
        const auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return nullptr;

        const auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
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
    bool
    extract_pdb_info(std::uint8_t* base, std::string& out_filename, std::string& out_guid, std::uint32_t& out_age) {
        const auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return false;

        const auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)
            return false;

        const auto& [VirtualAddress, Size] = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
        if (!VirtualAddress || !Size)
            return false;

        const auto* dbg_entries = reinterpret_cast<IMAGE_DEBUG_DIRECTORY*>(base + VirtualAddress);
        const int count = Size / sizeof(IMAGE_DEBUG_DIRECTORY);

        for (int i = 0; i < count; i++) {
            if (dbg_entries[i].Type != IMAGE_DEBUG_TYPE_CODEVIEW)
                continue;

            const auto* cv = reinterpret_cast<const std::uint32_t*>(base + dbg_entries[i].AddressOfRawData);
            const std::uint32_t signature = cv[0];

            if (signature == 'SDSR') { // RSDS PDB 7.0
                const auto* guid = reinterpret_cast<const GUID*>(&cv[1]);
                const auto age = cv[5];
                auto pdbname = reinterpret_cast<const char*>(&cv[6]);

                out_filename = pdbname;
                out_guid = std::format(
                        "{:08X}{:04X}{:04X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}", guid->Data1, guid->Data2,
                        guid->Data3, guid->Data4[0], guid->Data4[1], guid->Data4[2], guid->Data4[3], guid->Data4[4],
                        guid->Data4[5], guid->Data4[6], guid->Data4[7]
                );
                out_age = age;
                return true;

            } else if (signature == '01BN' || signature == '90BN') { // NB10/NB09  PDB 2.0
                const auto age = cv[3];
                auto pdbname = reinterpret_cast<const char*>(&cv[4]);

                out_filename = pdbname;
                out_guid = std::format("{:08X}", cv[2]);
                out_age = age;
                return true;
            }
        }

        return false;
    }
} // namespace

namespace detections {
    void scan_loaded_modules() {
        const PEB* peb = NtCurrentTeb()->ProcessEnvironmentBlock;
        if (!peb || !peb->Ldr)
            return;

        const LIST_ENTRY* head = &peb->Ldr->InMemoryOrderModuleList;
        LIST_ENTRY* entry = head->Flink;
        while (entry != head) {
            const LDR_DATA_TABLE_ENTRY* mod = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
            entry = entry->Flink;

            if (!mod->DllBase)
                continue;

            auto base = static_cast<std::uint8_t*>(mod->DllBase);
            const auto full_path_w = std::wstring(mod->FullDllName.Buffer, mod->FullDllName.Length / sizeof(wchar_t));
            const auto full_path = std::string(full_path_w.begin(), full_path_w.end());

            if (IMAGE_SECTION_HEADER* rwx_section = find_rwx_section(base)) {
                char raw_name[9] = {};
                for (int j = 0; j < 8; j++) { // normalize
                    const std::uint8_t c = rwx_section->Name[j];
                    if (!c)
                        break;
                    raw_name[j] = (c >= ' ' && c <= '~') ? static_cast<char>(c) : '?';
                }

                std::string section_tag = std::format(
                        "{} [Va=0x{:x}, Pa=0x{:x}, RawSize=0x{:x}]", raw_name, rwx_section->VirtualAddress,
                        rwx_section->Misc.PhysicalAddress, rwx_section->SizeOfRawData
                );

                std::vector<std::uint8_t> file_buf = utils::read_file_contents(full_path_w);

                loader::append_report(
                        message_id::rwx_section, section_tag.c_str(), section_tag.size(), full_path.c_str(),
                        full_path.size(), file_buf.empty() ? nullptr : file_buf.data(), file_buf.size()
                );

                if (!file_buf.empty()) {
                    std::memset(file_buf.data(), 0, file_buf.size());
                    file_buf.clear();
                }

                utils::submit_screenshot_report("EXECSECTION");

                const std::uintptr_t section_va = reinterpret_cast<std::uintptr_t>(base) + rwx_section->VirtualAddress;
                MEMORY_BASIC_INFORMATION mbi = {};
                SIZE_T return_len = 0;
                if (NtQueryVirtualMemory(
                            reinterpret_cast<HANDLE>(-1LL), reinterpret_cast<void*>(section_va), 0, &mbi, sizeof(mbi),
                            &return_len
                    ) < 0)
                    std::memset(&mbi, 0, sizeof(mbi));

                if (mbi.Protect && !(mbi.Protect & PAGE_GUARD) && !(mbi.Protect & PAGE_NOACCESS)) {
                    loader::append_report(
                            message_id::accessible_rwx_section, section_tag.c_str(), section_tag.size(),
                            full_path.c_str(), full_path.size(), reinterpret_cast<std::uint8_t*>(&mbi), sizeof(mbi)
                    );
                }
            }

            std::string pdb_filename, pdb_guid;
            std::uint32_t pdb_age = 0;
            if (extract_pdb_info(base, pdb_filename, pdb_guid, pdb_age) && !pdb_filename.empty()) {
                std::wstring pdb_path_w(pdb_filename.begin(), pdb_filename.end());

                if (utils::touch_file(pdb_path_w)) {
                    std::vector<std::uint8_t> pdb_buf = utils::read_file_contents(pdb_path_w);

                    loader::append_report(
                            message_id::pdb, "PDB", 3,
                            pdb_filename.c_str(), pdb_filename.size(),
                            pdb_buf.empty() ? nullptr : pdb_buf.data(), pdb_buf.size()
                    );

                    if (!pdb_buf.empty()) {
                        std::memset(pdb_buf.data(), 0, pdb_buf.size());
                        pdb_buf.clear();
                    }
                }
            }
        }
    }

    void scan_nvidia_overlay() {
        HWND hwnd = FindWindowA("CEF-OSC-WIDGET", "NVIDIA GeForce Overlay");
        if (!hwnd)
            return;

        if (const utils::window_info wi = utils::get_window_info(hwnd, 0xFFFFFFFF);
            wi.wi.dwExStyle & WS_EX_TRANSPARENT) {
            const std::string process_info = utils::format_window_process_info(wi);
            const std::string geometry_info = utils::format_window_geometry_info(wi);

            loader::append_report(
                    message_id::suspicious_nvidia_overlay, geometry_info.c_str(), geometry_info.size(),
                    process_info.c_str(), process_info.size(), nullptr, 0
            );

            utils::submit_screenshot_report("GeForce_");
        }
    }

    void scan_medal_overlay() {
        const HWND hwnd = FindWindowA("MedalOverlayClass", "MedalOverlay");
        if (!hwnd)
            return;

        if (const utils::window_info wi = utils::get_window_info(hwnd, 0xFFFFFFFF);
            wi.win_width > 100 && wi.win_height > 100 && (wi.wi.dwExStyle & WS_EX_TOPMOST)) {
            const std::string process_info = format_window_process_info(wi);
            const std::string geometry_info = format_window_geometry_info(wi);

            loader::append_report(
                    message_id::suspicious_medal_overlay, geometry_info.c_str(), geometry_info.size(),
                    process_info.c_str(), process_info.size(), nullptr, 0
            );

            utils::submit_screenshot_report("MEDAL");
        }
    }
} // namespace detections
