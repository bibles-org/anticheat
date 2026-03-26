#include "detections.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <string>
#include <vector>
#include <windows.h>

#include "../loader/loader.hpp"
#include "../utils/screenshot.hpp"

namespace {
  // mov rdx, rbx
  // mov rcx, r13
  // call rel32
  // mov [rsp+60h], eax
  // test eax, eax
  // 48 8B D3 49 8B CD E8 ?? ?? ?? ?? 89 44 24 60 85 C0
  constexpr auto call_pattern = std::to_array<std::uint8_t>(
          {0x48, 0x8B, 0xD3, 0x49, 0x8B, 0xCD, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x89, 0x44, 0x24, 0x60, 0x85, 0xC0}
  );


  // scan exported functions for call_pattern (bytes 7 10 are wildcard)
  // if capture_call_target, return the absolute destination of the call at offset 7
  // otherwise return the address of the matched bytes
  std::uint8_t* scan_exports(const utils::module_info& module, bool capture_call_target) {
    auto dos = module.get_dos_header();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
      return nullptr;

    auto nt = module.get_nt_headers();
    if (nt->Signature != IMAGE_NT_SIGNATURE)
      return nullptr;

    const auto& ed = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!ed.VirtualAddress)
      return nullptr;

    const auto* exp = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(module.base + ed.VirtualAddress);
    const auto* fn_rvas = reinterpret_cast<const DWORD*>(module.base + exp->AddressOfFunctions);
    const auto* ordinals = reinterpret_cast<const WORD*>(module.base + exp->AddressOfNameOrdinals);

    constexpr std::size_t k_window = 512;
    constexpr std::size_t k_len = sizeof(call_pattern);

    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
      const DWORD rva = fn_rvas[ordinals[i]];
      if (!rva)
        continue;
      const auto* fn = module.base + rva;

      for (std::size_t off = 0; off + k_len <= k_window; ++off) {
        bool ok = true;
        for (std::size_t k = 0; k < k_len && ok; ++k) {
          if (k >= 7 && k <= 10)
            continue; // rel32 wildcard
          if (fn[off + k] != call_pattern[k])
            ok = false;
        }
        if (!ok)
          continue;

        auto* hit = const_cast<std::uint8_t*>(fn + off);
        if (!capture_call_target)
          return hit;

        const auto rel32 = *reinterpret_cast<const std::int32_t*>(hit + 7);
        return hit + 11 + rel32;
      }
    }
    return nullptr;
  }

  struct jmp_class {
    int code;
    int op_off;
  };

  jmp_class classify_jmp(const std::uint8_t* p) {
    if (p[0] == 0xE9)
      return {2, 1};
    if (p[0] == 0xEB)
      return {3, 1};
    if (p[0] == 0x90 && p[1] == 0xE9)
      return {2, 2};
    if (p[0] == 0xFF && p[1] == 0x25 && p[6] == 0xCC)
      return {5, 2};
    if (p[0] == 0xFF && p[1] == 0x25 && *reinterpret_cast<const std::int32_t*>(p + 2) == 0)
      return {4, 6};
    return {0, 0};
  }

  // follows the jmp trampoline chain from start
  // non empty = function redirected
  std::vector<std::uintptr_t> resolve_jmp_chain(const std::uint8_t* start) {
    std::vector<std::uintptr_t> chain;
    auto* p = const_cast<std::uint8_t*>(start);

    for (int depth = 0; depth < 64; ++depth) {
      const auto [code, op_off] = classify_jmp(p);
      if (code == 2) {
        const auto rel32 = *reinterpret_cast<const std::int32_t*>(p + op_off);
        p = p + op_off + 4 + rel32;
      } else if (code == 3) {
        p = p + 2 + p[op_off];
      } else if (code == 4) {
        auto** ind = reinterpret_cast<std::uint8_t**>(p + op_off);
        if (!ind || !*ind)
          break;
        p = *ind;
      } else if (code == 5) {
        const auto rel32 = *reinterpret_cast<const std::int32_t*>(p + op_off);
        auto** ind = reinterpret_cast<std::uint8_t**>(p + 6 + rel32);
        if (!ind || !*ind)
          break;
        p = *ind;
      } else {
        break;
      }
      chain.push_back(reinterpret_cast<std::uintptr_t>(p));
    }
    return chain;
  }

  bool is_win10_build() {
    using fn_t = NTSTATUS(WINAPI*)(PRTL_OSVERSIONINFOW);
    const auto rtl_get_version =
            reinterpret_cast<fn_t>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion"));
    if (!rtl_get_version)
      return false;
    RTL_OSVERSIONINFOW vi{.dwOSVersionInfoSize = sizeof(vi)};
    if (rtl_get_version(&vi) < 0)
      return false;
    return vi.dwMajorVersion == 10 && vi.dwBuildNumber >= 0x55F0u;
  }
} // namespace

namespace detections {
  void check_present_hook(const std::vector<utils::module_info>& modules) {
    if (!is_win10_build())
      return;

    const auto dxgi_it = std::ranges::find_if(modules, [](const auto& module) -> bool {
      return module.name == "dxgi.dll";
    });

    if (dxgi_it == modules.end())
      return;

    const utils::module_info& dxgi = *dxgi_it;

    // scan for the Present stub walk back to the int3 boundary, check for a hook
    std::uint8_t* const present_match = scan_exports(dxgi, false);
    if (!present_match)
      return;

    auto* fn_start = present_match;
    for (std::size_t i = 0; i < 0x100u; ++i, --fn_start) {
      if (*fn_start == 0xCC) {
        ++fn_start;
        break;
      }
    }

    if (!resolve_jmp_chain(fn_start).empty()) {
      loader::append_report(message_id::present_hook, "PresentImpl", {}, nullptr, 0);
      utils::submit_screenshot_report("PresentImpl");
    }

    // scan for the ValidatePresent call target and check it directly
    std::uint8_t* const validate_target = scan_exports(dxgi, true);
    if (validate_target && !resolve_jmp_chain(validate_target).empty()) {
      loader::append_report(message_id::present_hook, "ValidatePresent", {}, nullptr, 0);
      utils::submit_screenshot_report("ValidatePresent");
    }
  }
} // namespace detections
