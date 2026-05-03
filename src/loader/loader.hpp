#ifndef LOADER_HPP
#define LOADER_HPP
#include <cstdint>
#include <format>
#include <string_view>

enum class message_id : std::uint32_t {
  wine = 0,
  screenshot_error = 0,
  screenshot = 0x2694,
  rwx_section = 0x1409,
  accessible_rwx_section = 0x1420,
  pdb = 0x142D,
  suspicious_nvidia_overlay = 0x13A5,
  suspicious_medal_overlay = 0x13E8,
  war_overlay = 0x1396,
  china_script = 0x13B8,
  test_window = 0x13A0,
  air_bot = 0x13AE,
  farm_bot = 0x138E,
  ccip_main = 0x13BA,
  hong2 = 0x13A3,
  bombscope = 0x13BD,
  cachebot = 0x13C1,
  ccrp7 = 0x13C3,
  v13bot = 0x13C6,
  takeoff_bot = 0x13CB,
  macro1 = 0x13D0,
  j6 = 0x13DD,
  exemix = 0x13E6,
  rdesk = 0x13F2,
  vmware2 = 0x13D7,
  botlauncher = 0x141D,
  sip_tampered = 0x142A,
  appinit_dlls = 0x142B,
  monkrel = 0x1418,
  aceaim = 0x13A7,
  lean_thunder = 0x13A8,
  lean_thunder2 = 0x13F8,
  thunder = 0x13A6,
  yellow = 0x13A9,
  winners_circle = 0x13AA,
  wtace = 0x13AB,
  unix = 0x13AC,
  softhub = 0x13AD,
  cmd_empty = 0x13C7,
  charmap = 0x13C8,
  unkmason = 0x13B5,
  script4wt = 0x13B6,
  navalrb1 = 0x13B7,
  hades3 = 0x13BF,
  ccip = 0x139D,
  ez = 0x139A,
  chinabot = 0x139B,
  acs = 0x139C,
  wtshipbot = 0x13A2,
  asm_ = 0x13AF,
  reverser = 0x13B0,
  navalab1 = 0x13B2,
  test_kern = 0x13C2,
  present_hook = 0x1403,
  imgui_region_or_xml_region = 0x1436,
  remote_scan_start = 0x1432,
  module_image_size_mismatch = 0x1F43,
  exception_dispatcher_mismatch = 0x1F48,
  blacklisted_paths = 0x26A0,
  ida_history_entry = 0x2240,
  visual_studio_project_entry = 0x2241,
  visual_studio_private_settings = 0x2242,
};

template <>
struct std::formatter<message_id> {
  constexpr auto parse(const auto& ctx) {
    return ctx.begin();
  }

  constexpr auto format(const message_id& id, auto& ctx) const {
    std::string_view result = [&id]() {
      switch (id) {
        using enum message_id;
        case wine:
          return "wine or screenshot_error";
        case screenshot:
          return "screenshot";
        case rwx_section:
          return "rwx_section";
        case accessible_rwx_section:
          return "accessible_rwx_section";
        case pdb:
          return "pdb";
        case suspicious_nvidia_overlay:
          return "suspicious_nvidia_overlay";
        case suspicious_medal_overlay:
          return "suspicious_medal_overlay";
        case war_overlay:
          return "war_overlay";
        case china_script:
          return "china_script";
        case test_window:
          return "test_window";
        case air_bot:
          return "air_bot";
        case farm_bot:
          return "farm_bot";
        case ccip_main:
          return "ccip_main";
        case hong2:
          return "hong2";
        case bombscope:
          return "bombscope";
        case cachebot:
          return "cachebot";
        case ccrp7:
          return "ccrp7";
        case v13bot:
          return "v13bot";
        case takeoff_bot:
          return "takeoff_bot";
        case macro1:
          return "macro1";
        case j6:
          return "j6";
        case exemix:
          return "exemix";
        case rdesk:
          return "rdesk";
        case vmware2:
          return "vmware2";
        case botlauncher:
          return "botlauncher";
        case sip_tampered:
          return "sip_tampered";
        case appinit_dlls:
          return "appinit_dlls";
        case monkrel:
          return "monkrel";
        case aceaim:
          return "aceaim";
        case lean_thunder:
          return "lean_thunder";
        case lean_thunder2:
          return "lean_thunder2";
        case thunder:
          return "thunder";
        case yellow:
          return "yellow";
        case winners_circle:
          return "winners_circle";
        case wtace:
          return "wtace";
        case unix:
          return "unix";
        case softhub:
          return "softhub";
        case cmd_empty:
          return "cmd_empty";
        case charmap:
          return "charmap";
        case unkmason:
          return "unkmason";
        case script4wt:
          return "script4wt";
        case navalrb1:
          return "navalrb1";
        case hades3:
          return "hades3";
        case ccip:
          return "ccip";
        case ez:
          return "ez";
        case chinabot:
          return "chinabot";
        case acs:
          return "acs";
        case wtshipbot:
          return "wtshipbot";
        case asm_:
          return "asm";
        case reverser:
          return "reverser";
        case navalab1:
          return "navalab1";
        case test_kern:
          return "test_kern";
        case present_hook:
          return "present_hook";
        case imgui_region_or_xml_region:
          return "imgui_region or xml_region";
        case remote_scan_start:
          return "remote_scan_start";
        case module_image_size_mismatch:
          return "module_image_size_mismatch";
        case exception_dispatcher_mismatch:
          return "exception_dispatcher_mismatch";
        case blacklisted_paths:
          return "blacklisted_paths";
        case ida_history_entry:
          return "ida_history_entry";
        case visual_studio_project_entry:
          return "visual_studio_project_entry";
        case visual_studio_private_settings:
          return "visual_studio_private_settings";

        default:
          return "unknown";
      }
    }();
    return std::format_to(ctx.out(), "{}", result);
  }
};

namespace loader {
  // this wont be used for the sake of simplicity
  struct shared_ctx {
    using queue_append_fn = void (*)(
            message_id id, wchar_t* str1, std::uint32_t str1_len, wchar_t* str2, std::uint32_t str2_len,
            std::uint8_t* data, std::uint32_t data_len
    );
    static constexpr std::uint32_t magic_constant = 0x504c4730; // 'PLG0'

    std::uint32_t magic = magic_constant;
    std::uint8_t padding[4]{};
    std::uint64_t scan_limit{};
    // the loader doesnt pass a raw function pointer, it instead
    // xors the address by the current tsc and stores both the key and the result
    // this behavior is very common and also used when dynamically
    // grabbing the necessary imports and storing them
    std::uint64_t xor_key{};
    queue_append_fn append_report_to_queue{};
    void* payload_base{};
    void* unk{};
  };

  void append_report(
          message_id id, const char* str1, std::uint32_t str1_len, const char* str2, std::uint32_t str2_len,
          const std::uint8_t* data, std::uint32_t data_len
  );

  inline void append_report(
          message_id id, std::string_view str1, std::string_view str2, const std::uint8_t* data, std::uint32_t data_len
  ) {
    append_report(id, str1.data(), str1.size(), str2.data(), str2.size(), data, data_len);
  }
} // namespace loader


#endif // LOADER_HPP
