#ifndef LOADER_HPP
#define LOADER_HPP
#include <cstdint>
#include <string_view>

enum class message_id : std::uint32_t{
  wine = 0,
  screenshot = 0x2694,
  screenshot_error = 0x0000,
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
  blacklisted_paths = 0x26A0,
  ida_history_entry = 0x2240,
  visual_studio_project_entry = 0x2241,
  visual_studio_private_settings = 0x2242,
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
