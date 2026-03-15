#ifndef LOADER_HPP
#define LOADER_HPP
#include <cstdint>
#include <string_view>

enum class message_id {
  screenshot = 0x2694u,
  screenshot_error = 0u,
  rwx_section = 0x1409u,
  accessible_rwx_section = 0x1420u,
  pdb = 0x142Du,
  suspicious_nvidia_overlay = 0x13A5u,
  suspicious_medal_overlay = 0x13E8u,
  war_overlay = 0x1396u,
  china_script = 0x13B8u,
  test_window = 0x13A0u,
  air_bot = 0x13AEu,
  farm_bot = 0x138Eu,
  ccip_main = 0x13BAu,
  hong2 = 0x13A3u,
  bombscope = 0x13BDu,
  cachebot = 0x13C1u,
  ccrp7 = 0x13C3u,
  v13bot = 0x13C6,
  takeoff_bot = 0x13CBu,
  macro1 = 0x13D0u,
  j6 = 0x13DDu,
  exemix = 0x13E6u,
  rdesk = 0x13F2u,
  vmware2 = 0x13D7u,
  botlauncher = 0x141Du,
  sip_tampered = 0x142Au,
  appinit_dlls = 0x142Bu,
  monkrel = 0x1418u,
  aceaim = 0x13A7u,
  lean_thunder = 0x13A8u,
  lean_thunder2 = 0x13F8u,
  thunder = 0x13A6u,
  yellow = 0x13A9u,
  winners_circle = 0x13AAu,
  wtace = 0x13ABu,
  unix = 0x13ACu,
  softhub = 0x13ADu,
  cmd_empty = 0x13C7u,
  charmap = 0x13C8u,
  unkmason = 0x13B5u,
  script4wt = 0x13B6u,
  navalrb1 = 0x13B7u,
  hades3 = 0x13BFu,
  ccip = 0x139Du,
  ez = 0x139Au,
  chinabot = 0x139Bu,
  acs = 0x139Cu,
  wtshipbot = 0x13A2u,
  asm_ = 0x13AFu,
  reverser = 0x13B0u,
  navalab1 = 0x13B2u,
  test_kern = 0x13C2u,

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
