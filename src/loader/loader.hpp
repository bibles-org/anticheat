#ifndef LOADER_HPP
#define LOADER_HPP
#include <cstdint>

enum class message_id {
    screenshot = 0x2694u,
    screenshot_error = 0u,
    rwx_section = 0x1409u,
    accessible_rwx_section = 0x1420u,
    pdb = 0x142Du,
    suspicious_nvidia_overlay = 0x13A5u,
    suspicious_medal_overlay = 0x13E8u,
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
            std::uint8_t* data, std::uint32_t data_len
    );
} // namespace loader


#endif // LOADER_HPP
