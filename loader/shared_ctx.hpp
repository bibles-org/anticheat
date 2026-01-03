#ifndef SHARED_LOADER_CTX_HPP
#define SHARED_LOADER_CTX_HPP
#include <memory>
#include <cstdint>

struct shared_loader_ctx {
    using queue_append_fn = void (*)(
            std::uint32_t message_id, const wchar_t* str1, std::uint32_t str1_len, const wchar_t* str2,
            std::uint32_t str2_len, const std::uint8_t* data, std::uint32_t data_len
    );
    static constexpr std::uint32_t magic_constant = 0x504c4730; // 'PLG0'

    std::uint32_t magic = magic_constant;
    std::uint8_t pad_[4]{};
    std::uint64_t scan_limit{};
    std::uint64_t xor_key{}; // the doesnt pass the function address directly, it
                             // xors it and
    // passes the xor key and the resulting value.
    queue_append_fn append_report_to_queue{};
    void* payload_base{};
    void* unk{};
};

std::unique_ptr<shared_loader_ctx> make_loader_ctx();
#endif // SHARED_LOADER_CTX_HPP
