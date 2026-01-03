#ifndef STR_ENCRYPT_HPP
#define STR_ENCRYPT_HPP
#include <array>
#include <cstdint>

template <std::size_t N>
struct wstr_enc {
    std::array<wchar_t, N> data;

    constexpr wchar_t xor_char(wchar_t c, std::size_t i) {
        const std::uint16_t key = (i / 55) * 55;
        return c ^ static_cast<wchar_t>(i - key + 50);
    }

    constexpr wstr_enc(const wchar_t (&str)[N]) : data{} {
        for (std::size_t i = 0; i < data.size(); ++i) {
            if (!str[i]) continue;
            data[i] = xor_char(str[i], i);
        }
    }

    // ..
    const wchar_t* decrypt() {
        for (std::size_t i = 0; i < data.size(); ++i) {
            if (!data[i]) continue;
            data[i] = xor_char(data[i], i);
        }
        return data.data();
    }
};


#endif //STR_ENCRYPT_HPP
