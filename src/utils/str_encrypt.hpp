#ifndef STR_ENCRYPT_HPP
#define STR_ENCRYPT_HPP
#include <array>
#include <cstdint>

// even though this will not be used in the code its still here
// to showcase the string encryption that was originally implemented
template <std::size_t N>
struct wstr_enc {
    std::array<wchar_t, N> data;

    constexpr wchar_t xor_char(const wchar_t c, const std::size_t i) {
        const std::uint16_t key = (i / 55) * 55;
        return c ^ static_cast<wchar_t>(i - key + 50);
    }

    constexpr wstr_enc(const wchar_t (&str)[N]) : data{} {
        for (std::size_t i = 0; i < data.size(); ++i) {
            if (!str[i]) continue;
            data[i] = xor_char(str[i], i);
        }
    }
};

#endif //STR_ENCRYPT_HPP
