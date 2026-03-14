#ifndef MAIN_CLASS_HPP
#define MAIN_CLASS_HPP
#include <winternl.h>

class vac_ctx {
    LARGE_INTEGER freq_start{};
    LARGE_INTEGER counter_start{};
    LARGE_INTEGER counter_copy{};
    HWND DagorWClass{};

public:
    vac_ctx();
    virtual ~vac_ctx() = default;

    virtual bool on_process_attach();
};

#endif //MAIN_CLASS_HPP
