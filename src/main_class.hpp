#ifndef MAIN_CLASS_HPP
#define MAIN_CLASS_HPP
#include <cstdint>
#include <vector>
#include <windows.h>
#include <winternl.h>

struct main_class {
    LARGE_INTEGER freq_start{};
    LARGE_INTEGER counter_start{};
    LARGE_INTEGER counter_copy{};
    HWND DagorWClass{};

    main_class();
    virtual ~main_class() = default;

    virtual bool scan_cheat_flags();
    virtual bool on_attach();
    virtual void on_detach();
    void scan_modules_for_rwx_section();
    void scan_nvidia_overlay();
    void scan_medal_overlay();
    static std::vector<SYSTEM_PROCESS_INFORMATION> capture_process_snapshot();
    std::uint32_t get_process_id_by_name(wchar_t* name);
    void win10_scan_user_execution_history();
    void win11_scan_execution_history();
    void check_system_integrity();
};

#endif //MAIN_CLASS_HPP
