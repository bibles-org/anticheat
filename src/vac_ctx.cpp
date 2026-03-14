#include <windows.h>
#include "vac_ctx.hpp"

extern "C" NTSTATUS NtQueryPerformanceCounter(PLARGE_INTEGER PerformanceCounter, PLARGE_INTEGER PerformanceFrequency);

vac_ctx::vac_ctx() {
    NtQueryPerformanceCounter(&counter_start, &freq_start);
    NtQueryPerformanceCounter(&counter_start, nullptr);
    counter_copy = counter_start;
    DagorWClass = FindWindowW(L"DagorWClass", nullptr);
}

bool vac_ctx::on_process_attach() {
    LARGE_INTEGER curr_count{};
    NtQueryPerformanceCounter(&curr_count, nullptr);

    constexpr double ms_per_sec = 1000.0;
    constexpr double timeout_ms = 60'000.0;
    const double elapsed_ms =
            (curr_count.LowPart - counter_start.LowPart) * ms_per_sec / static_cast<double>(freq_start.QuadPart);

    if (elapsed_ms < timeout_ms)
        return true;

    return false;
    /*
    * scan_modules_for_rwx_section();
    * scan_nvidia_overlay();
    * scan_medal_overlay();
    */
    /*v3 = capture_process_snapshot();
    v4 = v3;
    if ( v3 )
    {
    v5 = v3;
    for ( proccess_cur = v3; validate_process_name(proccess_cur) && v5->NextEntryOffset; proccess_cur = v5 )
    v5 = (SYSTEM_PROCESS_INFORMATION *)((char *)v5 + v5->NextEntryOffset);
    RtlFreeHeap(v4);
    }
    scan_all_windows();
    v7 = 1;
    if ( filtered_processid_list(L"rustdesk.exe") )
    {
    v7 = 3;
    if ( filtered_processid_list(&L"powershell.exe") )
    {
    v8 = 1;
    }
    }
    */
}