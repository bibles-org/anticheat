#include "main_class.hpp"
#include "imports.hpp"
#include "str_encrypt.hpp"

main_class::main_class() {
    NtQueryPerformanceCounter(&counter_start, &freq_start);
    NtQueryPerformanceCounter(&counter_start, nullptr);
    counter_copy = counter_start;
    wstr_enc class_name{L"DagorWClass"};
    DagorWClass = FindWindowW(class_name.decrypt(), nullptr);
}

std::vector<SYSTEM_PROCESS_INFORMATION> main_class::capture_process_snapshot() {
    std::vector<std::uint8_t> buffer{};
    std::uint32_t size{};

    NTSTATUS status{};
    while ((status = NtQuerySystemInformation(SystemProcessInformation, buffer.data(), static_cast<std::uint32_t>(buffer.size()), reinterpret_cast<ULONG*>(&size))) == 0xC0000004) { // STATUS_INFO_LENGTH_MISMATCH
        buffer.resize(size);
    }

    std::vector<SYSTEM_PROCESS_INFORMATION> process_snapshot{};
    auto process = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(buffer.data() + reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(buffer.data())->NextEntryOffset);
    while (process->NextEntryOffset) {
        process_snapshot.emplace_back(*process);
        process = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
                reinterpret_cast<std::uint8_t*>(process) + process->NextEntryOffset
        );
    }
    return process_snapshot;
}

bool main_class::scan_cheat_flags() {

}

bool main_class::on_attach() {
    LARGE_INTEGER curr_count{};
    NtQueryPerformanceCounter(&curr_count, nullptr);

    constexpr double ms_per_sec = 1000.0;
    constexpr double timeout_ms = 60'000.0;
    const double elapsed_ms =
            (curr_count.LowPart - counter_start.LowPart) * ms_per_sec / static_cast<double>(freq_start.QuadPart);

    if (elapsed_ms < timeout_ms)
        return true;

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

void main_class::on_detach() {
}
