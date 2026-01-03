#ifndef IMPORTS_HPP
#define IMPORTS_HPP
#include <windows.h>

extern "C" NTSTATUS NtQueryPerformanceCounter(PLARGE_INTEGER PerformanceCounter, PLARGE_INTEGER PerformanceFrequency);

#endif // IMPORTS_HPP
