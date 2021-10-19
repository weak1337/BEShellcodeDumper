#pragma once
#include <Windows.h>
#include <iostream>
#include <vector>
#include <fstream>
namespace utils {
    uintptr_t scanpattern(uintptr_t base, int size, const char* signature);
    bool CreateFileFromMemory(const std::string& desired_file_path, const char* address, size_t size);
}
typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;
extern "C" NTSYSCALLAPI NTSTATUS NtQueryVirtualMemory(
    HANDLE                   ProcessHandle,
    PVOID                    BaseAddress,
    MEMORY_INFORMATION_CLASS MemoryInformationClass,
    PVOID                    MemoryInformation,
    SIZE_T                   MemoryInformationLength,
    PSIZE_T                  ReturnLength
);
