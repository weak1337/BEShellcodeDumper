#include "utils.h"
#include <fstream>
#include <intrin.h>
#include <string>

using GetProcAddy_t = FARPROC(__stdcall*)(_In_ HMODULE hModule,_In_ LPCSTR lpProcName);
using CreateHook_t = uint64_t(__fastcall*)(LPVOID, LPVOID, LPVOID*);
using EnableHook_t = uint64_t(__fastcall*)(LPVOID, bool);
using EnableHookQueu_t = uint64_t(__stdcall*)(VOID);
CreateHook_t CreateHook = nullptr;
EnableHook_t EnableHook = nullptr;
EnableHookQueu_t EnableHookQue = nullptr;
bool init = false;
bool discord_hook(uintptr_t original, uintptr_t hook, uintptr_t tramp)
{
    if (!init) {
        uintptr_t discord_base = (uintptr_t)GetModuleHandleA("DiscordHook64.dll");
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(((PIMAGE_DOS_HEADER)discord_base)->e_lfanew + discord_base);
        DWORD discord_size = nt->OptionalHeader.SizeOfImage;
        CreateHook = (CreateHook_t)utils::scanpattern((uintptr_t)GetModuleHandleA("DiscordHook64.dll"), discord_size, "41 57 41 56 56 57 55 53 48 83 EC 68 4D 89 C6 49 89 D7");
        EnableHook = (EnableHook_t)utils::scanpattern((uintptr_t)GetModuleHandleA("DiscordHook64.dll"), discord_size,"41 56 56 57 53 48 83 EC 28 49 89 CE BF 01 00 00 00 31 C0 F0 ? ? ? ? ? ? ? 74");
        EnableHookQue = (EnableHookQueu_t)utils::scanpattern((uintptr_t)GetModuleHandleA("DiscordHook64.dll"), discord_size, "41 57 41 56 41 55 41 54 56 57 55 53 48 83 EC 38 48 ? ? ? ? ? ? 48 31 E0 48 89 44 24 30 BE 01 00 00 00 31 C0 F0 ? ? ? ? ? ? ? 74 2B" );
        init = true;
    }
    if (CreateHook((LPVOID)original, (LPVOID)hook, (LPVOID*)tramp) == 0)
    {
        if (EnableHook((LPVOID)original, true) == 0)
        {
            if (EnableHookQue() == 0)
            {
                return true;
            }
        }
    }

    return false;
}
std::vector<uintptr_t>dumped_shellcodes;
GetProcAddy_t origalgetproc;
LPVOID hookproc(
    _In_ HMODULE hModule,
    _In_ LPCSTR lpProcName) {
    uintptr_t retaddy = (uintptr_t)_ReturnAddress();
    MEMORY_BASIC_INFORMATION mbi{ 0 };
    size_t return_length{ 0 };
    if (NtQueryVirtualMemory((HANDLE)-1, (PVOID)retaddy, MemoryBasicInformation, &mbi, sizeof(mbi), &return_length) == 0) {
        if (
            mbi.State == MEM_COMMIT &&
            mbi.Protect == PAGE_EXECUTE_READWRITE && mbi.RegionSize > 0x1000
            )
        {
            if (std::find(dumped_shellcodes.begin(), dumped_shellcodes.end(), (uintptr_t)mbi.AllocationBase) == dumped_shellcodes.end()) {
                std::string to_stream = "C:\\Users\\weak\\Desktop\\r6dmps\\shellcode\\" + std::to_string((uintptr_t)mbi.BaseAddress) + ".dat"; //R6 has no admin rights so dont use paths like C:\file.dat
                printf("Call from be-shellcode dumping: %s\n", to_stream.c_str());
                uintptr_t possible_shellcode_start = utils::scanpattern((uintptr_t)mbi.BaseAddress, mbi.RegionSize, "4C 89");
                printf("Possible entry-rva: %x\n", possible_shellcode_start - (uintptr_t)mbi.BaseAddress);
                utils::CreateFileFromMemory(to_stream, (char*)mbi.BaseAddress, mbi.RegionSize);
                dumped_shellcodes.push_back((uintptr_t)mbi.AllocationBase);
            }      
        }
    }
    return origalgetproc(hModule, lpProcName);
}

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL, 
    DWORD fdwReason,  
    LPVOID lpReserved) 
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH: {
        AllocConsole();
        freopen("CONOUT$", "w", stdout);
        if (discord_hook((uintptr_t)GetProcAddress, (uintptr_t)hookproc, (uintptr_t)&origalgetproc))
            printf("Hook success\n");
        else
            printf("Hook failed\n");
        break;
    }
    }
    return TRUE; 
}