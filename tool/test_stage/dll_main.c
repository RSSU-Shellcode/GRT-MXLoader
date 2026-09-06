#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "hash_api.h"

// a fake Cobalt-Strike stage for test

#pragma comment(linker, "/ENTRY:DllMain")
BOOL DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    // special reason for boot stage
    if (dwReason == 4) 
    {
        Sleep_t Sleep = FindAPI_A("kernel32.dll", "Sleep");
        Sleep(1000);
    }
    return true;
}
