#ifndef PE_IMAGE_H
#define PE_IMAGE_H

#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"

typedef BOOL (*DllMain_t)
(
    HMODULE hModule, DWORD dwReason, LPVOID lpReserved
);

#endif // PE_IMAGE_H
