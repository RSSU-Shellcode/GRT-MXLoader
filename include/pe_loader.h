#ifndef PE_LOADER_H
#define PE_LOADER_H

#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "hash_api.h"
#include "errno.h"
#include "runtime.h"

typedef void* (*GetProc_t)(LPSTR name);
typedef errno (*Execute_t)();
typedef errno (*Exit_t)(uint exitCode);
typedef errno (*Destroy_t)();

typedef struct {
    // use custom FindAPI from Gleam-RT for hook.
    FindAPI_t FindAPI;

    // PE image memory address.
    void* Image;

    // for hook GetCommandLineA and GetCommandLineW,
    // if them are NULL, call original GetCommandLine.
    void* CommandLineA;
    void* CommandLineW;

    // wait main thread exit if it is a exe image.
    bool WaitMain;

    // if failed to load library, can continue it.
    bool AllowSkipDLL;

    // set standard handles for hook GetStdHandle,
    // if them are NULL, call original GetStdHandle.
    HANDLE StdInput;
    HANDLE StdOutput;
    HANDLE StdError;

    // not erase instructions after call functions about Init or Exit.
    bool NotEraseInstruction;

    // adjust current memory page protect.
    bool NotAdjustProtect;
} PELoader_Cfg;

typedef struct {
    // absolute memory address about PE entry point.
    void* EntryPoint;

	// this PE image is a DLL.
    bool IsDLL;

    // main thread return value or argument about call ExitProcess.
    uint ExitCode;

    // get export procedure address by name, must call Execute before call it.
    GetProc_t GetProc;

    // create a thread at EntryPoint or call DllMain with DLL_PROCESS_ATTACH.
    // it can call multi times.
    Execute_t Execute;

    // release all resource or call DllMain with DLL_PROCESS_DETACH.
    // it can call multi times.
    Exit_t Exit;

    // destroy all resource about PE loader, it can only call one time.
    Destroy_t Destroy;
} PELoader_M;

// InitPELoader is used to initialize PE loader, it will load PE file
// from memory, but it will not run it, caller must use PELoader_M.
// If failed to initialize, use GetLastError to get error code.
PELoader_M* InitPELoader(Runtime_M* runtime, PELoader_Cfg* cfg);

#endif // PE_LOADER_H
