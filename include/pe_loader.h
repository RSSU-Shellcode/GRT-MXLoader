#ifndef PE_LOADER_H
#define PE_LOADER_H

#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "hash_api.h"
#include "errno.h"
#include "runtime.h"

typedef void* (*GetProc_t)(LPSTR name);
typedef uint  (*ExitCode_t)();
typedef errno (*Start_t)();
typedef errno (*Wait_t)();
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

    // create NUL file for set StdInput, StdOutput and
    // StdError for ignore console input/output.
    // If it is true, it will overwrite standard handles.
    bool IgnoreStdIO;

    // set standard handles for hook GetStdHandle,
    // if them are NULL, call original GetStdHandle.
    HANDLE StdInput;
    HANDLE StdOutput;
    HANDLE StdError;

    // not running PE image after load.
    bool NotAutoRun;

    // not stop runtime when call ExitProcess.
    bool NotStopRuntime;

    // not erase instructions after call functions about Init or Exit.
    bool NotEraseInstruction;

    // adjust current memory page protect.
    bool NotAdjustProtect;
} PELoader_Cfg;

typedef struct {
    // absolute memory address about PE image base.
    void* ImageBase;

    // absolute memory address about PE entry point.
    void* EntryPoint;

    // is this PE image is a DLL image.
    bool IsDLL;

    // runtime mutex, need lock it before call some loader methods.
    HANDLE RuntimeMu;

    // get export procedure address by name, must call Execute before call it.
    GetProc_t GetProc;

    // get main thread return value or argument about call ExitProcess.
    ExitCode_t ExitCode;

    // create a thread at EntryPoint, it useless for DLL image.
    // it can call multi times with Wait and Exit.
    Start_t Start;

    // wait the thread at EntryPoint, it useless for DLL image.
    // it can call multi times with Start.
    Wait_t Wait;

    // create a thread at EntryPoint or call DllMain with DLL_PROCESS_ATTACH.
    // it can call multi times with Exit.
    Execute_t Execute;

    // release all resource or call DllMain with DLL_PROCESS_DETACH.
    // it can call multi times with Execute.
    Exit_t Exit;

    // destroy all resource about PE loader, it can only call once.
    // it will exit runtime, but caller need erase the remaining instruction.
    Destroy_t Destroy;
} PELoader_M;

// InitPELoader is used to initialize PE loader, it will load PE file
// from memory, but it will not run it, caller must use PELoader_M.
// If failed to initialize, use GetLastError to get error code.
extern PELoader_M* InitPELoader(Runtime_M* runtime, PELoader_Cfg* cfg);

#endif // PE_LOADER_H
