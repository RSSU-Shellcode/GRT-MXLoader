#ifndef DEBUG_H
#define DEBUG_H

#include "build.h"
#include "c_types.h"

#ifdef ENABLE_DEBUGGER

bool InitDebugger();

void dbg_lock();
void dbg_unlock();

void dbg_log(char* mod, char* fmt, ...);

#else

#define InitDebugger() (true)

#define dbg_lock()
#define dbg_unlock()

#define dbg_log(mod, fmt, ...)

#endif // ENABLE_DEBUGGER

#endif // DEBUG_H
