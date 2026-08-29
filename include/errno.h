#ifndef ERRNO_H
#define ERRNO_H

#include "c_types.h"

typedef uint32 errno;

void  SetLastErrno(errno errno);
errno GetLastErrno();

// 0x00······ module id
// 0x··00···· error flags
// 0x····00·· major error id
// 0x······00 minor error id

#define NO_ERROR 0x00000000

#define ERR_FLAG_CAN_IGNORE 0x00010000

#endif // ERRNO_H
