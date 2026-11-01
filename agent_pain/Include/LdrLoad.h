#ifndef LDRLOAD_H
#define LDRLOAD_H

#include <windows.h>
#include <stdint.h>

namespace LdrLoad
{
    auto Module(
        uint32_t hash
    ) -> ULONG_PTR;

    auto _Api(
        ULONG_PTR module_base,
        uint32_t hash
    ) -> ULONG_PTR;
}

#endif