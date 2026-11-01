#include "pain_shellcode.h"

// Running shellcode via function pointer - PainSC::Data lives in .text so no RWX needed
extern "C" __attribute__((noreturn)) void loader_entry(void) {
    void (*sc)(void) = (void(*)(void))PainSC::Data;
    sc();
    __builtin_unreachable();
}