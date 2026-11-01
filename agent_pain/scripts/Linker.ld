SECTIONS
{
    .text :
    {
        *(.text$A)      /* Entry asm will land here, this is byte 0 of the shellcode */
        *(.text$B)      /* All C++ Function marked DECLFN go here */
        *(.rdata*)      /*  Read-Only data: vtables, const arrays */
        *(.text$C)      /*  EndPtr label must land last */
    }
}