SECTIONS
{
    .text :
    {
        *(.text$A)      /* Entry asm will land here, this is byte 0 of the shellcode */
        *(.text$B)      /* DECLFN data/functions */
        *(.text$BC)     /* DECLFN_CODE - functions in TUs that also have DECLFN data */
        *(.rdata*)      /*  Read-Only data: vtables, const arrays */
        *(.text$C)      /*  EndPtr label must land last */
    }
}