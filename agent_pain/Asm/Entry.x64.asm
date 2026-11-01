[BITS 64]

EXTERN Main                         ; C_++ entry function defined in Main.cc

GLOBAL StartPtr                     ; StartPtr() that returns base address of shellcode 
GLOBAL EndPtr                       ; EndPtr() that returns address of last byte of shellcode

;; Linker puts this section first - shellcode entry lands here
[SECTION .text$A]
    Start:
    ;; Preserve rsi (callee-saved) we use it to hold the original rsp
    push rsi
    ;; save original rsp before we forcibly align it
    mov rsi, rsp
    ;; Align stack to 16-byte (-16) boundary (Windows x64 ABI)
    and rsp, 0FFFFFFFFFFFFFFF0h
    ;; Allocate 32-byte shadow space
    sub rsp, 0x20
    ;; rcx still holds the arguments the loader passed from Main
    call Main
    ;; restore original (unligned) rsp and callee-saved rsi
    mov rsp, rsi
    pop rsi
    ret

    StartPtr:
        ;; Trick: call pushes address of the Next Instruction [rip]
        ;; that gives us a know runtime address we can math off of
        call RetStartPtr
        ret                            ;; sit at offset 0x1b from start this is what [rsp] points to inside RetStartPtr

    RetStartPtr:
        ;; [rsp] = Address of the ret above = Start + 0x1b
        ;; subtract 0x1b to get back to Start, which IS the base of the shellcode
        ;; Making sure that it match the exact byte size from Start ... ret
        mov rax, [rsp]
        sub rax, 0x1b
        ret

;; Linker puts this section in last - EndPtr marks the end of the shellcode
[SECTION .text$C]
    EndPtr:
        ;; Same  call/pop trick - call pushes address of the ret below (EndPtr + 5)
        call RetEndPtr
        ret                             ;; sits at EndPtr + 5 (call rel32 is always 5 bytes)

    RetEndPtr:
        ;; [rsp] = EndPtr + 5, subtrct 5 to get EndPtr itself
        mov rax, [rsp]
        sub rax, 0x5
        ret