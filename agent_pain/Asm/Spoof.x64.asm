[BITS 64]

global SpoofCall

[SECTION .text$B]
    SpoofCall:
        ; ----------------------------------------------------------------
        ; Initial setup
        ; ----------------------------------------------------------------
        pop rax             ; save real return address
        mov r10, rdi        ; preserve original rdi (arg1) in r10
        mov r11, rsi        ; preserve original rsi (arg2) in r11

        mov rdi, [rsp + 40] ; load SpoofSetup* into rdi  ([rsp+0x28] after pop)
        mov rsi, [rsp + 32] ; load target function into rsi ([rsp+0x20] after pop)

        ; ----------------------------------------------------------------
        ; Save callee-saved registers into the spoof struct
        ; ----------------------------------------------------------------
        mov [rdi + 0x50], r10       ; save original rdi
        mov [rdi + 0x58], r11       ; save original rsi
        mov [rdi + 0x60], r12
        mov [rdi + 0x68], r13
        mov [rdi + 0x70], r14
        mov [rdi + 0x78], r15

        mov r12, rax                ; keep real return address in r12

        ; ----------------------------------------------------------------
        ; Pre-calculate where stack args land after fake-stack setup.
        ; r14 = total bytes that will be subtracted from rsp:
        ;   0x200 scratch + 8 (NULL push) + First.Size + Second.Size + Gadget.Size
        ; Subtract 0x20 so the first arg (after the 4 reg args + return addr)
        ; aligns to [rsp+0x28] relative to the target's entry rsp.
        ; ----------------------------------------------------------------
        xor r11, r11
        mov r13, [rdi + 0x80]       ; ArgCount (12)

        mov r14, 0x200
        add r14, 8
        add r14, [rdi + 0x08]       ; + First.Size
        add r14, [rdi + 0x18]       ; + Second.Size
        add r14, [rdi + 0x28]       ; + Gadget.Size
        sub r14, 0x20

        lea r10, [rsp + 0x28]       ; points to SpoofSetup* slot; loop advances past it

        ; ----------------------------------------------------------------
        ; Copy stack arguments (arg5..arg12) to their new positions
        ; ----------------------------------------------------------------
        .set_args:
            xor r15, r15
            cmp r11d, r13d
            je  .finish

            sub r14, 8
            mov r15, rsp
            sub r15, r14

            add r10, 8
            push qword [r10]
            pop  qword [r15]

            add r11, 1
            jmp .set_args

        ; ----------------------------------------------------------------
        ; Build the fake call stack
        ; ----------------------------------------------------------------
        .finish:
        sub rsp, 0x200
        push 0                      ; NULL - terminates stack walk

        ; RtlUserThreadStart frame
        sub rsp, [rdi + 0x08]
        mov r11, [rdi + 0x00]       ; First.Ptr
        mov [rsp], r11

        ; BaseThreadInitThunk frame
        sub rsp, [rdi + 0x18]
        mov r11, [rdi + 0x10]       ; Second.Ptr
        mov [rsp], r11

        ; gadget frame  - `jmp [rbx]` in kernel32
        sub rsp, [rdi + 0x28]
        mov r11, [rdi + 0x20]       ; Gadget.Ptr
        mov [rsp], r11

        ; ----------------------------------------------------------------
        ; Wire up restoration and jump to target
        ; ----------------------------------------------------------------
        mov r11, rsi                        ; target function

        mov [rdi + 0x40], r12               ; store real return address
        mov [rdi + 0x48], rbx               ; save rbx
        lea rbx, [rel .restore]             ; address of restoration routine
        mov [rdi], rbx                      ; overwrite First.Ptr slot with .restore
        mov rbx, rdi                        ; rbx = SpoofSetup* (preserved by target)

        ; syscall path: load SSN into rax, rcx → r10
        mov r10, rcx
        mov rax, [rdi + 0x38]

        jmp r11                             ; jump (not call) - fake stack is the "call"

        ; ----------------------------------------------------------------
        ; Restoration routine - entered via `jmp [rbx]` gadget after target returns
        ; ----------------------------------------------------------------
        .restore:
            mov rcx, rbx                    ; rcx = SpoofSetup*

            ; unwind the fake stack frames
            add rsp, 0x200
            add rsp, [rbx + 0x08]           ; First.Size
            add rsp, [rbx + 0x18]           ; Second.Size
            add rsp, [rbx + 0x28]           ; Gadget.Size

            ; restore all saved registers
            mov rbx, [rcx + 0x48]
            mov rdi, [rcx + 0x50]
            mov rsi, [rcx + 0x58]
            mov r12, [rcx + 0x60]
            mov r13, [rcx + 0x68]
            mov r14, [rcx + 0x70]
            mov r15, [rcx + 0x78]

            jmp [rcx + 0x40]                ; jump to real return address
