# Pain

<img width="1536" height="1024" alt="Pain_Picture" src="https://github.com/user-attachments/assets/b19a8d05-dd08-4cc6-94d5-140667f2fcbd" />


Pain is a custom C2 agent built for the [Adaptix](https://github.com/Adaptix-Framework/AdaptixC2) framework. It was written from scratch as a learning project, heavily inspired by [Kharon](https://github.com/entropy-z/Kharon).

The goal was simple - understand how a real implant works by building one. No shortcuts, no borrowed shellcode loaders, just writing it piece by piece and figuring out why things break.

> **Requires Adaptix v2.0** - Pain targets the v2.0 plugin API. The public `main` branch of AdaptixC2 may be ahead of or behind this. Use the `testing-v2.0` branch when cloning the framework.

---

## Requirements

Clone the framework and switch to the correct branch before building:

```bash
git clone https://github.com/Adaptix-Framework/AdaptixC2.git
cd AdaptixC2
git checkout testing-v2.0
```

Then build the Adaptix client and server according to the AdaptixC2 instructions, and come back here to run `setup_pain.sh`.

---

## What it does

- **Position-Independent Code** - the agent is a raw `.bin` shellcode blob, no PE headers, no reflective loader needed
- **HTTP and HTTPS transport** - talks to the C2 over HTTP POST, supports HTTPS with self-signed cert bypass
- **Malleable HTTP profiles** - upload a JSON profile when creating a listener to control the URI, User-Agent, custom request headers (e.g. `x-amz-date`), and server response format per callback; traffic can be made to blend in with real services (S3, CDN APIs, etc.)
- **Domain rotation** - multiple C2 hosts baked into one agent at build time; three strategies selectable per listener: round-robin, random (LCG), or failover
- **Sleep obfuscation** - three selectable techniques, all park the main thread in `NtSignalAndWaitForSingleObject` while a timer-pool chain does the work:
  - *Ekko* - creates a fresh timer queue; flips shellcode RW, encrypts it with `SystemFunction040`, XORs the tracked heap, spoofs the sleep stack, then reverses everything before waking
  - *EkkoGraft* - same chain but grafts onto an existing thread-pool timer queue instead of creating one, leaving fewer new kernel objects behind
  - *TimerSpoof* - drives the same encrypt/decrypt cycle through `NtSetTimer2` rather than a named queue
- **Sleep-time stack spoofing** - a step in every sleep chain calls `NtGetContextThread` to save the real RSP/RIP, then `NtSetContextThread` to replace the parked thread's saved context with a hand-built fake stack (`NtSignalAndWait → kernel32 gadget → BaseThreadInitThunk+0x14 → RtlUserThreadStart+0x21`); the real context is restored before the thread wakes, so a scanner inspecting the sleeping thread sees no agent addresses
- **Live call stack spoofing (SpoofCall)** - wraps every sensitive NT/WinAPI call with a synthetic call chain: pops the real return address, builds fake frames (`jmp [rbx]` gadget → `BaseThreadInitThunk` → `RtlUserThreadStart`) on the stack using UNWIND_INFO frame sizes, then `jmp`s to the target; covers active execution - the call stack at the exact moment of a suspicious syscall shows only legitimate Windows frames
- **Heap tracking** - all agent allocations go through a private heap with a linked-list tracker; the full heap gets XOR'd during sleep
- **Runtime UUID** - every execution generates a fresh identity from ASLR entropy so running the same binary twice gives two separate sessions
- **Authentication** - two optional modes baked in at build time:
  - *Command Auth* - a random 16-byte key is generated per build, multiple runs of the same binary are allowed
  - *One-Time Key* - same thing but the server consumes the key on first check-in, any second run gets rejected
- **Multiple output formats** - generate as `Pain.x64.exe` (standalone loader), `Pain.x64.svc.exe` (Windows Service), `Pain.x64.dll`, or a raw shellcode `.bin`
- **BOF Support** - runs Beacon Object Files in-process with a full COFF loader and Beacon API implementation; compatible with the [Adaptix Extension-Kit](https://github.com/Adaptix-Framework/Extension-Kit) BOFs out of the box (whoami, execute-assembly, and the rest of the standard set)

---

## How it's structured

```
agent_pain/         the agent shellcode (C++, compiled to .bin)
  Source/           beacon logic - transport, tasks, sleep, heap, crypto
  Include/          headers
  Asm/              PIC entry point (x64 NASM)
  src_loader/       thin loaders that embed and run the shellcode
  src_server/       Adaptix Go plugin - registers the agent, handles check-ins

listener_pain_http/ HTTP listener plugin for Adaptix
```

---

## Building

You need `x86_64-w64-mingw32-g++`, `nasm`, and Go installed.

```bash
./setup_pain.sh --ax /path/to/AdaptixC2
```

This builds and installs both the agent and listener plugins, then rebuilds the Adaptix server binary to keep plugin API versions in sync.

Once the server is running, generate a payload from the Adaptix UI - pick your output format and authentication mode and hit generate.

---

## Status

Work in progress. The core beacon loop is solid - check-in, polling, basic commands (shell, pwd, ls, exit), sleep obfuscation, HTTPS, malleable profiles, domain rotation, and BOF execution all work.

The SMB listener exists and is partially functional but is **not stable** - it is still in active development and not ready for real use.

Built while reading Kharon's source and figuring out how each piece fits together.

---

## What's Coming

- **Sacrificial Process for execute-assembly** - currently `execute-assembly` runs the CLR in-process and leaves JIT RWX pages behind; the plan is to inject into a short-lived sacrificial process, collect output over a named pipe, and kill it - keeping the agent process clean
- **More Stack Spoofing** - extend live spoofing to cover more call sites; handle spoofing across injected threads and BOF execution contexts
- **More Evasion Capabilities** - AMSI/ETW bypass, indirect syscalls during the timer chain, syscall obfuscation
- **SMB Listener** - peer-to-peer beaconing over named pipes *(implemented, stabilisation in progress)*

Good things are coming. Just not all at once.
