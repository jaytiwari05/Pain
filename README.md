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
- **Sleep obfuscation** - custom Ntdll timer-chain sleep: encrypts the shellcode in place with `SystemFunction040` (RtlEncryptMemory), XORs the heap, and spoof the main thread's call stack via `NtSetContextThread` - all while blocked in `NtSignalAndWaitForSingleObject`
- **Heap tracking** - all agent allocations go through a private heap with a linked-list tracker; the full heap gets XOR'd during sleep
- **Runtime UUID** - every execution generates a fresh identity from ASLR entropy so running the same binary twice gives you two separate sessions
- **Authentication** - two optional modes baked in at build time:
  - *Command Auth* - a random 16-byte key is generated per build, multiple runs of the same binary are allowed
  - *One-Time Key* - same thing but the server consumes the key on first check-in, any second run gets rejected
- **Multiple output formats** - generate as a standalone EXE loader, a Windows Service EXE, a DLL, or a raw shellcode `.bin`
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

This is a work in progress. The core beacon loop works - check-in, polling, basic commands (shell, pwd, ls, exit), sleep obfuscation, and HTTPS. Some things are still rough or not yet implemented.

Built while reading Kharon's source and figuring out how each piece fits together.

---

## What's Coming

The agent isn't production-ready yet but there's a clear roadmap of where it's going:

- **Sacrificial Process for execute-assembly** - currently `execute-assembly` runs the CLR in-process and leaves JIT RWX pages behind; the plan is to inject into a short-lived sacrificial process, collect output over a named pipe, and kill it - keeping the agent process clean
- **More Sleep Techniques** - the current timer-chain works but synthetic frame spoofing (building a believable fake call stack instead of substituting the timer thread's context) is the next step
- **More Stack Spoofing** - currently spoofing the main thread's call stack during sleep; more ways to handle this across different execution contexts
- **More Evasion Capabilities** - AMSI/ETW bypass, syscall obfuscation, and other techniques as the project matures
- **C2 Profile Support** - malleable HTTP profiles so traffic patterns can be customized per engagement
- **SMB Listener** - peer-to-peer beaconing over named pipes for internal network pivoting

Good things are coming. Just not all at once.
