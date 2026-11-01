# Pain

Pain is a custom C2 agent built for the [Adaptix](https://github.com/Adaptix-Framework/AdaptixC2) framework. It was written from scratch as a learning project, heavily inspired by [Kharon](https://github.com/MrAle98/Kharon).

The goal was simple - understand how a real implant works by building one. No shortcuts, no borrowed shellcode loaders, just writing it piece by piece and figuring out why things break.

---

## What it does

- **Position-Independent Code** - the agent is a raw `.bin` shellcode blob, no PE headers, no reflective loader needed
- **HTTP and HTTPS transport** - talks to the C2 over HTTP POST, supports HTTPS with self-signed cert bypass
- **Sleep obfuscation** - uses the EKKO timer-chain technique to encrypt memory and spoof the call stack while sleeping
- **Heap tracking** - all agent allocations go through a private heap with a linked-list tracker; the full heap gets XOR'd during sleep
- **Runtime UUID** - every execution generates a fresh identity from ASLR entropy so running the same binary twice gives you two separate sessions
- **Authentication** - two optional modes baked in at build time:
  - *Command Auth* - a random 16-byte key is generated per build, multiple runs of the same binary are allowed
  - *One-Time Key* - same thing but the server consumes the key on first check-in, any second run gets rejected
- **Multiple output formats** - generate as a standalone EXE loader, a Windows Service EXE, a DLL, or a raw shellcode `.bin`

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

- **BOF API Support** - execute Beacon Object Files in-process with a proper API proxy layer
- **More Sleep Techniques** - EKKO is in, but there are other approaches worth implementing and comparing
- **More Stack Spoofing** - currently spoofing the main thread's call stack during sleep; more ways to handle this across different execution contexts
- **More Evasion Capabilities** - AMSI/ETW bypass, syscall obfuscation, and other techniques as the project matures
- **C2 Profile Support** - malleable HTTP profiles so traffic patterns can be customized per engagement
- **SMB Listener** - peer-to-peer beaconing over named pipes for internal network pivoting

Good things are coming. Just not all at once.
