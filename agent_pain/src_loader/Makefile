CXX    = x86_64-w64-mingw32-g++
TARGET = Pain.x64.exe

# Shellcode loader: no CRT, custom entry, no windows subsystem header
CXXFLAGS = -nostdlib            \
           -nostartfiles        \
           -fno-stack-protector \
           -fno-exceptions      \
           -fno-rtti            \
           -mno-stack-arg-probe \
           -O2

LDFLAGS = -Wl,-e,loader_entry      \
          -Wl,--subsystem,windows  \
          -Wl,-s

# Standard flags for normal Win32 binaries (DLL + service)
CXXFLAGS_NORMAL = -O2 -fno-exceptions -fno-rtti -Wl,-s

all: $(TARGET)

$(TARGET): loader.cc pain_shellcode.h
	@echo "[CXX] compiling loader..."
	@$(CXX) $(CXXFLAGS) loader.cc -o $(TARGET) $(LDFLAGS)
	@echo "[OK]  $(TARGET) ready"

Pain.x64.dll: dll_loader.cc pain_shellcode.h
	@echo "[CXX] compiling DLL..."
	@$(CXX) $(CXXFLAGS_NORMAL) -shared -o Pain.x64.dll dll_loader.cc
	@echo "[OK]  Pain.x64.dll ready"

Pain.x64.svc.exe: svc_loader.cc pain_shellcode.h
	@echo "[CXX] compiling service..."
	@$(CXX) $(CXXFLAGS_NORMAL) -mwindows -o Pain.x64.svc.exe svc_loader.cc -ladvapi32
	@echo "[OK]  Pain.x64.svc.exe ready"

clean:
	rm -f $(TARGET) Pain.x64.dll Pain.x64.svc.exe
