CXX    = x86_64-w64-mingw32-g++
TARGET = loader.exe

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

pain.dll: dll_loader.cc pain_shellcode.h
	@echo "[CXX] compiling DLL..."
	@$(CXX) $(CXXFLAGS_NORMAL) -shared -o pain.dll dll_loader.cc
	@echo "[OK]  pain.dll ready"

pain_svc.exe: svc_loader.cc pain_shellcode.h
	@echo "[CXX] compiling service..."
	@$(CXX) $(CXXFLAGS_NORMAL) -mwindows -o pain_svc.exe svc_loader.cc -ladvapi32
	@echo "[OK]  pain_svc.exe ready"

clean:
	rm -f $(TARGET) pain.dll pain_svc.exe
