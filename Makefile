# BoAT Attestor (C) - Makefile for native build on riscv64 board
# Builds boat-attest-c linking against BoAT v4 SDK (built as a static library)

CC      ?= gcc
CFLAGS  := -Wall -O2 -std=c11 -D_GNU_SOURCE \
           -DBOAT_EVM_ENABLED=1 -DBOAT_PAY_X402_ENABLED=1 -DBOAT_SOL_ENABLED=0
LDFLAGS := -lcurl -lssl -lcrypto -lcjson -lpthread -lm

# BoAT4 SDK - cloned from GitHub if not present
BOAT4_DIR    := BoAT4
BOAT4_REPO   := https://github.com/boat-x/BoAT4.git
BOAT4_COMMIT := main

# BoAT4 build output
BOAT4_BUILD  := $(BOAT4_DIR)/build
BOAT4_LIB    := $(BOAT4_BUILD)/libboat4.a

# Include paths
INCLUDES := -I$(BOAT4_DIR)/include \
            -I$(BOAT4_DIR)/third-party/crypto \
            -I/usr/include/riscv64-linux-gnu \
            -I/usr/include/cjson

TARGET := boat-attest-c

.PHONY: all clean distclean deps boat4

all: deps boat4 $(TARGET)

# Clone BoAT4 SDK from GitHub if not present
deps:
	@if [ ! -d "$(BOAT4_DIR)/include" ]; then \
		echo "Cloning BoAT4 SDK from $(BOAT4_REPO)..."; \
		git clone --depth 1 --branch $(BOAT4_COMMIT) $(BOAT4_REPO) $(BOAT4_DIR); \
	fi

# Build BoAT4 as a static library using its CMake build system
boat4: deps
	@if [ ! -f "$(BOAT4_LIB)" ]; then \
		echo "Building BoAT4 SDK..."; \
		cmake -S $(BOAT4_DIR) -B $(BOAT4_BUILD) \
			-DBOAT_EVM=ON \
			-DBOAT_SOL=OFF \
			-DBOAT_PAY_X402=ON \
			-DBOAT_PAY_NANO=OFF \
			-DBOAT_PAY_GATEWAY=OFF \
			-DBOAT_VENDOR_CJSON=ON \
			-DBOAT_PAL=linux \
			-DCMAKE_C_FLAGS="-D_GNU_SOURCE -I/usr/include/cjson" \
			> /dev/null; \
		cmake --build $(BOAT4_BUILD) -- -j$$(nproc) > /dev/null; \
	fi

$(TARGET): boat-attest-c.c $(BOAT4_LIB)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ boat-attest-c.c $(BOAT4_LIB) $(LDFLAGS)

clean:
	rm -f $(TARGET)

# Rebuild BoAT4 from scratch
boat4-clean:
	rm -rf $(BOAT4_BUILD)

# Remove everything including cloned SDK
distclean: clean
	rm -rf $(BOAT4_DIR)
