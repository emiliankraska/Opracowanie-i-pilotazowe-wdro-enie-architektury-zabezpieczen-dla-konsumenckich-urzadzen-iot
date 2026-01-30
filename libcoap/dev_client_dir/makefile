# ===============================


# -------------------------------------------------------------------
# Minimal Makefile for cross-compiling with Buildroot toolchain
# -------------------------------------------------------------------

# Path to your Buildroot toolchain binaries
TOOLCHAIN_PATH := /home/emil/myStuff/buildroot-2025.02.7/output/host/opt/ext-toolchain/bin
# Cross-compiler prefix
CROSS_COMPILE := aarch64-buildroot-linux-gnu-

# Sysroot (optional, ensures headers/libs are from target)
SYSROOT := /home/emil/myStuff/buildroot-2025.02.7/output/host/aarch64-buildroot-linux-gnu/sysroot

# Compiler and flags
CC := $(TOOLCHAIN_PATH)/$(CROSS_COMPILE)gcc
CFLAGS := --sysroot=$(SYSROOT) -O2 

LFLAGS= -L$(SYSROOT)/usr/lib64
#LFLAGS = -L/home/emil/myStuff/buildroot-2025.02.7/output/target/usr/lib
LIBS := -lcoap-3-openssl -lssl -lcrypto -ldl -lpthread
#LIBS := -lcoap-3
INCLUDES := -I$(SYSROOT)/usr/include -I.

SRC := client-dev.cc
OBJ := $(SRC:.c=.o)
TARGET := client-dev

# Clean command
RM := rm -rf

# Pattern rule: compile .c -> .o
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Link objects into executable
$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LFLAGS) $(LIBS)

# Default target
all: $(TARGET)

# Clean up build artifacts
clean:
	$(RM) $(TARGET) *.o *~