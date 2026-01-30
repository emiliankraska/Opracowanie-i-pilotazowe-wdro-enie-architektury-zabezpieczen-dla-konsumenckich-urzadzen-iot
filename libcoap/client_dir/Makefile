# Makefile for libcoap minimal examples
#
# Copyright (C) 2018-2024 Olaf Bergmann <bergmann@tzi.org>
#

LIBCOAP?=libcoap-3-wolfssl

pkgconfig=$(shell pkg-config $(1) $(2))
CPPFLAGS=-Wall -Wextra $(call pkgconfig,--cflags,$(LIBCOAP))
LDLIBS=$(call pkgconfig,--libs,$(LIBCOAP))
LINK.o=$(LINK.cc)

CXXFLAGS=-std=c++14

all: client

client:: client.o common.o

clean:
	rm -f *.o client