# Copyright (C) 2018 Guillaume Valadon <guillaume@valadon.net>

# Retrieve radare2 related information
R2_PLUGIN_PATH=$(HOME)/.local/share/radare2/plugins/
R2_INCLUDES_PATH=$(shell r2 -hh|grep INCDIR|awk '{print $$2}')
R2_CFLAGS=-g -fPIC $(shell pkg-config --cflags r_asm)

# Retrieve Python related information
PYTHON2_CFLAGS=$(shell python2-config --cflags)
PYTHON2_LDFLAGS=$(shell python2-config --ldflags)

# Prepare r2m2 specific variables
SO_EXT=$(shell uname|grep -q Darwin && echo dylib || echo so)
R2M2_LDFLAGS=-shared $(PYTHON2_LDFLAGS) $(shell pkg-config --libs r_asm)
R2M2_LIBS=r2m2_ad.$(SO_EXT) r2m2_Ae.$(SO_EXT)

# OS detection
OS=$(shell uname)
ifeq ($(OS), Linux)
    LINKER_OPTIONS=-Wl,--no-undefined
endif

# Project management targets
all: $(R2M2_LIBS)

# Ignore errors
.IGNORE: clean install uninstall

# Don't remove intermediary files
.SECONDARY:

# Regular targets
clean: 
	rm miasm_embedded_*.* r2m2_*.* src/r2m2.h

install: $(R2M2_LIBS)
	mkdir -p $(R2_PLUGIN_PATH) && cp -f *.$(SO_EXT) $(R2_PLUGIN_PATH)

uninstall:
	cd $(R2_PLUGIN_PATH) && rm $(R2M2_LIBS)

# Targets to compile r2m2 plugins
src/r2m2.h: tools/gen_includes.py src/r2m2.h.j2
	python2 tools/gen_includes.py $(R2_INCLUDES_PATH)

miasm_embedded_%.c: tools/cffi_miasm.py src/r2m2.h src/%_cffi.py
	python2 tools/cffi_miasm.py $(shell echo $(basename $@) |cut -c 16-)

%.$(SO_EXT): src/%.c miasm_embedded_%.c
	$(CC) $(R2_CFLAGS) $(PYTHON2_CFLAGS) $^ -o $@ $(LINKER_OPTIONS) $(R2M2_LDFLAGS)
