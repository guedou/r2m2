# Copyright (C) 2016 Guillaume Valadon <guillaume@valadon.net>

# Retrieve radare2 related informations
R2_PLUGIN_PATH=$(HOME)/.config/radare2/plugins/
R2_INCLUDES_PATH=$(shell r2 -hh|grep INCDIR|awk '{print $$2}')
R2_CFLAGS=-g -fPIC $(shell pkg-config --cflags r_asm)

# Prepare r2m2 specific variables
SO_EXT=$(shell uname|grep -q Darwin && echo dylib || echo so)
R2M2_LDFLAGS=-shared $(shell pkg-config --libs r_asm) 
R2M2_LIBS=r2m2_ad.$(SO_EXT) r2m2_Ae.$(SO_EXT) miasm_embedded_r2m2_ad.$(SO_EXT) miasm_embedded_r2m2_Ae.$(SO_EXT)

# OS detection
OS=$(shell uname)
ifeq ($(OS), Linux)
    LINKER_OPTIONS=-Wl,-rpath=$(R2_PLUGIN_PATH)
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
	python tools/gen_includes.py $(R2_INCLUDES_PATH)

miasm_embedded_%.$(SO_EXT): tools/cffi_miasm.py src/r2m2.h src/%_cffi.py
	python tools/cffi_miasm.py $(shell echo $(basename $@) |cut -c 16-)

%.$(SO_EXT): src/%.c miasm_embedded_%.$(SO_EXT)
	$(CC) $(R2_CFLAGS) $(R2M2_LDFLAGS) $^ -o $@ $(LINKER_OPTIONS)
