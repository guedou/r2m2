# Copyright (C) 2016 Guillaume Valadon <guillaume@valadon.net>

# Retrieve radare2 related informations
R2_PLUGIN_PATH=$(shell r2 -hh|grep LIBR_PLUGINS|awk '{print $$2}')
R2_INCLUDES_PATH=$(shell r2 -hh|grep INCDIR|awk '{print $$2}')
R2_CFLAGS=-g -fPIC $(shell pkg-config --cflags r_asm)

# Prepare r2m2 specific variables
SO_EXT=$(shell uname|grep -q Darwin && echo dylib || echo so)
R2M2_LDFLAGS=-shared $(shell pkg-config --libs r_asm) 
R2M2_LIBS=r2m2_ad.$(SO_EXT) r2m2_Ae.$(SO_EXT)

# Project management targets
all: $(R2M2_LIBS)

.IGNORE: clean install uninstall
clean: 
	rm miasm_embedded_*.* r2m2_*.o r2m2_*.so

install: $(R2M2_LIBS)
	cp -f $(R2M2_LIBS) $(R2_PLUGIN_PATH)

uninstall:
	cd $(R2_PLUGIN_PATH) && rm $(R2M2_LIBS)

# Targets to compile r2m2 plugins
src/r2m2.h: tools/gen_includes.py src/r2m2.h.j2
	python tools/gen_includes.py $(R2_INCLUDES_PATH)

miasm_embedded_r2m2_ad.so: tools/cffi_miasm.py src/r2m2.h src/r2m2_ad_cffi.py
	python tools/cffi_miasm.py r2m2_ad

miasm_embedded_r2m2_Ae.so: tools/cffi_miasm.py src/r2m2.h src/r2m2_Ae_cffi.py
	python tools/cffi_miasm.py r2m2_Ae

r2m2_ad.so: src/r2m2_ad.c miasm_embedded_r2m2_ad.so
	$(CC) $(R2_CFLAGS) $(R2M2_LDFLAGS) $^ -o $@

r2m2_Ae.so: src/r2m2_Ae.c miasm_embedded_r2m2_Ae.so
	$(CC) $(R2_CFLAGS) $(R2M2_LDFLAGS) $^ -o $@
