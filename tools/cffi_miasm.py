#!/usr/bin/env python2
# Copyright (C) 2016 Guillaume Valadon <guillaume@valadon.net>

"""
Generate the r2m2 library
"""

import sys
import cffi

ffi = cffi.FFI()

plugin_name = sys.argv[1]

ffi.set_source("miasm_embedded_%s" % plugin_name, """
#include "src/r2m2.h"
""")

includes = "".join(open("src/r2m2.h").readlines())
includes += "".join(open("src/%s.h" % plugin_name).readlines())
ffi.embedding_api(includes)

ffi.cdef("""
void *malloc(size_t size);
char *strncpy(char *dest, const char *src, size_t n);
""")

ffi.embedding_init_code("".join(open("src/%s_cffi.py" % plugin_name).readlines()))

ffi.compile(verbose=True)
