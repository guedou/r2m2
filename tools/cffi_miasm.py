#!/usr/bin/env python2
# Copyright (C) 2018 Guillaume Valadon <guillaume@valadon.net>

"""
Generate the miasm embedded library
"""

import cffi
import argparse


# Parse command line arguments
parser = argparse.ArgumentParser(description="generate the miasm library")
parser.add_argument("--compile", action="store_true",
                    dest="compile", default=False)
parser.add_argument("plugin_name", help="r2m2 plugin name")
args = parser.parse_args()

# Create the FFI object
ffi = cffi.FFI()

# Declare the library name
ffi.set_source("miasm_embedded_%s" % args.plugin_name, """
#include "src/r2m2.h"
""")

# Parse include files to get functions that will be exported
includes = "".join(open("src/r2m2.h").readlines())
includes += "".join(open("src/%s.h" % args.plugin_name).readlines())
ffi.embedding_api(includes)

# libc functions that will be used from Python
ffi.cdef("""
void *malloc(size_t size);
char *strncpy(char *dest, const char *src, size_t n);
""")

# Python code that will be embedded
ffi.embedding_init_code("".join(open("src/%s_cffi.py" % args.plugin_name).readlines()))

# Compile the library, or dump the C code
if not args.compile:
    ffi.emit_c_code("miasm_embedded_%s.c" % args.plugin_name)
else:
    ffi.compile(verbose=True)
