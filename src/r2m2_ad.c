// Copyright (C) 2018 Guillaume Valadon <guillaume@valadon.net>

// r2m2 plugin that uses miasm2 as a radare2 disassembly and assembly backend


#include <dlfcn.h>
#include <r_asm.h>
#include <r_lib.h>
#include <r_version.h>
#include "r2m2.h"
#include "r2m2_ad.h"


static int disassemble (RAsm *rasm, RAsmOp *rop, const unsigned char *data, int len) {
    // Disassemble an instruction using miasm
    rop->size = 0;
    miasm_dis ((RAsmOp_r2m2*)rop, rasm->pc, data, len);
    return rop->size;
}


static int assemble (RAsm *rasm, RAsmOp *rop, const char *data) {
    // Assemble an instruction using miasm
    rop->size = 0;
    miasm_asm ((RAsmOp_r2m2*)rop, rasm->pc, data);
    return rop->size;
}


#ifdef linux
static bool init(void *user) {
  // Load the libpython2.7 dynamic library
  void *libpython = dlopen ("libpython2.7.so", RTLD_LAZY|RTLD_GLOBAL);

  if (!libpython) {
    char* error = dlerror();
    fprintf (stderr, "r2m2_ad.init: ERROR - %s\n", error);
    return false;
  }

  return true;
}
#endif


RAsmPlugin r_asm_plugin_r2m2 = {
    .name = "r2m2",
    .arch = "r2m2",
    .license = "LGPL3",
    .bits = 8|16|32|64,
    .desc = "miasm2 backend",
    .disassemble = disassemble,
    .assemble = assemble,
#ifdef linux
    .init = init,
#endif
};


#ifndef CORELIB
RLibStruct radare_plugin = {
    .type = R_LIB_TYPE_ASM,
    .data = &r_asm_plugin_r2m2,
    .version = R2_VERSION
};
#endif
