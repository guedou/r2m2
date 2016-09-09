// Copyright (C) 2016 Guillaume Valadon <guillaume@valadon.net>

// r2m2 plugin that uses miasm2 as a radare2 disassembly and assembly backend


#include <r_asm.h>
#include <r_lib.h>
#include "r2m2.h"
#include "r2m2_ad.h"


static int disassemble (RAsm *unused, RAsmOp *rop, const unsigned char *data, int len) {
    // Disassemble an instruction using miasm
    rop->size = 0;
    miasm_dis (data, len, (RAsmOp_r2m2*)rop);
    return rop->size;
}


static int assemble (RAsm *unused, RAsmOp *rop, const char *data) {
    // Assemble an instruction using miasm
    rop->size = 0;
    miasm_asm (data, (RAsmOp_r2m2*)rop);
    return rop->size;
}


RAsmPlugin r_asm_plugin_r2m2 = {
    .name = "r2m2",
    .arch = "r2m2",
    .license = "LGPL3",
    .bits = R2M2_ARCH_BITS, // GV: seems fishy !
    .desc = "miasm2 backend",
    .disassemble = disassemble,
    .assemble = assemble
};


#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
    .type = R_LIB_TYPE_ASM,
    .data = &r_asm_plugin_r2m2
};
#endif
