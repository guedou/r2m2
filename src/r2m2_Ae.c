// Copyright (C) 2017 Guillaume Valadon <guillaume@valadon.net>

// r2m2 plugin that uses miasm2 as a radare2 analysis and emulation backend


#include <dlfcn.h>
#include <r_asm.h>
#include <r_lib.h>
#include "r2m2.h"
#include "r2m2_Ae.h"


static int analyze (RAnal *unused, RAnalOp *rop, ut64 addr, const ut8 *data, int len) {
     // If the size is set, the instruction was already processed
     // Note: this is a trick to enhance performances, as radare2 calls analyze()
     //       several times.
     if (rop->size) {
         return rop->size;
     }

    // Analyze an instruction using miasm
    memset (rop, 0, sizeof (RAnalOp));
    rop->type = R_ANAL_OP_TYPE_UNK;

    miasm_anal ((RAnalOp_r2m2*)rop, addr, data, len);

    return rop->size;
}


#ifdef linux
static int init(void *user) {
  // Load the libpython2.7 dynamic library
  void *libpython = dlopen ("libpython2.7.so", RTLD_LAZY|RTLD_GLOBAL);

  if (!libpython) {
    char* error = dlerror();
    fprintf (stderr, "r2m2_Ae.init: ERROR - %s\n", error);
    return false;
  }

  return true;
}
#endif


static int set_reg_profile (RAnal *anal) {
    // Set the registers profile using miasm
    char *profile = miasm_get_reg_profile ();
    return r_reg_set_profile_string (anal->reg, profile);
}


static int esil_r2m2_init (RAnalEsil *esil) {
    // Set radare2 'pc' to 0x0
    if (esil->anal && esil->anal->reg) {
        RRegItem *reg_item = r_reg_get (esil->anal->reg, "pc", -1);

        if (reg_item) {
            r_reg_set_value (esil->anal->reg, reg_item, 0x0000);
        }
    }
    return true;
}

static int esil_r2m2_fini (RAnalEsil *unused) {
    return true;
}

struct r_anal_plugin_t r_anal_plugin_r2m2 = {
    .name = "r2m2",
    .arch = "r2m2",
    .license = "LGPL3",
    .bits = 8|16|32|64,
    .desc = "miasm2 backend",
    .op = analyze,
#ifdef linux
    .init = init,
#endif

    .set_reg_profile = set_reg_profile,

    .esil = true,
    .esil_init = esil_r2m2_init,
    .esil_fini = esil_r2m2_fini
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
    .type = R_LIB_TYPE_ANAL,
    .data = &r_anal_plugin_r2m2
};
#endif
