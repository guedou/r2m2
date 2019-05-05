// Copyright (C) 2019 Guillaume Valadon <guillaume@valadon.net>

// r2m2 plugin that uses miasm2 as a radare2 analysis and emulation backend


#include <dlfcn.h>
#include <r_asm.h>
#include <r_lib.h>
#include <r_version.h>
#include "r2m2.h"
#include "r2m2_Ae.h"


#define R2M2_CC_SDB_PATH "./r2m2-cc.sdb"


static int analyze (RAnal *ranal, RAnalOp *rop, ut64 addr, const ut8 *data, int len, RAnalOpMask mask) {
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

    // Load the calling convention database
    struct stat cc_db_stat;
    int cc_db_exists = stat (R2M2_CC_SDB_PATH, &cc_db_stat);

    if (r_anal_cc_exist (ranal, "r2m2") == 0 && cc_db_exists == 0) {
        sdb_open (ranal->sdb_cc, R2M2_CC_SDB_PATH);

        if (ranal->sdb_cc->db.size == 0) {
	    eprintf("analyze(): loading the calling convention database failed !\n");
        }
    }

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
RLibStruct radare_plugin = {
    .type = R_LIB_TYPE_ANAL,
    .data = &r_anal_plugin_r2m2,
    .version = R2_VERSION
};
#endif
