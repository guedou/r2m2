# Copyright (C) 2016 Guillaume Valadon <guillaume@valadon.net>

"""
r2m2 plugin that uses miasm2 as a radare2 disassembly and assembly backend
"""


import os
import sys

from miasm2.analysis.machine import Machine

from miasm_embedded_r2m2_ad import ffi


def miasm_machine():
    """Retrieve a miasm2 machine using the R2M2_ARCH environment variable."""

    r2m2_arch = os.getenv("R2M2_ARCH")
    available_archs = Machine.available_machine()

    if not r2m2_arch or not r2m2_arch in available_archs:
        message = "Please specify a valid miasm2 arch in the R2M2_ARCH " \
                  "environment variable !\n" \
                  "The following are available: "
        message += ", ".join(available_archs)
        print >> sys.stderr, message + "\n"

        return None

    return Machine(r2m2_arch)


@ffi.def_extern()
def miasm_dis(r2_buffer, r2_length, r2_op):
    """Disassemble an instruction using miasm."""

    # Cast radare2 variables
    rasmop = ffi.cast("RAsmOp_r2m2*", r2_op)
    opcode = ffi.cast("char*", r2_buffer)

    # Prepare the opcode
    opcode = ffi.unpack(opcode, r2_length)

    # Get the miasm2 machine
    machine = miasm_machine()
    if machine is None:
        return

    # Disassemble the opcode
    try:
        mode = machine.dis_engine().attrib
        instr = machine.mn().dis(opcode, mode)
        dis_str = str(instr)
        dis_len = instr.l
    except:
        dis_str = "/!\ Can't disassemble using miasm /!\\"
        dis_len = 2  # GV: seems fischy !

    # Fill the RAsmOp structure
    rasmop.size = dis_len
    rasmop.buf_asm = dis_str
    rasmop.buf_hex = opcode[0:rasmop.size].encode("hex")


@ffi.def_extern()
def miasm_asm(r2_buffer, r2_op):
    """Assemble an instruction using miasm."""

    # Cast radare2 variables
    rasmop = ffi.cast("RAsmOp_r2m2*", r2_op)
    mn_str = ffi.string(r2_buffer)

    # miasm2 only parses upper case mnemonics
    mn_str = mn_str.upper()
    mn_str = mn_str.replace("X", "x")  # hexadecimal

    # Get the miasm2 machine
    machine = miasm_machine()
    if machine is None:
        return

    # Get the miasm2 mnemonic object
    mn = machine.mn()

    # Assemble and return all possible candidates
    mode = machine.dis_engine().attrib
    instr = mn.fromstring(mn_str, mode)
    asm_instr = [i for i in mn.asm(instr)][0]

    # Fill the RAsmOp structure
    rasmop.size = len(asm_instr)
    rasmop.buf = asm_instr
    rasmop.buf_hex = asm_instr.encode("hex")
