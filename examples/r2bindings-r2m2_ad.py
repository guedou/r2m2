#!/usr/bin/env python2
# Copyright (C) 2017 Guillaume Valadon <guillaume@valadon.net>


"""
Simple r2m2 native ad plugin for x86_64

Note: it could be used as follows:
    $ r2pm install lang-python2
    $ r2 -i r2bindings-r2m2_ad.py -qc 'e asm.arch=r2m2_native; pd 5' /bin/ls
"""

from miasm2.analysis.machine import Machine
import r2lang

import struct


def r2m2_asm(mn_str):
    """Assemble an instruction using miasm."""

    # miasm2 only parses upper case mnemonics
    mn_str = mn_str.upper()
    mn_str = mn_str.replace("X", "x")  # hexadecimal

    machine = Machine("x86_64")
    mode = machine.dis_engine().attrib
    mn = machine.mn()
    instr = mn.fromstring(mn_str, mode)
    asm_instr = [i for i in mn.asm(instr)][0]

    return [struct.unpack("!B", byte)[0] for byte in asm_instr]


def r2m2_dis(opcode):
    """Disassemble an instruction using miasm."""

    machine = Machine("x86_64")
    mode = machine.dis_engine().attrib
    instr = machine.mn().dis(opcode, mode)

    return [instr.l, str(instr)]


def r2m2_ad_plugin(a):

    return { "name": "r2m2_native",
             "arch": "r2m2_native",
             "bits": 32,
             "license": "LGPL3",
             "desc": "miasm2 backend with radare2-bindings",
             "assemble": r2m2_asm,
             "disassemble": r2m2_dis }

# Register the ad plugin
r2lang.plugin("asm", r2m2_ad_plugin)
