# Copyright (C) 2016 Guillaume Valadon <guillaume@valadon.net>

"""
r2m2 plugin that uses miasm2 as a radare2 analysis and emulation backend
"""


import os
import sys
import importlib

from miasm2.analysis.machine import Machine
from miasm2.expression.expression import ExprInt, ExprAff, ExprId, ExprCond, \
                                         ExprOp, ExprMem, ExprCompose, ExprSlice
from miasm2.expression.simplifications import expr_simp

from miasm_embedded_r2m2_Ae import ffi


# libc CFFI handle
CFFI_LIBC = ffi.dlopen("libc.so.6")

def alloc_string(string):
    """malloc & strcpy a string.
       Note: this is used to allow radare2 to call free() on the string."""

    ptr = CFFI_LIBC.malloc(len(string) + 1)
    CFFI_LIBC.strncpy(ptr, string, len(string) + 1)
    return ptr


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

    else:
        return Machine(r2m2_arch)


def m2op_to_r2cond(m2_op):
    """Convert a miasm2 conditonnal operator to a radare2 ANAL type."""

    operator = [("==", R_ANAL_COND_EQ), ("!=", R_ANAL_COND_NE)]

    for m2_op, r2_cond in operator:
        if m2_op:
            return r2_cond

    return None


@ffi.def_extern()
def miasm_get_reg_profile():
    """Return a radare2 register profile string"""

    reg_profile = ""

    # Get the miasm2 machine
    machine = miasm_machine()
    if machine is None:
        return ""

    # Get the miasm2 mnemonic class
    mn_cls = machine.mn

    # First add PC and SP aliases
    try:
        for alias, get_reg in [("PC", mn_cls.getpc), ("SP", mn_cls.getsp)]:
            mode = machine.dis_engine().attrib
            reg = get_reg(mode)
            if reg:
                reg_profile += "=%s %6s\n" % (alias, reg.name.lower())
    except AttributeError, aerror:  # GV: too generic !
        print >> sys.stderr, "R2M2 ERROR: %s" % aerror

    # Add all registers
    reg_offset = 0
    for reg_expr in mn_cls.regs.all_regs_ids:
        # Format names
        reg_name = reg_expr.name.lower()
        reg_name = reg_name.replace("(", "_").replace(")", "_")
        reg_name = reg_name.replace("_", "")

        # Adjust size padding and build the r2 register definition
        size_padding = " " * (6-(len(str(reg_expr.size))))
        # r2 format: type name .size offset packedsize
        reg_profile += "\ngpr %6s %s.%s %6s 0" % (reg_name, size_padding,
                                                  reg_expr.size, reg_offset)

        # Compute register offset
        reg_offset += reg_expr.size / 8

    return ffi.new("char[]", reg_profile)


@ffi.def_extern()
def miasm_anal(r2_op, r2_addr, r2_buffer, r2_length):
    """Define an instruction behavior using miasm."""

    # Cast radare2 variables
    opcode = ffi.cast("char*", r2_buffer)


    # Prepare the opcode
    opcode = ffi.unpack(opcode, r2_length)


    # Disassemble the opcode
    try:
        machine = miasm_machine()
        mode = machine.dis_engine().attrib
        instr = machine.mn().dis(opcode, mode)
        dis_len = instr.l
    except:
        # Can't do anything with an invalid instruction
        return


    # Cast the RAnalOp structure and fill some fields
    r2_analop = ffi.cast("RAnalOp_r2m2*", r2_op)
    r2_analop.mnemonic = alloc_string(instr.name)
    r2_analop.size = dis_len
    r2_analop.type = R_ANAL_OP_TYPE_UNK
    r2_analop.eob = 0   # End Of Block


    # Convert miasm expressions to ESIL
    get_esil(r2_analop, instr)


    ### Architecture agnostic analysis

    # Instructions that *DO NOT* stop a basic bloc
    if instr.breakflow() is False:
        return
    else:
        r2_analop.eob = 1  # End Of Block


    # Assume that an instruction starting with 'RET' is a return
    # Note: add it to miasm2 as getpc() ?
    if instr.name[:3].upper().startswith("RET"):
        r2_analop.type = R_ANAL_OP_TYPE_RET

    # Instructions that explicitly provide the destination
    if instr and instr.dstflow():
        expr = instr.getdstflow(None)[0]

        if instr.is_subcall():
            r2_anal_subcall(r2_analop, r2_addr, expr)
            return

        if r2_analop.type == R_ANAL_OP_TYPE_UNK and instr.splitflow():
            r2_anal_splitflow(r2_analop, r2_addr, instr, expr)
            return

        if isinstance(expr, ExprInt):
            r2_analop.type = R_ANAL_OP_TYPE_JMP
            r2_analop.jump = r2_addr + int(expr.arg)

        elif isinstance(expr, ExprId):
            r2_analop.type = R_ANAL_OP_TYPE_UJMP

        else:
            print >> sys.stderr, "miasm_anal(): don't know what to do with: %s" % instr


def r2_anal_splitflow(analop, address, instruction, expression):
    """Handle splitflow analysis"""


    # Get the miasm machine and IR objects
    machine = miasm_machine()
    if machine is None:
        return
    mode = machine.dis_engine().attrib
    ir = machine.ir()

    # Get the IR and only keep affectations
    iir, _ = ir.get_ir(instruction)
    aff = [i for i in iir if isinstance(i, ExprAff)] 

    # Only keep one affectation to 'PC'
    current_pc = machine.mn.getpc(mode)
    aff = [i for i in iir if i.dst == current_pc]
    if not len(aff) == 1:
        return
    else:
        aff = aff[0]
    if isinstance(aff.src, ExprCond):

        # Retrieve, or guess, the condition operator
        if isinstance(aff.src._cond, ExprId):
            operator = R_ANAL_COND_EQ
        else:
            operator = aff.src._cond._op

        # Get the r2 condition analysis type
        r2cond = m2op_to_r2cond(operator)
        if not r2cond:
            return

        # Fill the RAnalOp structure
        analop.type = R_ANAL_OP_TYPE_CJMP
        analop.cond = r2cond
        analop.jump = address + int(expression.arg)
        analop.fail = address + instruction.l

    else:
        print >> sys.stderr, "r2_anal_splitflow(): don't know what to do with: %s" % instruction


def r2_anal_subcall(analop, address, expression):
    """Handle subcall analysis"""

    if isinstance(expression, ExprInt):
        analop.type = R_ANAL_OP_TYPE_CALL
        analop.jump = address + int(expression.arg)
    else:
        analop.type = R_ANAL_OP_TYPE_UCALL


def get_esil(analop, instruction):
    """Fill the r2 analop structure"""

    esil_string = m2instruction_to_r2esil(instruction)
    if esil_string and len(esil_string) < 64:  # hardcoded RStrBuf limitation
        analop.esil.buf = esil_string
        analop.esil.len = len(esil_string)


def m2instruction_to_r2esil(instruction):
    """Convert a miasm2 instruction to a radare2 ESIL"""

    # Get the IR
    try:
        machine = miasm_machine()
        ir = machine.ir()
        iir, eiir = ir.get_ir(instruction)
    except:
        iir, eiir = [], []

    # Remove IRDst
    for i in iir:
        if isinstance(i, ExprAff) and isinstance(i._dst, ExprId) \
           and i._dst._name == "IRDst":
            iir.remove(i)

    if eiir:
        print >> sys.stderr, "Don't know what to do with non-empty eiir:", eiir

    if iir is None or iir == []:
        return

    else:
        result = [m2expr_to_r2esil(i) for i in iir]

        tmp_result = ",".join(result)
        if len(tmp_result) < 64:  # hardcoded RStrBuf limitation
            return tmp_result

        tmp_result = ""
        for esil in result:
            if (len(tmp_result) + len(esil) + 1) < 64:
                tmp_result += ",%s" % esil
            else:
                #print >> sys.stderr, "Truncated ESIL !"
                break
        return tmp_result


def m2expr_to_r2esil(iir):
    """Convert a miasm2 expression to a radare2 ESIL"""

    if isinstance(iir, ExprId):
        if not isinstance(iir._name, str):
            return "TODO"
        #    print type(iir._name), iir._name, iir._name.offset
        #    return "0x%x" % iir._name.offset
        return iir._name.lower()

    if isinstance(iir, ExprInt):
        return "0x%x" % iir._arg

    if isinstance(iir, ExprMem):
        ret = "%s,[]" % m2expr_to_r2esil(iir._arg)
        return ret.lower()

    elif isinstance(iir, ExprAff):
        if not isinstance(iir._dst, ExprMem):
            esil_dst = m2expr_to_r2esil(iir._dst)
            return "%s,%s,=" % (m2expr_to_r2esil(iir._src), esil_dst)
        else:
            esrc = m2expr_to_r2esil(iir._src)
            edst = m2expr_to_r2esil(iir._dst._arg)
            return "%s,%s,=[]" % (esrc, edst)

    elif isinstance(iir, ExprOp):
        if len(iir._args) == 2:
            arg_1 = m2expr_to_r2esil(iir._args[1])
            arg_0 = m2expr_to_r2esil(iir._args[0])
            return "%s,%s,%s" % (arg_1, arg_0, iir._op)
        else:
            return "0,%s,%s" % (m2expr_to_r2esil(iir._args[0]), iir._op)

    elif isinstance(iir, ExprCompose):

        esil_strings = []
        for expr, start, stop in iir.args:
            mask = (2**stop -1) - (2**start -1)
            esil_strings.append("%s,0x%x,&" % (m2expr_to_r2esil(expr), mask))

        l = esil_strings
        if len(l) == 2:
            ret_string = "%s,%s,+" % (l[0], l[1])
            return ret_string
        else:
            tmp_list = [",".join(l[i:i+2]) for i in xrange(0, len(l), 2)]
            ret_string = ",+,".join(tmp_list)
            return ret_string

    elif isinstance(iir, ExprSlice):

        mask = (2**iir.stop -1) - (2**iir.start -1)
        return "%s,0x%x,&" % (m2expr_to_r2esil(iir.arg), mask)

    elif isinstance(iir, ExprCond):

        if isinstance(iir._cond, ExprSlice):

            # Attempt to evaluate the expression
            result = expr_simp(iir._cond)

            if isinstance(result, ExprInt):
                if result.arg != 0:
                    tmp_src = iir._src1
                else:
                    tmp_src = iir._src2
            else:
                tmp = m2expr_to_r2esil(iir._cond)
                esil_string = "%s,0,!=,?{,%s,},%s,0,==,?{,%s,}" % (tmp, iir._src1, tmp, iir._src2)
                return esil_string

            return m2expr_to_r2esil(tmp_src)

        elif isinstance(iir._cond, ExprOp):
            condition = m2expr_to_r2esil(iir.cond)
            if_clause = m2expr_to_r2esil(iir.src1)
            then_clause = m2expr_to_r2esil(iir.src2)
            return "%s,?{,%s,}{,%s,}" % (condition, if_clause, then_clause)

        elif isinstance(iir._cond, ExprInt):
            if int(iir._cond.arg):
                return m2expr_to_r2esil(iir.src1)
            else:
                return m2expr_to_r2esil(iir.src2)

        return "TODO_Cond"  # GV: use a r2m2 exception ?

    elif isinstance(iir, str):
        return iir

    else:
        print >> sys.stderr, "Unknown type:", type(iir), iir
        return "TODO_UNK"


# Manually imported libr/include/r_anal.h
# Note: the code was modified using the following vim regexp:
#   :.s/\([0-9] \)/\1  # /g
R_ANAL_OP_TYPE_COND  = 0x80000000   # // TODO must be moved to prefix?
R_ANAL_OP_TYPE_REP   = 0x40000000   # /* repeats next instruction N times */
R_ANAL_OP_TYPE_MEM   = 0x20000000   # // TODO must be moved to prefix?
R_ANAL_OP_TYPE_NULL  = 0
R_ANAL_OP_TYPE_JMP   = 1   #  /* mandatory jump */
R_ANAL_OP_TYPE_UJMP  = 2   #  /* unknown jump (register or so) */
R_ANAL_OP_TYPE_CJMP  = R_ANAL_OP_TYPE_COND | R_ANAL_OP_TYPE_JMP  #   /* conditional jump */
R_ANAL_OP_TYPE_MJMP  = R_ANAL_OP_TYPE_MEM | R_ANAL_OP_TYPE_JMP  #   /* conditional jump */
R_ANAL_OP_TYPE_UCJMP = R_ANAL_OP_TYPE_COND | R_ANAL_OP_TYPE_UJMP  #  /* conditional unknown jump */
R_ANAL_OP_TYPE_CALL  = 3   #  /* call to subroutine (branch+link) */
R_ANAL_OP_TYPE_UCALL = 4   # /* unknown call (register or so) */
R_ANAL_OP_TYPE_CCALL = R_ANAL_OP_TYPE_COND | R_ANAL_OP_TYPE_CALL  #  /* conditional call to subroutine */
R_ANAL_OP_TYPE_UCCALL= R_ANAL_OP_TYPE_COND | R_ANAL_OP_TYPE_UCALL  #  /* conditional unknown call */
R_ANAL_OP_TYPE_RET   = 5   # /* returns from subroutine */
R_ANAL_OP_TYPE_CRET  = R_ANAL_OP_TYPE_COND | R_ANAL_OP_TYPE_RET  # /* conditional return from subroutine */
R_ANAL_OP_TYPE_ILL   = 6   #  /* illegal instruction // trap */
R_ANAL_OP_TYPE_UNK   = 7   # /* unknown opcode type */
R_ANAL_OP_TYPE_NOP   = 8   # /* does nothing */
R_ANAL_OP_TYPE_MOV   = 9   # /* register move */
R_ANAL_OP_TYPE_CMOV  = 9   # | R_ANAL_OP_TYPE_COND /* conditional move */
R_ANAL_OP_TYPE_TRAP  = 10   # /* it's a trap! */
R_ANAL_OP_TYPE_SWI   = 11   #  /* syscall software interrupt */
R_ANAL_OP_TYPE_UPUSH = 12   # /* unknown push of data into stack */
R_ANAL_OP_TYPE_PUSH  = 13   #  /* push value into stack */
R_ANAL_OP_TYPE_POP   = 14   #   /* pop value from stack to register */
R_ANAL_OP_TYPE_CMP   = 15   #  /* compare something */
R_ANAL_OP_TYPE_ACMP  = 16   #  /* compare via and */
R_ANAL_OP_TYPE_ADD   = 17
R_ANAL_OP_TYPE_SUB   = 18
R_ANAL_OP_TYPE_IO    = 19
R_ANAL_OP_TYPE_MUL   = 20
R_ANAL_OP_TYPE_DIV   = 21
R_ANAL_OP_TYPE_SHR   = 22
R_ANAL_OP_TYPE_SHL   = 23
R_ANAL_OP_TYPE_SAL   = 24
R_ANAL_OP_TYPE_SAR   = 25
R_ANAL_OP_TYPE_OR    = 26
R_ANAL_OP_TYPE_AND   = 27
R_ANAL_OP_TYPE_XOR   = 28
R_ANAL_OP_TYPE_NOR   = 29
R_ANAL_OP_TYPE_NOT   = 30
R_ANAL_OP_TYPE_STORE = 31   #  /* store from register to memory */
R_ANAL_OP_TYPE_LOAD  = 32   #  /* load from memory to register */
R_ANAL_OP_TYPE_LEA   = 33
R_ANAL_OP_TYPE_LEAVE = 34
R_ANAL_OP_TYPE_ROR   = 35
R_ANAL_OP_TYPE_ROL   = 36
R_ANAL_OP_TYPE_XCHG  = 37
R_ANAL_OP_TYPE_MOD   = 38
R_ANAL_OP_TYPE_SWITCH = 39
R_ANAL_OP_TYPE_CASE = 40
R_ANAL_OP_TYPE_LENGTH = 41
R_ANAL_OP_TYPE_CAST = 42
R_ANAL_OP_TYPE_NEW = 43
R_ANAL_OP_TYPE_ABS = 44
R_ANAL_OP_TYPE_CPL = 45  # /* complement */
R_ANAL_OP_TYPE_CRYPTO = 46

R_ANAL_COND_AL = 1   #        // Always executed (no condition)
R_ANAL_COND_EQ = 2   #         // Equal
R_ANAL_COND_NE = 3   #         // Not equal
R_ANAL_COND_GE = 4   #         // Greater or equal
R_ANAL_COND_GT = 5   #         // Greater than
R_ANAL_COND_LE = 6   #         // Less or equal
R_ANAL_COND_LT = 7   #         // Less than
R_ANAL_COND_NV = 8   #         // Never executed             must be a nop? :D
R_ANAL_COND_HS = 9   #         // Carry set                  >, ==, or unordered
R_ANAL_COND_LO = 10   #         // Carry clear                Less than
R_ANAL_COND_MI = 11   #         // Minus, negative            Less than
R_ANAL_COND_PL = 12   #         // Plus, positive or zero     >, ==, or unordered
R_ANAL_COND_VS = 13   #         // Overflow                   Unordered
R_ANAL_COND_VC = 14   #        // No overflow                Not unordered
R_ANAL_COND_HI = 15   #         // Unsigned higher            Greater than, or unordered
R_ANAL_COND_LS = 16   #         // Unsigned lower or same     Less than or equal
