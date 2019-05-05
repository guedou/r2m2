# Copyright (C) 2019 Guillaume Valadon <guillaume@valadon.net>

"""
r2m2 plugin that uses miasm as a radare2 analysis and emulation backend
"""


import os
import sys

from miasm.analysis.machine import Machine
from miasm.expression.expression import ExprInt, ExprId, ExprCond, ExprOp
from miasm.expression.expression import ExprMem, ExprCompose
from miasm.expression.expression import ExprSlice, ExprLoc, ExprAssign
from miasm.expression.simplifications import expr_simp
from miasm.core.locationdb import LocationDB

from miasm_embedded_r2m2_Ae import ffi


class CachedRAnalOp(object):
    """
    Cache the result of the miasm_anal() function
    """

    # RAnalOp members used by r2m2
    mnemonic = None
    size = None
    type = None
    eob = None
    esil_string = None
    jump = None
    fail = None
    cond = None

    def fill_ranalop(self, r2_op):
        """
        Fill the C structure
        """

        # Cast the RAnalOp structure and fill some fields
        r2_analop = ffi.cast("RAnalOp_r2m2*", r2_op)

        r2_analop.mnemonic = alloc_string(self.mnemonic)
        r2_analop.size = self.size
        r2_analop.type = self.type
        r2_analop.eob = self.eob

        if self.esil_string:
            # Write the ESIL string to the buffer or allocate a string
            if len(self.esil_string) < 32:
                r2_analop.esil.buf = self.esil_string
            else:
                r2_analop.esil.ptr = alloc_string(self.esil_string)
            r2_analop.esil.len = len(self.esil_string)

        if self.jump:
            r2_analop.jump = self.jump

        if self.fail:
            r2_analop.fail = self.fail

        if self.cond:
            r2_analop.cond = self.cond


# Cheap LRU cache
LRU_CACHE = dict()


# libc CFFI handle
CFFI_LIBC = ffi.dlopen()


def alloc_string(string):
    """malloc & strncpy a string.
       Note: this is used to allow radare2 to call free() on the string."""

    ptr = CFFI_LIBC.malloc(len(string) + 1)
    CFFI_LIBC.strncpy(ptr, string, len(string) + 1)
    return ptr


MIASM_MACHINE = None


def miasm_machine():
    """Retrieve a miasm machine using the R2M2_ARCH environment variable."""

    r2m2_arch = os.getenv("R2M2_ARCH")
    available_archs = Machine.available_machine()

    if not r2m2_arch or r2m2_arch not in available_archs:
        message = "Please specify a valid miasm arch in the R2M2_ARCH "
        message += "environment variable !\nThe following are available: "
        message += ", ".join(available_archs)
        print >> sys.stderr, message + "\n"

        return None

    else:
        global MIASM_MACHINE
        if MIASM_MACHINE is None:
            MIASM_MACHINE = Machine(r2m2_arch)
        return MIASM_MACHINE


def m2op_to_r2cond(m2_op):
    """Convert a miasm conditonnal operator to a radare2 ANAL type."""

    operator = [("==", R_ANAL_COND_EQ), ("!=", R_ANAL_COND_NE)]

    for m2_op, r2_cond in operator:
        if m2_op:
            return r2_cond

    return None


@ffi.def_extern()
def miasm_get_reg_profile():
    """Return a radare2 register profile string"""

    reg_profile = ""

    # Get the miasm machine
    machine = miasm_machine()
    if machine is None:
        return alloc_string("")

    # Get the miasm mnemonic class
    mn_cls = machine.mn

    # First add PC and SP aliases
    try:
        for alias, get_reg in [("PC", mn_cls.getpc), ("SP", mn_cls.getsp)]:
            mode = machine.dis_engine().attrib
            reg = get_reg(mode)
            if reg:
                reg_profile += "=%s %6s\n" % (alias, reg.name.lower())
    except AttributeError as aerror:  # GV: too generic !
        print >> sys.stderr, "R2M2 ERROR: %s" % aerror

    # Add all registers
    reg_offset = 0
    for reg_expr in mn_cls.regs.all_regs_ids:
        # Format names
        reg_name = reg_expr.name.lower()
        reg_name = reg_name.replace("(", "_").replace(")", "_")
        reg_name = reg_name.replace("_", "")

        # Remove internal miasm register
        if reg_name == "exceptionflags":
            continue

        # Adjust size padding and build the r2 register definition
        size_padding = " " * (6-(len(str(reg_expr.size))))
        # r2 format: type name .size offset packedsize
        reg_profile += "\ngpr %6s %s.%s %6s 0" % (reg_name, size_padding,
                                                  reg_expr.size, reg_offset)

        # Compute register offset
        reg_offset += reg_expr.size if reg_expr.size < 8 else reg_expr.size / 8

    return alloc_string(reg_profile)


@ffi.def_extern()
def miasm_anal(r2_op, r2_address, r2_buffer, r2_length):
    """Define an instruction behavior using miasm."""

    # Return the cached result if any
    global LRU_CACHE
    result = LRU_CACHE.get(r2_address, None)
    if result is not None:
        result.fill_ranalop(r2_op)
        return

    # Cheap garbage collection
    if len(LRU_CACHE.keys()) >= 10:
        to_delete = [addr for addr in LRU_CACHE.keys() if addr < r2_address]
        for key in to_delete[:5]:
            del LRU_CACHE[key]

    # Cast radare2 variables
    opcode = ffi.cast("char*", r2_buffer)

    # Prepare the opcode
    opcode = ffi.unpack(opcode, r2_length)

    # Disassemble the opcode
    loc_db = LocationDB()
    try:
        machine = miasm_machine()
        mode = machine.dis_engine().attrib
        instr = machine.mn().dis(opcode, mode)
        instr.offset = r2_address
        if instr.dstflow():
            # Adjust arguments values using the instruction offset
            instr.dstflow2label(loc_db)
        dis_len = instr.l
    except:
        # Can't do anything with an invalid instruction
        return

    result = CachedRAnalOp()
    result.mnemonic = instr.name
    result.size = dis_len
    result.type = R_ANAL_OP_TYPE_UNK
    result.eob = 0   # End Of Block

    # Convert miasm expressions to ESIL
    get_esil(result, instr, loc_db)

    # # # Architecture agnostic analysis

    # Instructions that *DO NOT* stop a basic bloc
    if instr.breakflow() is False:
        result.fill_ranalop(r2_op)
        LRU_CACHE[r2_address] = result
        return
    else:
        result.eob = 1  # End Of Block

    # Assume that an instruction starting with 'RET' is a return
    # Note: add it to miasm as getpc() ?
    if instr.name[:3].upper().startswith("RET"):
        result.type = R_ANAL_OP_TYPE_RET

    # Instructions that explicitly provide the destination
    if instr and instr.dstflow():
        expr = instr.getdstflow(None)[0]

        if instr.is_subcall():
            r2_anal_subcall(result, expr, loc_db)
            result.fill_ranalop(r2_op)
            LRU_CACHE[r2_address] = result
            return

        if result.type == R_ANAL_OP_TYPE_UNK and instr.splitflow():
            r2_anal_splitflow(result, r2_address, instr, expr, loc_db)
            result.fill_ranalop(r2_op)
            LRU_CACHE[r2_address] = result
            return

        if isinstance(expr, ExprInt):
            result.type = R_ANAL_OP_TYPE_JMP
            result.jump = int(expr.arg) & 0xFFFFFFFFFFFFFFFF

        elif isinstance(expr, ExprId):
            result.type = R_ANAL_OP_TYPE_UJMP

        elif isinstance(expr, ExprLoc):
            addr = loc_db.get_location_offset(expr.loc_key)
            result.type = R_ANAL_OP_TYPE_JMP
            result.jump = addr & 0xFFFFFFFFFFFFFFFF

        elif isinstance(expr, ExprMem):
            result.type = R_ANAL_OP_TYPE_MJMP

        else:
            msg = "miasm_anal(): don't know what to do with: %s" % instr
            print >> sys.stderr, msg

    result.fill_ranalop(r2_op)
    LRU_CACHE[r2_address] = result


def isAssignation(miam2_ir_obj):
    """Check if the IR object assign a value to another."""

    return isinstance(miam2_ir_obj, ExprAssign)


def r2_anal_splitflow(analop, address, instruction, expression, loc_db):
    """Handle splitflow analysis"""

    # Get the miasm machine and IR objects
    machine = miasm_machine()
    if machine is None:
        return
    mode = machine.dis_engine().attrib
    ir = machine.ir(loc_db)

    # Get the IR and only keep affectations
    iir, _ = ir.get_ir(instruction)
    aff = [i for i in iir if isAssignation(i)]

    # Only keep one affectation to 'PC'
    current_pc = machine.mn.getpc(mode)
    aff = [i for i in iir if i.dst == current_pc]
    if not len(aff) == 1:
        return
    else:
        aff = aff[0]
    if isinstance(aff.src, ExprCond):

        # Retrieve, or guess, the condition operator
        if isinstance(aff.src.cond, ExprId):
            operator = R_ANAL_COND_EQ
        elif isinstance(aff.src.cond, ExprSlice):
            operator = None
        else:
            operator = aff.src.cond.op

        # Get the r2 condition analysis type
        r2cond = m2op_to_r2cond(operator)
        if not r2cond:
            return

        # Fill the RAnalOp structure
        analop.type = R_ANAL_OP_TYPE_CJMP
        analop.cond = r2cond
        if isinstance(expression, ExprLoc):
            jmp_address = loc_db.get_location_offset(expression.loc_key)
        else:
            jmp_address = int(expression.arg)
        analop.jump = jmp_address & 0xFFFFFFFFFFFFFFFF
        analop.fail = (address + instruction.l) & 0xFFFFFFFFFFFFFFFF

    else:
        msg_fmt = "r2_anal_splitflow(): don't know what to do with: %s"
        print >> sys.stderr, msg_fmt % instruction


def r2_anal_subcall(analop, expression, loc_db):
    """Handle subcall analysis"""

    if isinstance(expression, ExprLoc):
        analop.type = R_ANAL_OP_TYPE_CALL
        analop.jump = loc_db.get_location_offset(expression.loc_key)
    elif isinstance(expression, ExprInt):
        analop.type = R_ANAL_OP_TYPE_CALL
        analop.jump = int(expression.arg) & 0xFFFFFFFFFFFFFFFF
    else:
        analop.type = R_ANAL_OP_TYPE_UCALL


def get_esil(analop, instruction, loc_db):
    """Fill the r2 analop structure"""

    esil_string = m2instruction_to_r2esil(instruction, loc_db)
    if esil_string:
        analop.esil_string = esil_string


def m2_filter_IRDst(ir_list):
    """Filter IRDst from the expessions list"""

    return [ir for ir in ir_list if not (isAssignation(ir) and
            isinstance(ir.dst, ExprId) and ir.dst.name == "IRDst")]


def m2instruction_to_r2esil(instruction, loc_db):
    """Convert a miasm instruction to a radare2 ESIL"""

    # Get the IR
    try:
        machine = miasm_machine()
        ir = machine.ir(loc_db)
        iir, eiir = ir.get_ir(instruction)
    except:
        iir, eiir = [], []

    # Convert IRs
    result = list()
    if iir:
        result += [m2expr_to_r2esil(ir, loc_db) for ir in m2_filter_IRDst(iir)]

    for irblock in eiir:
        for ir_list in irblock.assignblks:
            aff = (ExprAssign(dst, src) for dst, src in ir_list.iteritems())
            result += (m2expr_to_r2esil(ir, loc_db) for ir in
                       m2_filter_IRDst(aff))

    if not len(result):
        return None

    return ",".join(result)


def m2expr_to_r2esil(iir, loc_db):
    """Convert a miasm expression to a radare2 ESIL"""

    if isinstance(iir, ExprId):
        return iir.name.lower()

    if isinstance(iir, ExprLoc):
        return loc_db.get_location_offset(iir.loc_key)

    if isinstance(iir, ExprInt):
        return hex(iir.arg)

    if isinstance(iir, ExprMem):
        ret = "%s,[%d]" % (m2expr_to_r2esil(iir.arg, loc_db), iir.size/8)
        return ret.lower()

    elif isAssignation(iir):
        if not isinstance(iir.dst, ExprMem):
            esil_dst = m2expr_to_r2esil(iir.dst, loc_db)
            return "%s,%s,=" % (m2expr_to_r2esil(iir.src, loc_db), esil_dst)
        else:
            esrc = m2expr_to_r2esil(iir.src, loc_db)
            edst = m2expr_to_r2esil(iir.dst.arg, loc_db)
            return "%s,%s,=[]" % (esrc, edst)

    elif isinstance(iir, ExprOp):
        if len(iir.args) == 2:
            arg_1 = m2expr_to_r2esil(iir.args[1], loc_db)
            arg_0 = m2expr_to_r2esil(iir.args[0], loc_db)
            if iir.op == "FLAG_SIGN_SUB":
                shift = iir.args[1].size - 1
                return "%s,%s,-,%d,>>" % (arg_1, arg_0, shift)
            return "%s,%s,%s" % (arg_1, arg_0, iir.op)
        elif iir.op == "parity":
            arg = m2expr_to_r2esil(iir.args[0], loc_db)
            return "%s,1,&,?{,0,}{,1,}" % arg
        elif iir.op.startswith("signExt_") and isinstance(iir.args[0], ExprMem):
            argsize = iir.args[0].size
            bits = int(iir.op.split("_")[1])
            test = 1 << (argsize - 1)
            mask = 2**bits-1 ^ 2**argsize-1
            tmp = m2expr_to_r2esil(iir.args[0], loc_db)
            sign_extension = "%s,0x%x,&,1,?{,%s,0x%x,+,}{,%s,}"
            return sign_extension % (tmp, test, tmp, mask, tmp)
        elif iir.op.startswith("zeroExt_"):
            return m2expr_to_r2esil(iir.args[0], loc_db)
        elif iir.op == "CC_EQ":
            return m2expr_to_r2esil(iir.args[0], loc_db)
        else:
            return "%s,0,%s" % (m2expr_to_r2esil(iir.args[0], loc_db), iir.op)

    elif isinstance(iir, ExprCompose):

        esil_strings = []
        for start, expr in iir.iter_args():
            stop = start + expr.size
            mask = (2**stop - 1) - (2**start - 1)
            esil_tmp = "%s,%s,&" % (m2expr_to_r2esil(expr, loc_db), hex(mask))
            esil_strings.append(esil_tmp)

        l = esil_strings
        if len(l) == 2:
            ret_string = "%s,%s,+" % (l[0], l[1])
            return ret_string
        else:
            tmp_list = [",".join(l[i:i+2]) for i in xrange(0, len(l), 2)]
            ret_string = ",+,".join(tmp_list)
            return ret_string

    elif isinstance(iir, ExprSlice):

        mask = (2**iir.stop - 1) - (2**iir.start - 1)
        return "%s,%s,&" % (m2expr_to_r2esil(iir.arg, loc_db), hex(mask))

    elif isinstance(iir, ExprCond):

        if isinstance(iir.cond, ExprSlice):

            # Attempt to evaluate the expression
            result = expr_simp(iir.cond)

            if isinstance(result, ExprInt):
                if result.arg != 0:
                    tmp_src = iir.src1
                else:
                    tmp_src = iir.src2
            else:
                tmp = m2expr_to_r2esil(iir.cond, loc_db)
                esil_string = "%s,?{,%s,},?{,%s,}" % (tmp, iir.src1, iir.src2)
                return esil_string

            return m2expr_to_r2esil(tmp_src, loc_db)

        elif (isinstance(iir.cond, ExprOp) or isinstance(iir.cond, ExprId) or
                isinstance(iir.cond, ExprCond)):
            condition = m2expr_to_r2esil(iir.cond, loc_db)
            if_clause = m2expr_to_r2esil(iir.src1, loc_db)
            then_clause = m2expr_to_r2esil(iir.src2, loc_db)
            return "%s,?{,%s,}{,%s,}" % (condition, if_clause, then_clause)

        elif isinstance(iir.cond, ExprInt):
            if int(iir.cond.arg):
                return m2expr_to_r2esil(iir.src1, loc_db)
            else:
                return m2expr_to_r2esil(iir.src2, loc_db)

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
