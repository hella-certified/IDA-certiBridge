import ida_ua
import ida_bytes
import ida_funcs
import ida_idaapi

OP_TYPE_NAMES = {
    ida_ua.o_void: "",
    ida_ua.o_reg: "R",
    ida_ua.o_mem: "M",
    ida_ua.o_phrase: "P",
    ida_ua.o_displ: "D",
    ida_ua.o_imm: "I",
    ida_ua.o_far: "F",
    ida_ua.o_near: "N",
}

def normalizeOperand(op):
    opType = op.type
    if opType == ida_ua.o_void:
        return None
    tag = OP_TYPE_NAMES.get(opType, "?")
    if opType == ida_ua.o_reg:
        return f"{tag}{op.reg}"
    return tag

def normalizeFunction(startEa, endEa):
    parts = []
    ea = startEa
    insn = ida_ua.insn_t()
    while ea < endEa:
        insnLen = ida_ua.decode_insn(insn, ea)
        if insnLen <= 0:
            ea += 1
            continue
        mnem = insn.get_canon_mnem() or "?"
        ops = []
        for i in range(8):
            if insn.ops[i].type == ida_ua.o_void:
                break
            norm = normalizeOperand(insn.ops[i])
            if norm is not None:
                ops.append(norm)
        token = f"{mnem}:{','.join(ops)}" if ops else mnem
        parts.append(token)
        ea += insnLen
    return "|".join(parts)

def normalizeFunctionBytes(startEa, endEa):
    normalized = normalizeFunction(startEa, endEa)
    return normalized.encode("utf-8") if normalized else None
