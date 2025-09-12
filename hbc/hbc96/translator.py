import pathlib
import json
from hbctool.util import *

basepath = pathlib.Path(__file__).parent.absolute()

operand_type = {
    "Reg8": (1, to_uint8, from_uint8),
    "Reg32": (4, to_uint32, from_uint32),
    "UInt8": (1, to_uint8, from_uint8),
    "UInt16": (2, to_uint16, from_uint16),
    "UInt32": (4, to_uint32, from_uint32),
    "Addr8": (1, to_int8, from_int8),
    "Addr32": (4, to_int32, from_int32),
    "Reg32": (4, to_uint32, from_uint32),
    "Imm32": (4, to_uint32, from_uint32),
    "Double": (8, to_double, from_double)
}

f = open(f"{basepath}/data/opcode.json", "r")
opcode_operand = json.load(f)
opcode_mapper = list(opcode_operand.keys())
print(f"[DEBUG] Loaded opcode_mapper with {len(opcode_mapper)} opcodes.")
opcode_mapper_inv = {}
for i, v in enumerate(opcode_mapper):
    opcode_mapper_inv[v] = i

f.close()

def disassemble(bc):
    i = 0
    insts = []
    while i < len(bc):
        try:
            opcode_val = bc[i]
            opcode = opcode_mapper[opcode_val]
            inst = (opcode, [])
            operand_ts = opcode_operand[opcode]
            i += 1  # تحريك المؤشر بعد قراءة بايت التعليمة

            for oper_t in operand_ts:
                # تحقق من وجود أي لاحقة (tag) وقم بإزالتها قبل البحث
                is_tagged = ":" in oper_t
                base_oper_t = oper_t.split(":")[0] if is_tagged else oper_t

                # استخدم النوع الأساسي للبحث في القاموس
                size, conv_to, _ = operand_type[base_oper_t]

                # تأكد من وجود بايتات كافية للقراءة
                if i + size > len(bc):
                    raise IndexError("Attempt to read past end of bytecode for operand")

                val = conv_to(bc[i:i+size])
                # قم بتخزين النوع الأصلي مع اللاحقة في النتائج
                inst[1].append((oper_t, is_tagged, val))
                i += size

        except IndexError:
            # في حالة وجود تعليمة غير معروفة أو مشكلة في القراءة
            if i < len(bc):
                # إذا كان لا يزال بإمكاننا قراءة البايت الحالي، فهي تعليمة غير معروفة
                opcode_val = bc[i]
                inst = (f"UnknownOpcode_0x{opcode_val:02x}", [])
            i += 1 # تحريك المؤشر لتجاوز البايت غير المعروف
        else:
            # إذا وصلنا إلى نهاية الشيفرة، توقف
            inst = ("InvalidBytecode_EOF", [])
            i += 1 # زيادة المؤشر لضمان إنهاء الحلقة

        insts.append(inst)

    return insts

def assemble(insts):
    bc = []
    for opcode, operands in insts:
        op = opcode_mapper_inv[opcode]
        bc.append(op)
        assert len(opcode_operand[opcode]) == len(operands), f"Malicious instruction: {op}, {operands}"
        for oper_t, _, val in operands:
            assert oper_t in operand_type, f"Malicious operand type: {oper_t}"
            _, _, conv_from = operand_type[oper_t]
            bc += conv_from(val)
    
    return bc