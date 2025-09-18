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
    "Imm32": (4, to_int32, from_int32), # Changed to signed int for Imm32
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
        start_ip = i
        try:
            opcode_val = bc[i]
            opcode = opcode_mapper[opcode_val]
            inst = (opcode, [])
            operand_ts = opcode_operand[opcode]
            i += 1  # Move past the opcode byte

            for oper_t in operand_ts:
                is_tagged = ":" in oper_t
                base_oper_t = oper_t.split(":")[0] if is_tagged else oper_t

                size, conv_to, _ = operand_type[base_oper_t]
                
                if i + size > len(bc):
                    # Not enough bytes for the operand, treat as invalid
                    raise IndexError("Attempt to read past end of bytecode for operand")

                val = conv_to(bc[i:i+size])
                
                # Check for string ID tag, which is the value of is_tagged
                is_string_id = is_tagged
                inst[1].append((base_oper_t, is_string_id, val))
                i += size
            
            # Append the successfully parsed instruction
            insts.append(inst)

        except (IndexError, KeyError):
            # If an error occurs (e.g., unknown opcode or incomplete operand),
            # mark the byte as Unknown and move on.
            if start_ip < len(bc):
                opcode_val = bc[start_ip]
                inst = (f"UnknownOpcode_0x{opcode_val:02x}", [])
                insts.append(inst)
            
            i = start_ip + 1 # Move to the next byte to continue parsing

    return insts

def assemble(insts):
    bc = []
    for opcode, operands in insts:
        # Check for UnknownOpcode and skip if necessary
        if opcode.startswith("UnknownOpcode"):
            val = int(opcode.split('_')[-1], 16)
            bc.append(val)
            continue
        
        op = opcode_mapper_inv[opcode]
        bc.append(op)
        
        # We need to reconstruct the tagged operand type
        tagged_operand_ts = opcode_operand[opcode]
        assert len(tagged_operand_ts) == len(operands), f"Malicious instruction: {op}, {operands}"
        
        for idx, (oper_t, is_str, val) in enumerate(operands):
            # Use the original tagged type for lookup
            original_oper_t = tagged_operand_ts[idx]
            base_oper_t = original_oper_t.split(":")[0]
            
            assert base_oper_t in operand_type, f"Malicious operand type: {base_oper_t}"
            _, _, conv_from = operand_type[base_oper_t]
            bc += conv_from(val)
    
    return bc