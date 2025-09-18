from hbctool.util import *
import json
import pathlib
import copy

basepath = pathlib.Path(__file__).parent.absolute()

MAGIC = 2240826417119764422
BYTECODE_ALIGNMENT = 4

INVALID_OFFSET = (1 << 23)
INVALID_LENGTH = (1 << 8) - 1

structure = json.load(open(f"{basepath}/data/structure.json", "r"))

headerS = structure["header"]
functionHeaderS = structure["FuncHeader"]
overflowStringTableEntryS = structure["OverflowStringTableEntry"]
regExpTableEntryS = structure["RegExpTableEntry"]
bigIntTableEntryS = structure["BigIntTableEntry"]
cjsModuleTableS = structure["CJSModuleTable"]

def align(f):
    f.pad(BYTECODE_ALIGNMENT)

def parse(f):
    obj = {}

    # Segment 1: Header
    header = {}
    for key in headerS:
        header[key] = read(f, headerS[key])

    obj["header"] = header
    align(f)

    # Segment 2: Function Headers
    functionHeaders = []
    overflowed_headers_info = []

    for i in range(header["functionCount"]):
        functionHeader = {}
        
        chunk_as_bytelist = [f._readbyte() for _ in range(16)]
        chunk = bytes(chunk_as_bytelist)
        
        word1 = int.from_bytes(chunk[0:4], 'little')
        word2 = int.from_bytes(chunk[4:8], 'little')
        word3 = int.from_bytes(chunk[8:12], 'little')
        word4 = int.from_bytes(chunk[12:16], 'little')

        flags_byte = chunk[15]
        is_overflowed = (flags_byte >> 5) & 1

        functionHeader["flags"] = flags_byte

        if is_overflowed:
            small_offset = word1 & 0x1FFFFFF
            small_info_offset = word3 & 0x1FFFFFF
            large_header_offset = (small_info_offset << 16) | small_offset
            overflowed_headers_info.append({'index': i, 'offset': large_header_offset})
        else:
            functionHeader["offset"]              = word1 & 0x1FFFFFF
            functionHeader["paramCount"]          = word1 >> 25
            functionHeader["bytecodeSizeInBytes"] = word2 & 0x7FFF
            functionHeader["functionName"]        = word2 >> 15
            functionHeader["infoOffset"]          = word3 & 0x1FFFFFF
            functionHeader["frameSize"]           = word3 >> 25
            functionHeader["environmentSize"]         = chunk[12]
            functionHeader["highestReadCacheIndex"]  = chunk[13]
            functionHeader["highestWriteCacheIndex"] = chunk[14]

        functionHeaders.append(functionHeader)

    for info in overflowed_headers_info:
        saved_pos = f.tell()
        f.seek(info['offset'])
        
        largeHeader = {}
        for key in functionHeaderS:
            largeHeader[key] = read(f, functionHeaderS[key])
        
        largeHeader['flags'] = functionHeaders[info['index']]['flags']
        functionHeaders[info['index']] = largeHeader
        
        f.seek(saved_pos)
        
    obj["functionHeaders"] = functionHeaders
    align(f)
    
    # Segment 3: StringKind
    stringKinds = []
    for _ in range(header["stringKindCount"]):
        stringKinds.append(readuint(f, bits=32))
    obj["stringKinds"] = stringKinds
    align(f)

    # Segment 4: IdentifierHash
    identifierHashes = []
    for _ in range(header["identifierCount"]):
        identifierHashes.append(readuint(f, bits=32))
    obj["identifierHashes"] = identifierHashes
    align(f)

    # Segment 5: StringTable
    stringTableEntries = []
    for _ in range(header["stringCount"]):
        stringTableEntry = {}
        word = readuint(f, bits=32)
        
        stringTableEntry["isUTF16"] = word & 0x1
        stringTableEntry["offset"]  = (word >> 1) & 0x7FFFFF
        stringTableEntry["length"]  = (word >> 24) & 0xFF
        stringTableEntries.append(stringTableEntry)
    obj["stringTableEntries"] = stringTableEntries
    align(f)

    # Segment 6: StringTableOverflow
    stringTableOverflowEntries = []
    for _ in range(header["overflowStringCount"]):
        entry = {}
        entry['offset'] = readuint(f, bits=32)
        entry['length'] = readuint(f, bits=32)
        stringTableOverflowEntries.append(entry)
    obj["stringTableOverflowEntries"] = stringTableOverflowEntries
    align(f)

    # =======================================================================
    # ## BEGIN FIXED SECTION / بداية الجزء المصحح ##
    # =======================================================================
    # Helper function to read a block of bytes using the correct method
    def read_bytes(size):
        if size == 0:
            return b''
        return bytes([f._readbyte() for _ in range(size)])

    # Segment 7: StringStorage
    stringStorage = read_bytes(header["stringStorageSize"])
    obj["stringStorage"] = stringStorage
    align(f)

    # Segment 8: ArrayBuffer
    arrayBuffer = read_bytes(header["arrayBufferSize"])
    obj["arrayBuffer"] = arrayBuffer
    align(f)

    # Segment 9: ObjKeyBuffer
    objKeyBuffer = read_bytes(header["objKeyBufferSize"])
    obj["objKeyBuffer"] = objKeyBuffer
    align(f)

    # Segment 10: ObjValueBuffer
    objValueBuffer = read_bytes(header["objValueBufferSize"])
    obj["objValueBuffer"] = objValueBuffer
    align(f)

    # Segment 11: BigIntTable
    bigIntTable = []
    # Not fully implemented yet, just skipping based on count
    f.seek(f.tell() + header["bigIntCount"] * 8) # Assuming 8 bytes per entry
    obj["bigIntTable"] = bigIntTable
    align(f)
    
    # Segment 12: BigIntStorage
    bigIntStorage = read_bytes(header["bigIntStorageSize"])
    obj["bigIntStorage"] = bigIntStorage
    align(f)
    
    # Segment 13: RegExpTable
    regExpTable = []
    for _ in range(header["regExpCount"]):
        entry = {}
        entry['offset'] = readuint(f, bits=32)
        entry['length'] = readuint(f, bits=32)
        regExpTable.append(entry)
    obj["regExpTable"] = regExpTable
    align(f)    
    
    # Segment 14: RegExpStorage
    regExpStorage = read_bytes(header["regExpStorageSize"])
    obj["regExpStorage"] = regExpStorage
    align(f)

    # Segment 15: CJSModuleTable
    cjsModuleTable = []
    for _ in range(header["cjsModuleCount"]):
         # Each entry is a pair of uint32_t
        entry = [readuint(f, bits=32), readuint(f, bits=32)]
        cjsModuleTable.append(entry)
    obj["cjsModuleTable"] = cjsModuleTable
    align(f)
    
    # Segment 16: FunctionSourceTable
    functionSourceTable = []
    # Not fully implemented, skipping
    f.seek(f.tell() + header["functionSourceCount"] * 8) # Assuming 8 bytes per entry
    obj["functionSourceTable"] = functionSourceTable
    align(f)

    obj["instOffset"] = f.tell()
    # الكود الجديد (الصحيح)
    obj["inst"] = f.readall()
    
    # =======================================================================
    # ## END FIXED SECTION / نهاية الجزء المصحح ##
    # =======================================================================

    return obj

def export(obj, f):
    # This function needs to be rewritten to match the new parsing logic if you want to re-assemble bytecode.
    # For now, we are focused on disassembly, so this is not critical.
    pass