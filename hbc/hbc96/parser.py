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
smallFunctionHeaderS = structure["SmallFuncHeader"]
functionHeaderS = structure["FuncHeader"]
stringTableEntryS = structure["SmallStringTableEntry"]
overflowStringTableEntryS = structure["OverflowStringTableEntry"]
stringStorageS = structure["StringStorage"]
arrayBufferS = structure["ArrayBuffer"]
objKeyBufferS = structure["ObjKeyBuffer"]
objValueBufferS = structure["ObjValueBuffer"]
regExpTableEntryS = structure["RegExpTableEntry"]
regExpStorageS = structure["RegExpStorage"]
bigIntTableEntryS = structure["BigIntTableEntry"]
bigIntStorageS = structure["BigIntStorage"]
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
    
    # Segment 2: Function Header
    functionHeaders = []
    for i in range(header["functionCount"]):
        functionHeader = {}
        # اقرأ الـ 16 بايت الخاصة بالرأس الصغير
        chunk = [f._readbyte() for _ in range(16)]

        # استخرج الكلمات الأربع
        word1 = int.from_bytes(chunk[0:4], 'little')
        word2 = int.from_bytes(chunk[4:8], 'little')
        word3 = int.from_bytes(chunk[8:12], 'little')
        word4 = int.from_bytes(chunk[12:16], 'little')

        # استخرج الأعلام (flags) أولاً لتحديد الحالة
        flags = (word4 >> 24) & 0xFF
        is_overflowed = (flags >> 5) & 1

        if is_overflowed:
            # === الحالة الخاصة: رأس كبير (Overflowed) ===
            # في هذه الحالة، يتم إعادة استخدام حقول البت لتخزين مؤشر للرأس الكبير
            # المصدر C++ يوضح: offset_field = low_16_bits; infoOffset_field = high_16_bits;

            # نستخرج المؤشر الصحيح
            offset_low = word1 & 0xFFFF
            offset_high = (word3 & 0x1FFFFFF) >> 0 # infoOffset field
            large_offset = (offset_high << 16) | offset_low

            # احفظ الموقع الحالي، واقفز إلى موقع الرأس الكبير
            saved_pos = f.tell()
            f.seek(large_offset)

            # اقرأ الرأس الكبير باستخدام تعريفه من structure.json
            largeHeader = {}
            for key in functionHeaderS:
                largeHeader[key] = read(f, functionHeaderS[key])
            functionHeader = largeHeader

            # اقرأ الـ 16 بايت الخاصة بالـ Header دفعة واحدة
            chunk = [f._readbyte() for _ in range(16)]

            # استخرج الأربع كلمات (كل كلمة 4 بايت)
            word1 = int.from_bytes(chunk[0:4], 'little')
            word2 = int.from_bytes(chunk[4:8], 'little')
            word3 = int.from_bytes(chunk[8:12], 'little')
            word4 = int.from_bytes(chunk[12:16], 'little')

            # استخرج الحقول باستخدام عمليات البت بناءً على تعريفها
            functionHeader["offset"]              = word1 & 0x1FFFFFF # 25 bits
            functionHeader["paramCount"]          = word1 >> 25       # 7 bits

            functionHeader["bytecodeSizeInBytes"] = word2 & 0x7FFF    # 15 bits
            functionHeader["functionName"]        = word2 >> 15       # 17 bits

            functionHeader["infoOffset"]          = word3 & 0x1FFFFFF # 25 bits
            functionHeader["frameSize"]           = word3 >> 25       # 7 bits

            functionHeader["environmentSize"]         = word4 & 0xFF          # 8 bits
            functionHeader["highestReadCacheIndex"]  = (word4 >> 8) & 0xFF   # 8 bits
            functionHeader["highestWriteCacheIndex"] = (word4 >> 16) & 0xFF  # 8 bits
            functionHeader["flags"]                   = (word4 >> 24) & 0xFF  # 8 bits

            # ارجع إلى الموقع الأصلي
            f.seek(saved_pos)

            # لا تنس أن الأعلام (flags) موجودة فقط في الرأس الصغير
            functionHeader['flags'] = flags
        else:
            # === الحالة العادية: رأس صغير ===
            # استخرج الحقول كالمعتاد
            functionHeader["offset"] = word1 & 0x1FFFFFF
            functionHeader["paramCount"] = word1 >> 25
            functionHeader["bytecodeSizeInBytes"] = word2 & 0x7FFF
            functionHeader["functionName"] = word2 >> 15
            functionHeader["infoOffset"] = word3 & 0x1FFFFFF
            functionHeader["frameSize"] = word3 >> 25
            functionHeader["environmentSize"] = word4 & 0xFF
            functionHeader["highestReadCacheIndex"] = (word4 >> 8) & 0xFF
            functionHeader["highestWriteCacheIndex"] = (word4 >> 16) & 0xFF
            functionHeader["flags"] = flags

        functionHeaders.append(functionHeader)

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
        # اقرأ الـ 4 بايت الخاصة بالمدخل دفعة واحدة
        chunk = [f._readbyte() for _ in range(4)] # <--- السطر الأول الجديد
        # الآن قم بتحويل قائمة البايتات إلى رقم
        word = int.from_bytes(chunk, 'little')

        # استخرج الحقول باستخدام عمليات البت
        stringTableEntry["isUTF16"] = word & 0x1          # 1 bit
        stringTableEntry["offset"]  = (word >> 1) & 0x7FFFFF # 23 bits
        stringTableEntry["length"]  = (word >> 24) & 0xFF      # 8 bits

        stringTableEntries.append(stringTableEntry)

    obj["stringTableEntries"] = stringTableEntries
    align(f)

    # Segment 6: StringTableOverflow
    stringTableOverflowEntries = []
    for _ in range(header["overflowStringCount"]):
        stringTableOverflowEntry = {}
        for key in overflowStringTableEntryS:
            stringTableOverflowEntry[key] = read(f, overflowStringTableEntryS[key])
        
        stringTableOverflowEntries.append(stringTableOverflowEntry)
    
    obj["stringTableOverflowEntries"] = stringTableOverflowEntries
    align(f)

    # Segment 7: StringStorage
    stringStorageS[2] = header["stringStorageSize"]
    stringStorage = read(f, stringStorageS)
    obj["stringStorage"] = stringStorage
    align(f)

    # Segment 8: ArrayBuffer
    arrayBufferS[2] = header["arrayBufferSize"]
    arrayBuffer = read(f, arrayBufferS)
    obj["arrayBuffer"] = arrayBuffer
    align(f)

    # Segment 9: ObjKeyBuffer
    objKeyBufferS[2] = header["objKeyBufferSize"]
    objKeyBuffer = read(f, objKeyBufferS)
    obj["objKeyBuffer"] = objKeyBuffer
    align(f)

    # Segment 10: ObjValueBuffer
    objValueBufferS[2] = header["objValueBufferSize"]
    objValueBuffer = read(f, objValueBufferS)
    obj["objValueBuffer"] = objValueBuffer
    align(f)

    # === New Segments Start Here ===

    # Segment 11: BigIntTable (New)
    bigIntTable = []
    # Currently we don't know the structure of this section, leaving it empty for now
    # for _ in range(header["bigIntCount"]):
    #     pass 
    obj["bigIntTable"] = bigIntTable
    align(f)

    # Segment 12: BigIntStorage (New)
    bigIntStorageS[2] = header["bigIntStorageSize"]
    bigIntStorage = read(f, bigIntStorageS)
    obj["bigIntStorage"] = bigIntStorage
    align(f)

    # Segment 13: RegExpTable
    regExpTable = []
    for _ in range(header["regExpCount"]):
        regExpEntry = {}
        for key in regExpTableEntryS:
            regExpEntry[key] = read(f, regExpTableEntryS[key])
        
        regExpTable.append(regExpEntry)

    obj["regExpTable"] = regExpTable
    align(f)    
    
    # Segment 14: RegExpStorage
    regExpStorageS[2] = header["regExpStorageSize"]
    regExpStorage = read(f, regExpStorageS)
    obj["regExpStorage"] = regExpStorage
    align(f)

    # Segment 15: CJSModuleTable
    cjsModuleTable = []
    for _ in range(header["cjsModuleCount"]):
        cjsModuleEntry = {}
        for key in cjsModuleTableS:
            cjsModuleEntry[key] = read(f, cjsModuleTableS[key])
        
        cjsModuleTable.append(cjsModuleEntry)

    obj["cjsModuleTable"] = cjsModuleTable
    align(f)

    # Segment 16: FunctionSourceTable (New)
    functionSourceTable = []
    # Currently we don't know the structure of this section, leaving it empty for now
    # for _ in range(header["functionSourceCount"]):
    #     pass
    obj["functionSourceTable"] = functionSourceTable
    align(f)

    obj["instOffset"] = f.tell()
    obj["inst"] = f.readall()
    print(f"[DEBUG] Header functionCount: {obj['header']['functionCount']}")
    print(f"[DEBUG] Parsed functionHeaders length: {len(obj['functionHeaders'])}")

    return obj

def export(obj, f):
    # Segment 1: Header
    header = obj["header"]
    for key in headerS:
        write(f, header[key], headerS[key])
    
    align(f)
    
    overflowedFunctionHeaders = []
    # Segment 2: Function Header
    functionHeaders = obj["functionHeaders"]
    for i in range(header["functionCount"]):
        functionHeader = functionHeaders[i]
        if "small" in functionHeader:
            for key in smallFunctionHeaderS:
                write(f, functionHeader["small"][key], smallFunctionHeaderS[key])
            
            overflowedFunctionHeaders.append(functionHeader)
        
        else:
            for key in smallFunctionHeaderS:
                write(f, functionHeader[key], smallFunctionHeaderS[key])

    align(f)

    # Segment 3: StringKind
    # FIXME : Do nothing just skip
    stringKinds = obj["stringKinds"]
    for i in range(header["stringKindCount"]):
        writeuint(f, stringKinds[i], bits=32)

    align(f)

    # Segment 3: IdentifierHash
    # FIXME : Do nothing just skip
    identifierHashes = obj["identifierHashes"]
    for i in range(header["identifierCount"]):
        writeuint(f, identifierHashes[i], bits=32)

    align(f)

    # Segment 4: StringTable
    stringTableEntries = obj["stringTableEntries"]
    for i in range(header["stringCount"]):
        for key in stringTableEntryS:
            stringTableEntry = stringTableEntries[i]
            write(f, stringTableEntry[key], stringTableEntryS[key])

    align(f)

    # Segment 5: StringTableOverflow
    stringTableOverflowEntries = obj["stringTableOverflowEntries"]
    for i in range(header["overflowStringCount"]):
        for key in overflowStringTableEntryS:
            stringTableOverflowEntry = stringTableOverflowEntries[i]
            write(f, stringTableOverflowEntry[key], overflowStringTableEntryS[key])

    align(f)

    # Segment 6: StringStorage
    stringStorage = obj["stringStorage"]
    stringStorageS[2] = header["stringStorageSize"]
    write(f, stringStorage, stringStorageS)

    align(f)

    # Segment 7: ArrayBuffer
    arrayBuffer = obj["arrayBuffer"]
    arrayBufferS[2] = header["arrayBufferSize"]
    write(f, arrayBuffer, arrayBufferS)

    align(f)

    # Segment 9: ObjKeyBuffer
    objKeyBuffer = obj["objKeyBuffer"]
    objKeyBufferS[2] = header["objKeyBufferSize"]
    write(f, objKeyBuffer, objKeyBufferS)

    align(f)

    # Segment 10: ObjValueBuffer
    objValueBuffer = obj["objValueBuffer"]
    objValueBufferS[2] = header["objValueBufferSize"]
    write(f, objValueBuffer, objValueBufferS)

    align(f)

    # Segment: BigInt Table
    bigIntTable = obj["bigIntTable"]
    for i in range(header["bigIntCount"]):
        bigIntEntry = bigIntTable[i]
        for key in bigIntTableEntryS:
            write(f, bigIntEntry[key], bigIntTableEntryS[key])

    align(f)

    # Segment: BigInt Storage
    bigIntStorage = obj["bigIntStorage"]
    bigIntStorageS[2] = header["bigIntStorageSize"]
    write(f, bigIntStorage, bigIntStorageS)

    align(f)

    # Segment 11: RegExpTable
    regExpTable = obj["regExpTable"]
    for i in range(header["regExpCount"]):
        regExpEntry = regExpTable[i]
        for key in regExpTableEntryS:
            write(f, regExpEntry[key], regExpTableEntryS[key])

    align(f)    
    
    # Segment 12: RegExpStorage
    regExpStorage = obj["regExpStorage"]
    regExpStorageS[2] = header["regExpStorageSize"]
    write(f, regExpStorage, regExpStorageS)

    align(f)

    # Segment 13: CJSModuleTable
    cjsModuleTable = obj["cjsModuleTable"]
    for i in range(header["cjsModuleCount"]):
        cjsModuleEntry = cjsModuleTable[i]
        for key in cjsModuleTableS:
            write(f, cjsModuleEntry[key], cjsModuleTableS[key])
        
    align(f)

    # Write remaining
    f.writeall(obj["inst"])

    # Write Overflowed Function Header
    for overflowedFunctionHeader in overflowedFunctionHeaders:
        smallFunctionHeader = overflowedFunctionHeader["small"]
        large_offset = (smallFunctionHeader["infoOffset"] << 16 )  | smallFunctionHeader["offset"]
        f.seek(large_offset)
        for key in functionHeaderS:
            write(f, overflowedFunctionHeader[key], functionHeaderS[key])

