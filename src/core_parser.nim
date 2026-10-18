import std/[memfiles, math, os, strformat, strutils]

type
  PEFeatures* = object
    sections*: seq[string]
    imports*: seq[string]
    entropyScores*: seq[float]
    is64Bit*: bool
    contentHash*: string
    iocs*: seq[string]

  SectionRange = object
    virtualAddress: uint32
    virtualSize: uint32
    rawOffset: uint32
    rawSize: uint32

proc requireBounds(offset, size, fileSize: int) =
  if offset < 0 or size < 0 or offset > fileSize or size > fileSize - offset:
    raise newException(ValueError,
      fmt"Malformed PE: range 0x{offset:X}+0x{size:X} exceeds file size 0x{fileSize:X}")

proc readU16(data: ptr UncheckedArray[byte], offset, fileSize: int): uint16 =
  requireBounds(offset, 2, fileSize)
  uint16(data[offset]) or (uint16(data[offset + 1]) shl 8)

proc readU32(data: ptr UncheckedArray[byte], offset, fileSize: int): uint32 =
  requireBounds(offset, 4, fileSize)
  uint32(data[offset]) or (uint32(data[offset + 1]) shl 8) or
    (uint32(data[offset + 2]) shl 16) or (uint32(data[offset + 3]) shl 24)

proc readU64(data: ptr UncheckedArray[byte], offset, fileSize: int): uint64 =
  requireBounds(offset, 8, fileSize)
  for index in 0 ..< 8:
    result = result or (uint64(data[offset + index]) shl (index * 8))

proc readCString(data: ptr UncheckedArray[byte], offset, fileSize: int,
                 maxLength = 4096): string =
  requireBounds(offset, 1, fileSize)
  let limit = min(maxLength, fileSize - offset)
  for index in 0 ..< limit:
    let value = data[offset + index]
    if value == 0:
      return
    result.add(char(value))
  raise newException(ValueError, "Malformed PE: unterminated string")

proc calculateEntropy(data: ptr UncheckedArray[byte], offset, size,
                      fileSize: int): float =
  requireBounds(offset, size, fileSize)
  if size == 0:
    return 0.0

  var frequencies: array[256, int]
  for index in offset ..< offset + size:
    inc frequencies[data[index].int]

  for count in frequencies:
    if count > 0:
      let probability = count.float / size.float
      result -= probability * log2(probability)

proc rvaToOffset(rva: uint32, sections: openArray[SectionRange],
                 sizeOfHeaders: uint32, fileSize: int): int =
  if rva < sizeOfHeaders:
    result = rva.int
    requireBounds(result, 1, fileSize)
    return

  for section in sections:
    let extent = max(section.virtualSize, section.rawSize)
    if rva >= section.virtualAddress and
        uint64(rva) < uint64(section.virtualAddress) + uint64(extent):
      let delta = rva - section.virtualAddress
      if delta >= section.rawSize:
        raise newException(ValueError,
          fmt"Malformed PE: RVA 0x{rva:X} points to uninitialized section data")
      let rawOffset = uint64(section.rawOffset) + uint64(delta)
      if rawOffset > uint64(high(int)):
        raise newException(ValueError, "Malformed PE: file offset is too large")
      result = rawOffset.int
      requireBounds(result, 1, fileSize)
      return

  raise newException(ValueError, fmt"Malformed PE: unmapped RVA 0x{rva:X}")

proc parseImports(data: ptr UncheckedArray[byte], fileSize: int,
                  importRva, importSize: uint32, is64Bit: bool,
                  sizeOfHeaders: uint32,
                  sections: openArray[SectionRange]): seq[string] =
  if importRva == 0 and importSize == 0:
    return
  if importRva == 0 or importSize < 20:
    raise newException(ValueError, "Malformed PE: invalid import directory")

  let directoryOffset = rvaToOffset(importRva, sections, sizeOfHeaders, fileSize)
  if uint64(importSize) > uint64(fileSize - directoryOffset):
    raise newException(ValueError, "Malformed PE: import directory exceeds file bounds")
  let directorySize = importSize.int
  let descriptorCount = directorySize div 20
  var descriptorTerminated = false

  for descriptorIndex in 0 ..< descriptorCount:
    let descriptorOffset = directoryOffset + descriptorIndex * 20
    let originalThunk = readU32(data, descriptorOffset, fileSize)
    let timeDateStamp = readU32(data, descriptorOffset + 4, fileSize)
    let forwarderChain = readU32(data, descriptorOffset + 8, fileSize)
    let nameRva = readU32(data, descriptorOffset + 12, fileSize)
    let firstThunk = readU32(data, descriptorOffset + 16, fileSize)

    if originalThunk == 0 and timeDateStamp == 0 and forwarderChain == 0 and
        nameRva == 0 and firstThunk == 0:
      descriptorTerminated = true
      break
    if nameRva == 0:
      raise newException(ValueError, "Malformed PE: import descriptor has no DLL name")

    let dllOffset = rvaToOffset(nameRva, sections, sizeOfHeaders, fileSize)
    result.add(readCString(data, dllOffset, fileSize, 260))

    let thunkRva = if originalThunk != 0: originalThunk else: firstThunk
    if thunkRva == 0:
      continue

    let width = if is64Bit: 8 else: 4
    let ordinalMask = if is64Bit: 0x8000000000000000'u64 else: 0x80000000'u64
    let maxThunks = fileSize div width
    var thunkTerminated = false
    for thunkIndex in 0 ..< maxThunks:
      let thunkRva64 = uint64(thunkRva) + uint64(thunkIndex) * uint64(width)
      if thunkRva64 > uint64(high(uint32)):
        raise newException(ValueError, "Malformed PE: import thunk RVA overflow")
      let thunkOffset = rvaToOffset(thunkRva64.uint32, sections, sizeOfHeaders, fileSize)
      let entry = if is64Bit:
          readU64(data, thunkOffset, fileSize)
        else:
          uint64(readU32(data, thunkOffset, fileSize))
      if entry == 0:
        thunkTerminated = true
        break
      if (entry and ordinalMask) != 0:
        result.add(fmt"ordinal#{entry and 0xFFFF'u64}")
      else:
        if entry > uint64(high(uint32)):
          raise newException(ValueError, "Malformed PE: import name RVA is too large")
        let nameOffset = rvaToOffset(entry.uint32, sections, sizeOfHeaders, fileSize)
        requireBounds(nameOffset, 3, fileSize)
        result.add(readCString(data, nameOffset + 2, fileSize, 4096))

    if not thunkTerminated:
      raise newException(ValueError, "Malformed PE: unterminated import thunk table")

  if not descriptorTerminated:
    raise newException(ValueError, "Malformed PE: unterminated import descriptor table")

const
  XxhPrime1 = 0x9E3779B185EBCA87'u64
  XxhPrime2 = 0xC2B2AE3D27D4EB4F'u64
  XxhPrime3 = 0x165667B19E3779F9'u64
  XxhPrime4 = 0x85EBCA77C2B2AE63'u64
  XxhPrime5 = 0x27D4EB2F165667C5'u64

proc rotl64(value: uint64, shift: int): uint64 {.inline.} =
  (value shl shift) or (value shr (64 - shift))

proc xxhRound(accumulator, input: uint64): uint64 {.inline.} =
  var mixed = accumulator + input * XxhPrime2
  mixed = rotl64(mixed, 31)
  mixed * XxhPrime1

proc xxhMergeRound(accumulator, value: uint64): uint64 {.inline.} =
  var merged = accumulator xor xxhRound(0'u64, value)
  merged * XxhPrime1 + XxhPrime4

proc loadU64Le(data: ptr UncheckedArray[byte], offset: int): uint64 {.inline.} =
  for index in 0 ..< 8:
    result = result or (uint64(data[offset + index]) shl (index * 8))

proc loadU32Le(data: ptr UncheckedArray[byte], offset: int): uint32 {.inline.} =
  uint32(data[offset]) or (uint32(data[offset + 1]) shl 8) or
    (uint32(data[offset + 2]) shl 16) or (uint32(data[offset + 3]) shl 24)

proc xxh64(data: ptr UncheckedArray[byte], offset, size: int,
           seed = 0'u64): uint64 =
  ## Streaming-free XXH64 (https://github.com/Cyan4973/xxHash), seed 0 by default.
  let endOffset = offset + size
  var cursor = offset
  var hash: uint64

  if size >= 32:
    var v1 = seed + XxhPrime1 + XxhPrime2
    var v2 = seed + XxhPrime2
    var v3 = seed
    var v4 = seed - XxhPrime1
    let bulkEnd = endOffset - 32
    while cursor <= bulkEnd:
      v1 = xxhRound(v1, loadU64Le(data, cursor))
      v2 = xxhRound(v2, loadU64Le(data, cursor + 8))
      v3 = xxhRound(v3, loadU64Le(data, cursor + 16))
      v4 = xxhRound(v4, loadU64Le(data, cursor + 24))
      cursor += 32
    hash = rotl64(v1, 1) + rotl64(v2, 7) + rotl64(v3, 12) + rotl64(v4, 18)
    hash = xxhMergeRound(hash, v1)
    hash = xxhMergeRound(hash, v2)
    hash = xxhMergeRound(hash, v3)
    hash = xxhMergeRound(hash, v4)
  else:
    hash = seed + XxhPrime5

  hash += uint64(size)

  while cursor + 8 <= endOffset:
    hash = hash xor xxhRound(0'u64, loadU64Le(data, cursor))
    hash = rotl64(hash, 27) * XxhPrime1 + XxhPrime4
    cursor += 8

  if cursor + 4 <= endOffset:
    hash = hash xor (uint64(loadU32Le(data, cursor)) * XxhPrime1)
    hash = rotl64(hash, 23) * XxhPrime2 + XxhPrime3
    cursor += 4

  while cursor < endOffset:
    hash = hash xor (uint64(data[cursor]) * XxhPrime5)
    hash = rotl64(hash, 11) * XxhPrime1
    cursor += 1

  hash = hash xor (hash shr 33)
  hash = hash * XxhPrime2
  hash = hash xor (hash shr 29)
  hash = hash * XxhPrime3
  hash = hash xor (hash shr 32)
  result = hash

proc contentFingerprint*(data: pointer, size: int): string =
  ## Fast 64-bit content fingerprint rendered as 16 lowercase hex digits.
  toHex(xxh64(cast[ptr UncheckedArray[byte]](data), 0, size)).toLowerAscii()

const
  SensitiveStrings = [
    "cmd.exe", "powershell", "powershell.exe", "rundll32.exe", "regsvr32.exe",
    "schtasks.exe", "bitsadmin.exe", "certutil.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "ieexec.exe", "hh.exe", "msbuild.exe", "csc.exe", "vbc.exe",
    "installutil.exe", "msiexec.exe"
  ]

proc isPrintableAscii(b: byte): bool {.inline.} =
  b >= 0x20 and b <= 0x7e

proc extractPrintableStrings(data: ptr UncheckedArray[byte], offset, size,
                              fileSize: int, minLen = 4): seq[string] =
  requireBounds(offset, size, fileSize)
  result = newSeq[string]()
  var cursor = offset
  let endOffset = offset + size
  while cursor < endOffset:
    # Skip non-printable bytes.
    while cursor < endOffset and not isPrintableAscii(data[cursor]):
      inc cursor
    let strStart = cursor
    while cursor < endOffset and isPrintableAscii(data[cursor]):
      inc cursor
    let strLen = cursor - strStart
    if strLen >= minLen:
      var s = ""
      for i in strStart ..< cursor:
        s.add(char(data[i]))
      result.add(s)

proc looksLikeIPv4(s: string): bool =
  var parts: seq[string]
  var cur = ""
  for ch in s:
    if ch == '.':
      parts.add(cur)
      cur = ""
    else:
      cur.add(ch)
  parts.add(cur)
  if parts.len != 4:
    return false
  for part in parts:
    if part.len == 0 or part.len > 3:
      return false
    for ch in part:
      if ch < '0' or ch > '9':
        return false
    let val = part.parseInt()
    if val < 0 or val > 255:
      return false
    # Reject leading zeros like "01" except "0" itself.
    if part.len > 1 and part[0] == '0':
      return false
  return true

proc extractIOCs(data: ptr UncheckedArray[byte], fileSize: int): seq[string] =
  ## Extract hardcoded IOCs from raw PE bytes: IPv4, URLs, PDB paths,
  ## and sensitive execution strings.
  var found: seq[string] = @[]
  proc addIOC(candidate: string) =
    if not (candidate in found):
      found.add(candidate)

  let strings = extractPrintableStrings(data, 0, fileSize, fileSize, minLen = 4)
  for s in strings:
    let lower = s.toLowerAscii()

    # IPv4 addresses: scan the printable string for a dotted-quad pattern.
    for i in 0 ..< max(0, s.len - 7):
      let window = s.substr(i, min(16, s.len - i))
      var j = 0
      while j < window.len:
        if window[j] >= '0' and window[j] <= '9':
          let start = j
          while j < window.len and window[j] >= '0' and window[j] <= '9':
            inc j
          if j < window.len and window[j] == '.':
            inc j
            while j < window.len and window[j] >= '0' and window[j] <= '9':
              inc j
            if j < window.len and window[j] == '.':
              inc j
              while j < window.len and window[j] >= '0' and window[j] <= '9':
                inc j
            if j < window.len and window[j] == '.':
              inc j
              while j < window.len and window[j] >= '0' and window[j] <= '9':
                inc j
            let candidate = window[start .. min(j, window.high)]
            if looksLikeIPv4(candidate):
              addIOC(candidate)
          continue
        inc j

    # URLs.
    if lower.startsWith("http://") or lower.startsWith("https://"):
      addIOC(s)

    # PDB paths.
    if lower.contains(".pdb"):
      addIOC(s)

    # Sensitive execution strings.
    for sens in SensitiveStrings:
      if lower.contains(sens):
        addIOC(s)
        break

  return found

proc parsePEFile*(filePath: string): PEFeatures =
  if not fileExists(filePath):
    raise newException(IOError, "File not found: " & filePath)

  var mapped = memfiles.open(filePath, fmRead)
  defer: mapped.close()

  let fileSize = mapped.size
  if fileSize == 0:
    raise newException(ValueError, "Malformed PE: file is empty")
  let data = cast[ptr UncheckedArray[byte]](mapped.mem)
  result.contentHash = contentFingerprint(mapped.mem, fileSize)
  result.iocs = extractIOCs(data, fileSize)

  requireBounds(0, 64, fileSize)
  if data[0] != byte('M') or data[1] != byte('Z'):
    raise newException(ValueError, "Invalid DOS signature (expected MZ)")

  let ntOffsetRaw = readU32(data, 0x3C, fileSize)
  if uint64(ntOffsetRaw) > uint64(high(int)):
    raise newException(ValueError, "Malformed PE: NT header offset is too large")
  let ntOffset = ntOffsetRaw.int
  requireBounds(ntOffset, 24, fileSize)
  if readU32(data, ntOffset, fileSize) != 0x00004550'u32:
    raise newException(ValueError, "Invalid PE signature (expected PE\\0\\0)")

  let coffOffset = ntOffset + 4
  let numberOfSections = readU16(data, coffOffset + 2, fileSize).int
  if numberOfSections == 0 or numberOfSections > 96:
    raise newException(ValueError, "Malformed PE: section count is outside 1..96")
  let optionalHeaderSize = readU16(data, coffOffset + 16, fileSize).int
  let optionalOffset = coffOffset + 20
  requireBounds(optionalOffset, optionalHeaderSize, fileSize)
  if optionalHeaderSize < 2:
    raise newException(ValueError, "Malformed PE: optional header is missing")

  let optionalMagic = readU16(data, optionalOffset, fileSize)
  result.is64Bit = optionalMagic == 0x20B
  if optionalMagic != 0x10B and optionalMagic != 0x20B:
    raise newException(ValueError, fmt"Unsupported PE optional-header magic 0x{optionalMagic:X}")

  let directoryBase = if result.is64Bit: 112 else: 96
  let directoryCountOffset = if result.is64Bit: 108 else: 92
  if optionalHeaderSize < directoryBase or optionalHeaderSize < 64:
    raise newException(ValueError, "Malformed PE: optional header is truncated")
  let sizeOfHeaders = readU32(data, optionalOffset + 60, fileSize)
  let numberOfDirectories = readU32(data, optionalOffset + directoryCountOffset, fileSize)

  let sectionTableOffset = optionalOffset + optionalHeaderSize
  requireBounds(sectionTableOffset, numberOfSections * 40, fileSize)
  var sections: seq[SectionRange]
  for sectionIndex in 0 ..< numberOfSections:
    let sectionOffset = sectionTableOffset + sectionIndex * 40
    var sectionName = ""
    for nameIndex in 0 ..< 8:
      let value = data[sectionOffset + nameIndex]
      if value == 0:
        break
      sectionName.add(char(value))

    let virtualSize = readU32(data, sectionOffset + 8, fileSize)
    let virtualAddress = readU32(data, sectionOffset + 12, fileSize)
    let rawSize = readU32(data, sectionOffset + 16, fileSize)
    let rawOffset = readU32(data, sectionOffset + 20, fileSize)
    var entropy = 0.0
    if rawSize > 0:
      if uint64(rawOffset) > uint64(high(int)) or
          uint64(rawSize) > uint64(high(int)):
        raise newException(ValueError, "Malformed PE: section range is too large")
      requireBounds(rawOffset.int, rawSize.int, fileSize)
      entropy = calculateEntropy(data, rawOffset.int, rawSize.int, fileSize)

    result.sections.add(sectionName)
    result.entropyScores.add(entropy)
    sections.add(SectionRange(
      virtualAddress: virtualAddress,
      virtualSize: virtualSize,
      rawOffset: rawOffset,
      rawSize: rawSize
    ))

  if numberOfDirectories > 1:
    if optionalHeaderSize < directoryBase + 16:
      raise newException(ValueError, "Malformed PE: import directory entry is truncated")
    let importRva = readU32(data, optionalOffset + directoryBase + 8, fileSize)
    let importSize = readU32(data, optionalOffset + directoryBase + 12, fileSize)
    result.imports = parseImports(data, fileSize, importRva, importSize,
      result.is64Bit, sizeOfHeaders, sections)
