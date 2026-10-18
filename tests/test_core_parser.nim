import std/[os, tempfiles, unittest]
import ../src/core_parser

proc createTestFile(contents: string): string =
  let (file, path) = createTempFile("chimera-test-", ".exe", getTempDir())
  file.write(contents)
  file.close()
  path

proc putU16(data: var string, offset: int, value: uint16) =
  data[offset] = char(value and 0xFF)
  data[offset + 1] = char(value shr 8)

proc putU32(data: var string, offset: int, value: uint32) =
  for index in 0 ..< 4:
    data[offset + index] = char((value shr (index * 8)) and 0xFF)

proc minimalPe64(): string =
  result = newString(0x400)
  result[0] = 'M'
  result[1] = 'Z'
  putU32(result, 0x3C, 0x80)
  result[0x80] = 'P'
  result[0x81] = 'E'
  putU16(result, 0x84, 0x8664)
  putU16(result, 0x86, 1)
  putU16(result, 0x94, 240)

  let optionalHeader = 0x98
  putU16(result, optionalHeader, 0x20B)
  putU32(result, optionalHeader + 60, 0x200)
  putU32(result, optionalHeader + 108, 0)

  let sectionHeader = optionalHeader + 240
  for index, value in ".text":
    result[sectionHeader + index] = value
  putU32(result, sectionHeader + 8, 0x200)
  putU32(result, sectionHeader + 12, 0x1000)
  putU32(result, sectionHeader + 16, 0x200)
  putU32(result, sectionHeader + 20, 0x200)

suite "PE parser":
  test "parses a PE32+ section and calculates entropy":
    let path = createTestFile(minimalPe64())
    defer: removeFile(path)

    let features = parsePEFile(path)
    check features.is64Bit
    check features.sections == @[".text"]
    check features.entropyScores.len == 1
    check features.entropyScores[0] == 0.0
    check features.imports.len == 0

  test "rejects an invalid DOS signature":
    let path = createTestFile("not a PE")
    defer: removeFile(path)

    expect ValueError:
      discard parsePEFile(path)

  test "rejects an NT header offset outside the mapped file":
    var data = minimalPe64()
    putU32(data, 0x3C, 0xFFFFFFF0'u32)
    let path = createTestFile(data)
    defer: removeFile(path)

    expect ValueError:
      discard parsePEFile(path)

  test "rejects section data outside the mapped file":
    var data = minimalPe64()
    let sectionHeader = 0x98 + 240
    putU32(data, sectionHeader + 20, 0x3FF)
    let path = createTestFile(data)
    defer: removeFile(path)

    expect ValueError:
      discard parsePEFile(path)
