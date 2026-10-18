import std/os
import winim

proc enumProcesses*(): seq[uint32] =
  let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
  if snapshot == INVALID_HANDLE_VALUE:
    raiseOSError(osLastError(), "CreateToolhelp32Snapshot failed")
  defer: discard CloseHandle(snapshot)

  var entry: PROCESSENTRY32
  entry.dwSize = sizeof(PROCESSENTRY32).DWORD
  if Process32First(snapshot, addr entry) == 0:
    raiseOSError(osLastError(), "Process32First failed")

  while true:
    result.add(entry.th32ProcessID.uint32)
    if Process32Next(snapshot, addr entry) == 0:
      break
