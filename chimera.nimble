# Package

version       = "0.1.0"
author        = "Chimera Team"
description   = "AI-Driven Ultra-Fast Dynamic Reverse Engineering & Threat Detection Engine"
license       = "MIT"
srcDir        = "src"
bin           = @["main"]

# Dependencies

requires "nim >= 2.0.14"
requires "nimpy >= 0.2.0"
requires "taskpools >= 0.2.2"
requires "winim >= 3.8.0"
