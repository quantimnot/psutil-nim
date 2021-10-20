# Package
version       = "0.6.1"
author        = "Juan Carlos, John Scillieri, Nim community"
description   = "Psutil is a cross-platform library for retrieving information on running processes and system utilization (CPU, memory, disks, network)"
license       = "MIT"
srcDir        = "src"
skipDirs      = @["tests"]

# Dependencies
requires "nim >= 1.2.6"

when defined windows:
  requires "winim"

task test, "Runs the test suite":
  when defined linux:
    exec "nim r tests/test_linux"
    exec "nim r tests/quick_test"
  elif defined windows:
    exec "nim.exe r tests/test_windows"
    exec "nim.exe r tests/quick_test"
  else:
    exec "nim r tests/test_posix"
    exec "nim r tests/quick_test"
