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


task docs, "Generate docs":
  rmDir "docs"
  when defined linux:
    exec "nim doc --project --outdir:htmldocs/linux src/psutil.nim"
    exec "nim doc --project --outdir:htmldocs/posix src/psutil.nim"
  elif defined windows:
    exec "nim.exe doc --project --outdir:htmldocs/windows src/psutil.nim"
  elif defined macosx:
    exec "nim doc --project --outdir:htmldocs/macos src/psutil.nim"
    exec "nim doc --project --outdir:htmldocs/posix src/psutil.nim"
  elif defined posix:
    exec "nim doc --project --outdir:htmldocs/posix src/psutil.nim"

  when defined windows:
    exec "nim.exe rst2html --outdir:htmldocs doc/index.rst"
  else:
    exec "nim rst2html --outdir:htmldocs doc/index.rst"


task test_all, "Runs all tests":
  when defined linux:
    exec "nim r tests/test_linux"
    exec "nim r tests/quick_test"
  elif defined windows:
    exec "nim.exe r tests/test_windows"
    exec "nim.exe r tests/quick_test"
  else:
    exec "nim r tests/test_posix"
    exec "nim r tests/quick_test"


task test_regression, "Runs regression tests on test cases that were already passing":
  when defined linux:
    exec "nim r tests/test_linux"
    exec "nim r tests/quick_test"
  elif defined windows:
    exec "nim.exe r tests/test_windows"
    # exec "nim.exe r tests/quick_test" # TODO: enable this once all procs are implemented
  else:
    exec "nim r tests/test_posix"
    exec "nim r tests/quick_test"
