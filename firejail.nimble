# Package

version       = "0.5.0"
author        = "Juan Carlos"
description   = "Firejail wrapper for Nim, Isolate your Production App before its too late!"
license       = "MIT"
srcDir        = "src"


# Dependencies

requires "nim >= 0.20.0"

import distros
foreignDep "firejail"
