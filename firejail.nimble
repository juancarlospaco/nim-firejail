version     = "0.5.5"
author      = "Juan Carlos"
description = "Firejail wrapper for Nim, Isolate your Production App before its too late!"
license     = "MIT"
srcDir      = "src"

requires "nim > 1.0.0"

import distros
foreignDep "firejail"
