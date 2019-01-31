## .. image:: https://source.unsplash.com/-YGdiRcY9Sc/800x402
import strutils, json, random
from ospaths import quoteShell
from osproc import execCmdEx

const
  h = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"]
  v = staticExec("firejail  --version").strip # Get version info from Firejails.
  firejailVersion* = v.splitLines[0].replace("firejail version ", "").strip
  fea = "{" & v.normalize.split("compile time support:")[1].multiReplace(
    ("disabled", "false,"), ("enabled", "true,"),
    (" support is ", "\": " ), ("- ", " \"" ), ("-", "_" )) & "}"
  enUsUtf8 = "--env=LC_" & [
   "CTYPE='$1'", "NUMERIC='$1'", "TIME='$1'", "COLLATE='$1'", "MONETARY='$1'",
   "MESSAGES='$1'", "PAPER='$1'", "NAME='$1'", "ADDRESS='$1'", "TELEPHONE='$1'",
   "MEASUREMENT='$1'", "IDENTIFICATION='$1'", "ALL='$1'",
  ].join(" --env=LC_").format("en_US.UTF-8") & " --env=LANG='en_US.UTF-8'"

let firejailFeatures* = parseJson(fea)  ## Features available on the Firejails.

type
  Firejail* = object  ## Firejail Security Sandbox.
    noAllusers*, apparmor*, caps*, noKeepDevShm*, noKeepVarTmp*: bool
    noMachineId*, noRamWriteExec*, no3d*, noDbus*, noDvd*, noGroups*: bool
    noNewPrivs*, noRoot*, noSound*, noAutoPulse*, noVideo*, forceEnUsUtf8: bool
    noU2f*, overlayClean*, privateTmp*, private*, privateCache*: bool
    privateDev*, seccomp*, noShell*, noX*, noNet*, noIp*, noDebuggers*: bool
    newIpcNamespace*, appimage*, useMtuJumbo9000*, useNice20*, useRandomMac*: bool

proc randomMacAddress(): string =
  ## Return 1 Random MAC Addres string.
  randomize()
  [h.rand & h.rand, h.rand & h.rand, h.rand & h.rand,
   h.rand & h.rand, h.rand & h.rand, h.rand & h.rand].join(":")

proc list*(this: Firejail): seq[JsonNode] =
  ## Return the list of Firejails sandboxes running, returns 1 seq of JSON.
  let (output, exitCode) = execCmdEx("firejail --list")
  if exitCode == 0 and output.strip.len > 1:
    for line in output.strip.splitLines:
      var l = line.split(":")
      result.add %*{"pid": l[0], "user": l[1], "name": l[2], "command": l[3]}

proc tree*(this: Firejail): string {.inline.} =
  ## Return the list of Firejails sandboxes running (Human friendly string).
  let (output, exitCode) = execCmdEx("firejail --tree")
  if exitCode == 0: result = output.strip

proc shutdown*(this: Firejail, pid: int): bool {.inline.} =
  ## Shutdown a running Firejail sandbox by PID.
  when not defined(release): echo "Stoping 1 Firejail sandbox of PID: " & $pid
  execCmdEx("firejail --shutdown=" & $pid).exitCode == 0

proc exec*(this: Firejail, command: string, timeout: byte =0, name="",
           gateway="", hostsFile="", logFile="", chroot="", tmpfs="",
           whitelist: seq[string] = @[], blacklist: seq[string] = @[],
           dnsServers: array[4, string] = ["", "", "", ""],
           maxSubProcesses = 0, maxOpenFiles = 0, maxFileSize = 0,
           maxPendingSignals = 0, maxRam = 0, maxCpu = 0,
           cpuCoresByNumber: seq[int] = @[]): auto =
  ## Run a process on a Firejails sandbox, using the provided config.
  let
    nam = name.normalize.quoteShell
    lgs = logFile.normalize.quoteShell

  var blancas: string
  if whitelist != @[]:
    for folder in whitelist:
      if folder.strip.len > 1:
        blancas.add " --whitelist=" & folder.quoteShell

  var negras: string
  if blacklist != @[]:
    for folder in blacklist:
      if folder.strip.len > 1:
        negras.add " --blacklist=" & folder.quoteShell

  var denese: string
  if dnsServers != ["", "", "", ""]:
    for servo in dnsServers:
      if servo.strip.len > 6: # 1.2.3.4
        denese.add " --dns=" & servo.quoteShell

  let cmd = [
    "firejail --quiet --noprofile", # quiet for performance reasons.

    if this.noAllusers:   "" else: "--allusers",
    if this.apparmor:     "--apparmor" else: "",
    if this.caps:         "--caps" else: "",
    if this.noKeepDevShm: "" else: "--keep-dev-shm",
    if this.noKeepVarTmp: "" else: "--keep-var-tmp",
    if this.noMachineId:  "" else: "--machine-id",
    if this.no3d:         "--no3d" else: "",
    if this.noDbus:       "--nodbus" else: "",
    if this.noDvd:        "--nodvd" else: "",
    if this.noGroups:     "--nogroups" else: "",
    if this.noNewPrivs:   "--nonewprivs" else: "",
    if this.noRoot:       "--noroot" else: "",
    if this.noSound:      "--nosound" else: "",
    if this.noAutoPulse:  "--noautopulse" else: "",
    if this.noVideo:      "--novideo" else: "",
    if this.noU2f:        "--nou2f" else: "",
    if this.overlayClean: "--overlay-clean" else: "",
    if this.privateTmp:   "--private-tmp" else: "",
    if this.private:      "--private" else: "",
    if this.privateCache: "--private-cache" else: "",
    if this.privateDev:   "--private-dev" else: "",
    if this.seccomp:      "--seccomp" else: "",
    if this.noShell:      "--shell=none" else: "",
    if this.noX:          "--x11=none" else: "--x11",
    if this.noNet:        "--net=none" else: "",
    if this.noIp:         "--ip=none" else: "",
    if this.noDebuggers:  "" else: "--allow-debuggers",
    if this.appimage:     "--appimage" else: "",
    if this.useNice20:    "--nice=20" else: "",
    if timeout != 0:      "--timeout=" & quoteShell($timeout & ":00:00") else: "",
    if name != "":        "--name=" & nam & " --hostname=" & nam else: "",
    if gateway != "":     "--defaultgw=" & gateway.quoteShell else: "",
    if hostsFile != "":   "--hosts-file=" & hostsFile.quoteShell else: "",
    if logfile != "":     "--output=" & lgs & " --output-stderr=" & lgs else: "",
    if chroot != "":      "--chroot=" & chroot.quoteShell else: "",
    if tmpfs != "":       "--tmpfs=" & tmpfs.quoteShell else: "",
    if maxRam != 0:       "--rlimit-as=" & $maxRam else: "",
    if maxCpu != 0:       "--rlimit-cpu=" & $maxCpu else: "",
    if maxFileSize != 0:  "--rlimit-fsize=" & $maxFileSize else: "",
    if maxOpenFiles != 0: "--rlimit-nofile=" & $maxOpenFiles else: "",

    if maxSubProcesses != 0:    "--rlimit-nproc=" & $maxSubProcesses else: "",
    if maxPendingSignals != 0:  "--rlimit-sigpending=" & $maxPendingSignals else: "",
    if this.forceEnUsUtf8:      enUsUtf8 else: "",
    if this.useMtuJumbo9000:    "--mtu=9000" else: "",
    if this.useRandomMac:       "--mac=" & randomMacAddress().quoteShell else: "",
    if this.newIpcNamespace:    "--ipc-namespace" else: "",
    if this.noRamWriteExec:     "--memory-deny-write-execute" else: "",
    if cpuCoresByNumber != @[]: "--cpu=" & cpuCoresByNumber.join(",") else: "",

    denese, blancas, negras, command.quoteShell
  ].join(" ")
  #when not defined(release): echo cmd
  # execCmdEx(cmd)
  cmd


runnableExamples:
  import json ## Minimum possible basic Example.
  echo $Firejail().list()
  echo Firejail().tree()


when isMainModule:
  # let myjail = Firejail()   # Works with no options too, sane defaults.
  let myjail = Firejail( # ALL options used here, dont worry they are optional!
    noAllusers: false, apparmor: true, caps: true, noKeepDevShm: false,
    noKeepVarTmp: false, noMachineId: false, noRamWriteExec: true, no3d: true,
    noDbus: true, noDvd: true, noGroups: true, noNewPrivs: true, noRoot: true,
    noSound: true, noAutoPulse: true, noVideo: true, forceEnUsUtf8: true,
    noU2f: true, overlayClean: true, privateTmp: true, private: true,
    privateCache: true, privateDev: true, seccomp: true, noShell: true,
    noNet: true, noIp: true, noDebuggers: false, newIpcNamespace: true,
    appimage: true, useMtuJumbo9000: true, useNice20: true, noX: true,
    useRandomMac: true,
  )
  # echo $myjail.list()
  # echo myjail.tree()
  # echo myjail.exec("myApp") # Works with no options too, sane defaults.
  echo myjail.exec(      # ALL options used here, dont worry they are optional!
    command="myApp", timeout=255.byte, name="myAppName", gateway="10.0.0.1",
    hostsFile="/etc/hosts", logfile="/tmp/myApp.log", chroot="/tmp/chroot/",
    tmpfs="/tmp/tmpfs", dnsServers=["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.1.1.2"],
    whitelist= @["/tmp/one", "/tmp/two"], blacklist= @["/usr/bin", "/share/bin"],
    maxSubProcesses=int8.high, maxOpenFiles=int8.high, maxFileSize=int32.high,
    maxPendingSignals=int16.high, maxRam=int16.high, maxCpu=int32.high,
    cpuCoresByNumber= @[0, 2], #Only CPU Cores 0 & 2 can be used inside Firejail
  )
