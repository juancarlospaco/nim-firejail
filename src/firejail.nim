## .. image:: https://source.unsplash.com/-YGdiRcY9Sc/800x402
import json
from os import quoteShell
from osproc import execCmdEx
from random import randomize, sample
from strutils import strip, split, splitLines, normalize, replace, join, multiReplace


const
  h = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"]
  invalidWhitelist = ["~", "/dev", "/usr", "/etc", "/opt", "/var",
                      "/bin", "/proc", "/media", "/mnt", "/srv", "/sys"]
  errBadPath = """Invalid Path for Whitelist: Firejail wont accept this path.
  Whitelist Sub-Folders of those paths but not the root path itself directly."""
  v = staticExec("firejail  --version").strip # Get version info from Firejails.
  firejailVersion* = v.splitLines[0].replace("firejail version ", "").strip
  enUsUtf8 = "--env=LC_CTYPE='en_US.UTF-8' --env=LC_NUMERIC='en_US.UTF-8' --env=LC_TIME='en_US.UTF-8' --env=LC_COLLATE='en_US.UTF-8' --env=LC_MONETARY='en_US.UTF-8' --env=LC_MESSAGES='en_US.UTF-8' --env=LC_PAPER='en_US.UTF-8' --env=LC_NAME='en_US.UTF-8' --env=LC_ADDRESS='en_US.UTF-8' --env=LC_TELEPHONE='en_US.UTF-8' --env=LC_MEASUREMENT='en_US.UTF-8' --env=LC_IDENTIFICATION='en_US.UTF-8' --env=LC_ALL='en_US.UTF-8' --env=LANG='en_US.UTF-8'"

let fea = try: "{" & v.normalize.split("compile time support:")[1].multiReplace(
    ("disabled", "false,"), ("enabled", "true,"),
    (" support is ", "\": " ), ("- ", " \"" ), ("-", "_" )) & "}"
    except: """{"apparmor":false,"appimage":false,"chroot":false,
    "file and directory whitelisting":false,"file transfer":false,
    "networking":false,"overlayfs":false,"private_home":false,
    "seccomp_bpf":false,"user namespace":false,"x11 sandboxing":false}"""

let firejailFeatures* = parseJson(fea)  ## Features available on the Firejails.


type
  Firejail* = object  ## Firejail Security Sandbox.
    noAllusers*, apparmor*, caps*, noKeepDevShm*, noMachineId*, noMnt*: bool
    noRamWriteExec*, no3d*, noDbus*, noDvd*, noGroups*, noNewPrivs*: bool
    noRoot*, noSound*, noAutoPulse*, noVideo*, forceEnUsUtf8*, noU2f*: bool
    privateTmp*, private*, privateCache*, privateDev*, noTv*, writables*: bool
    seccomp*, noShell*, noX*, noNet*, noIp*, noDebuggers*, appimage*: bool
    newIpcNamespace*,  useMtuJumbo9000*, useNice20*, useRandomMac*: bool


proc randomMacAddress(): string =
  ## Return 1 Random MAC Addres string.
  randomize()
  [h.sample & h.sample, h.sample & h.sample, h.sample & h.sample,
   h.sample & h.sample, h.sample & h.sample, h.sample & h.sample].join(":")

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

proc makeCommand*(this: Firejail, command: string, timeout: range[0..99] = 0, name="",
           gateway="", hostsFile="", logFile="", chroot="", tmpfs="",
           whitelist: seq[string] = @[], blacklist: seq[string] = @[],
           dnsServers: array[4, string] = ["", "", "", ""], maxSubProcesses = 0,
           maxOpenFiles = 0, maxFileSize = 0, maxPendingSignals = 0,
           maxRam = 0, maxCpu = 0, cpuCoresByNumber: seq[int] = @[]): string =
  ## Return a command of a Firejails sandbox, using the provided config.
  let
    nam = name.quoteShell
    lgs = logFile.quoteShell

  var blancas: string
  if whitelist != @[]:
    for folder in whitelist:
      if folder.strip.len > 1:
        assert folder notin invalidWhitelist, errBadPath
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
    "firejail --noprofile",

    when defined(release): "--quiet" else: "--debug", # quiet for performance.

    if this.noAllusers:   "" else: "--allusers",
    if this.apparmor:     "--apparmor" else: "",
    if this.caps:         "--caps" else: "",
    if this.noKeepDevShm: "" else: "--keep-dev-shm",
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
    if this.noTv:         "--notv" else: "",
    if this.privateTmp:   "--private-tmp" else: "",
    if this.private:      "--private" else: "",
    if this.privateCache: "--private-cache" else: "",
    if this.privateDev:   "--private-dev" else: "",
    if this.seccomp:      "--seccomp" else: "",
    if this.noShell:      "--shell=none" else: "--shell=/bin/bash", #ZSH/Fish sometimes fail,force plain old Bash.
    if this.noX:          "--x11=xvfb" else: "", # "none" complains about network.
    if this.noNet:        "--net=none" else: "",
    if this.noIp:         "--ip=none" else: "",
    if this.noDebuggers:  "" else: "--allow-debuggers",
    if this.appimage:     "--appimage" else: "",
    if this.useNice20:    "--nice=20" else: "",
    if this.writables:    "--writable-etc --writable-run-user --writable-var --writable-var-log" else: "",
    if this.forceEnUsUtf8:   enUsUtf8 else: "",
    if this.useMtuJumbo9000: "--mtu=9000" else: "",
    if this.useRandomMac:    "--mac=" & randomMacAddress().quoteShell else: "",
    if this.newIpcNamespace: "--ipc-namespace" else: "",
    if this.noRamWriteExec:  "--memory-deny-write-execute" else: "",
    if this.noMnt:           "--disable-mnt" else: "",

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
    if cpuCoresByNumber != @[]: "--cpu=" & cpuCoresByNumber.join(",").quoteShell else: "",

    denese, blancas, negras, command
  ].join(" ")
  when not defined(release): echo cmd
  result = cmd

proc exec*(this: Firejail, command: string, timeout: range[0..99] =0, name="",
           gateway="", hostsFile="", logFile="", chroot="", tmpfs="",
           whitelist: seq[string] = @[], blacklist: seq[string] = @[],
           dnsServers: array[4, string] = ["", "", "", ""], maxSubProcesses = 0,
           maxOpenFiles = 0, maxFileSize = 0, maxPendingSignals = 0,
           maxRam = 0, maxCpu = 0, cpuCoresByNumber: seq[int] = @[]): auto =
  ## Return  a process on a Firejails sandbox, using the provided config.
  result = execCmdEx(makeCommand(
    this, command, timeout, name, gateway, hostsFile, logFile, chroot, tmpfs,
    whitelist, blacklist, dnsServers, maxSubProcesses, maxOpenFiles,
    maxFileSize, maxPendingSignals, maxRam, maxCpu, cpuCoresByNumber))


###############################################################################


runnableExamples:
  import json ## Minimum possible basic Example.
  echo $Firejail().list()
  echo Firejail().tree()
  echo firejailFeatures
  echo firejailVersion


when isMainModule:
  let myjail = Firejail( # ALL options used here, dont worry they are optional!
    noAllusers: false, apparmor: false, caps: true, noKeepDevShm: false,
    noMachineId: false, noRamWriteExec: true, no3d: true, noDbus: true,
    noDvd: true, noGroups: true, noNewPrivs: true, noRoot: true, noSound: true,
    noAutoPulse: true, noVideo: true, forceEnUsUtf8: true, noU2f: true,
    privateTmp: true, private: true, privateCache: true,
    privateDev: true, seccomp: true, noShell: true, noNet: true, noIp: true,
    noDebuggers: false, newIpcNamespace: true, appimage: true,
    useMtuJumbo9000: true, useNice20: true, noX: true, useRandomMac: true,
  )
  echo myjail.exec(      # ALL options used here, dont worry they are optional!
    command="echo 42", timeout=99, name="myAppName", gateway="10.0.0.1",
    hostsFile="/etc/hosts", logfile="/tmp/myApp.log", chroot="/tmp/chroot/",
    tmpfs="/tmp/tmpfs", dnsServers=["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.1.1.2"],
    whitelist= @["/tmp/one", "/tmp/two"], blacklist= @["/usr/bin", "/share/bin"],
    maxSubProcesses=int8.high, maxOpenFiles=int8.high, maxFileSize=int32.high,
    maxPendingSignals=int16.high, maxRam=int16.high, maxCpu=int32.high,
    cpuCoresByNumber= @[0, 2], #Only CPU Cores 0 & 2 can be used inside Firejail
  )

  let myjail2 = Firejail()     # Works with no options too, sane defaults.
  echo myjail2.exec("echo 42") # Works with no options too, sane defaults.
  echo $myjail2.list()
  echo myjail2.tree()
