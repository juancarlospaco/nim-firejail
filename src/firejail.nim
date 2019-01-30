import os, osproc, strformat, strutils, times, colors, tables, json

const
  v = staticExec("firejail  --version").strip
  firejailVersion* = v.splitLines[0].replace("firejail version ", "").strip
  fea = "{" & v.normalize.split("compile time support:")[1].multiReplace(
    ("disabled", "false,"), ("enabled", "true,"),
    (" support is ", "\": " ), ("- ", " \"" ), ("-", "_" )) & "}"

let firejailFeatures* = parseJson(fea)

type
  Firejail* = object  ## Firejail Security Sandbox.
    allusers*, apparmor*, caps*, ipcNamespace*, keepDevShm*, keepVarTmp*: bool
    machineId*, noRamWriteExecute*, no3d*, noDbus*, noDvd*, noGroups*: bool
    noNewPrivs*, noProfile*, noRoot*, noSound*, noAutoPulse*, noVideo*: bool
    nou2f*, overlayClean*, privateTmp*, private*, privateCache*: bool
    privateDev*, seccomp*, noShell*, noX*, noNet*, noIp*: bool

proc list*(this: Firejail): seq[JsonNode] =
  ## Return the list of Firejails sandboxes running, returns 1 seq of JSON.
  let (output, exitCode) = execCmdEx("firejail --list")
  if exitCode == 0:
    for line in output.strip.splitLines:
      var l = line.split(":")
      result.add %*{"pid": l[0], "user": l[1], "name": l[2], "command": l[3]}

proc tree*(this: Firejail): string {.inline.} =
  ## Return the list of Firejails sandboxes running (Human friendly string).
  let (output, exitCode) = execCmdEx("firejail --tree")
  if exitCode == 0: result = output.strip

proc exec*(this: Firejail): string =
  ## Run a process on a Firejails sandbox.
  let (output, exitCode) = execCmdEx("firejail --tree")
  if exitCode == 0: result = output.strip


echo Firejail().list()
echo Firejail().tree()


    # --bandwidth=name|pid - set bandwidth limits.
    # --blacklist=filename - blacklist directory or file.
    # --chroot=dirname - chroot into directory.
    # --cpu=cpu-number,cpu-number - set cpu affinity.
    # --defaultgw=address - configure default gateway.
    # --dns=address - set DNS server.
    # --env=name=value - set environment variable.
    # --hostname=name - set sandbox hostname.
    # --hosts-file=file - use file as /etc/hosts.
    # --ip=address - set interface IP address.
    # --ip6=address - set interface IPv6 address.
    # --mac=xx:xx:xx:xx:xx:xx - set interface MAC address.
    # --mtu=number - set interface MTU.
    # --name=name - set sandbox name.
    # --net=bridgename - enable network namespaces and connect to this bridge.
    # --net=ethernet_interface - enable network namespaces and connect to this
    #     Ethernet interface.
    # --nice=value - set nice value.
    # --output=logfile - stdout logging and log rotation.
    # --output-stderr=logfile - stdout and stderr logging and log rotation.
    # --rlimit-as=number - set the maximum size of the process's virtual memory
    #     (address space) in bytes.
    # --rlimit-cpu=number - set the maximum CPU time in seconds.
    # --rlimit-fsize=number - set the maximum file size that can be created by a process.
    # --rlimit-nofile=number - set the maximum number of files that can be opened by a process.
    # --rlimit-nproc=number - set the maximum number of processes that can be created for the real user ID of the calling process.
    # --rlimit-sigpending=number - set the maximum number of pending signals for a process.
    # --shutdown=name|pid - shutdown the sandbox identified by name or PID.
    # --timeout=hh:mm:ss - kill the sandbox automatically after the time has elapsed.
    # --tmpfs=dirname - mount a tmpfs filesystem on directory dirname.
    # --whitelist=filename - whitelist directory or file.
