import os, osproc, strformat, strutils, times, colors, tables, json

const
  v = staticExec("firejail  --version").strip
  firejailVersion* = v.splitLines[0].replace("firejail version ", "").strip

proc featureparser(stringy: string): JsonNode {.inline.} =
  result = parseJson("{" &
    stringy.normalize.split("compile time support:")[1].multiReplace(
      ("disabled", "false,"), ("enabled", "true,"),
      (" support is ", "\": " ), ("- ", " \"" ), ("-", "_" )) & "}")

let firejailFeatures* = featureparser(v)

type
  Firejail* = object  ## Firejail Security Sandbox.

proc list*(this: Firejail): seq[JsonNode] {.inline.} =
  ## Return the list of Firejails sandboxes running.
  let (output, exitCode) = execCmdEx("firejail --list")
  if exitCode == 0:
    for line in output.strip.splitLines:
      var l = line.split(":")
      result.add %*{
        "pid":     l[0],
        "user":    l[1],
        "name":    l[2],
        "command": l[3],
      }

proc tree*(this: Firejail): string {.inline.} =
  ## Return the list of Firejails sandboxes running (Human friendly string)
  let (output, exitCode) = execCmdEx("firejail --tree")
  if exitCode == 0: result = output.strip

proc exec*(this: Firejail): string =
  ## Run a process on a Firejails sandbox.
  let (output, exitCode) = execCmdEx("firejail --tree")
  if exitCode == 0: result = output.strip


echo Firejail().list()
echo Firejail().tree()


    #
    # --allusers - all user home directories are visible inside the sandbox.
    # --apparmor - enable AppArmor confinement.
    # --bandwidth=name|pid - set bandwidth limits.
    # --blacklist=filename - blacklist directory or file.
    # --caps - enable default Linux capabilities filter.
    # --chroot=dirname - chroot into directory.
    # --cpu=cpu-number,cpu-number - set cpu affinity.
    # --debug - print sandbox debug messages.
    # --defaultgw=address - configure default gateway.
    # --dns=address - set DNS server.
    # --env=name=value - set environment variable.
    # --hostname=name - set sandbox hostname.
    # --hosts-file=file - use file as /etc/hosts.
    # --ip=address - set interface IP address.
    # --ip=none - no IP address and no default gateway are configured.
    # --ip6=address - set interface IPv6 address.
    # --ipc-namespace - enable a new IPC namespace.
    # --keep-dev-shm - /dev/shm directory is untouched (even with --private-dev).
    # --keep-var-tmp - /var/tmp directory is untouched.
    # --mac=xx:xx:xx:xx:xx:xx - set interface MAC address.
    # --machine-id - preserve /etc/machine-id
    # --memory-deny-write-execute - seccomp filter to block attempts to create
    #     memory mappings  that are both writable and executable.
    # --mtu=number - set interface MTU.
    # --name=name - set sandbox name.
    # --net=bridgename - enable network namespaces and connect to this bridge.
    # --net=ethernet_interface - enable network namespaces and connect to this
    #     Ethernet interface.
    # --net=none - enable a new, unconnected network namespace.
    # --nice=value - set nice value.
    # --no3d - disable 3D hardware acceleration.
    # --noblacklist=filename - disable blacklist for file or directory.
    # --nodbus - disable D-Bus access.
    # --nodvd - disable DVD and audio CD devices.
    # --nogroups - disable supplementary groups.
    # --nonewprivs - sets the NO_NEW_PRIVS prctl.
    # --noprofile - do not use a security profile.
    # --noroot - install a user namespace with only the current user.
    # --nosound - disable sound system.
    # --noautopulse - disable automatic ~/.config/pulse init.
    # --novideo - disable video devices.
    # --nou2f - disable U2F devices.
    # --nowhitelist=filename - disable whitelist for file or directory .
    # --output=logfile - stdout logging and log rotation.
    # --output-stderr=logfile - stdout and stderr logging and log rotation.
    # --overlay - mount a filesystem overlay on top of the current filesystem.
    # --overlay-tmpfs - mount a temporary filesystem overlay on top of the
    #     current filesystem.
    # --overlay-clean - clean all overlays stored in $HOME/.firejail directory.
    # --private - temporary home directory.
    # --private-cache - temporary ~/.cache directory.
    # --private-dev - create a new /dev directory with a small number of common device files.
    # --private-tmp - mount a tmpfs on top of /tmp directory.
    # --quiet - turn off Firejail's output.
    # --rlimit-as=number - set the maximum size of the process's virtual memory
    #     (address space) in bytes.
    # --rlimit-cpu=number - set the maximum CPU time in seconds.
    # --rlimit-fsize=number - set the maximum file size that can be created by a process.
    # --rlimit-nofile=number - set the maximum number of files that can be opened by a process.
    # --rlimit-nproc=number - set the maximum number of processes that can be created for the real user ID of the calling process.
    # --rlimit-sigpending=number - set the maximum number of pending signals for a process.
    # --seccomp - enable seccomp filter and apply the default blacklist.
    # --shell=none - run the program directly without a user shell.
    # --shell=program - set default user shell.
    # --shutdown=name|pid - shutdown the sandbox identified by name or PID.
    # --timeout=hh:mm:ss - kill the sandbox automatically after the time has elapsed.
    # --tmpfs=dirname - mount a tmpfs filesystem on directory dirname.
    # --whitelist=filename - whitelist directory or file.
    # --writable-etc - /etc directory is mounted read-write.
    # --writable-run-user - allow access to /run/user/$UID/systemd and /run/user/$UID/gnupg.
    # --writable-var - /var directory is mounted read-write.
    # --writable-var-log - use the real /var/log directory, not a clone.
    # --x11 - enable X11 sandboxing. The software checks first if Xpra is
    #     installed, then it checks if Xephyr is installed. If all fails, it will
    #     attempt to use X11 security extension.
    # --x11=none - disable access to X11 sockets.
    # --x11=xephyr - enable Xephyr X11 server. The window size is 800x600.
    # --x11=xorg - enable X11 security extension.
    # --x11=xpra - enable Xpra X11 server.
    # --x11=xvfb - enable Xvfb X11 server.
