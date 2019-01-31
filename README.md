# Firejail

- [Firejail](https://firejail.wordpress.com/features-3/#namespaces) wrapper for [Nim](https://nim-lang.org/learn.html).
_Isolate your Production App before its too late!_
🔥 🔐👑🔥

![screenshot](https://source.unsplash.com/-YGdiRcY9Sc/800x402 "FireJails")


# Whats Firejail?

_...and why should I use it?_

- https://www.youtube.com/watch?v=UgddGZca5XU  
- https://www.digitalocean.com/community/tutorials/how-to-use-firejail-to-set-up-a-wordpress-installation-in-a-jailed-environment
- https://l3net.wordpress.com/2014/06/08/securing-a-web-server-using-a-linux-namespaces-sandbox
- https://hans-hermann-bode.de/en/content/web-server-sandbox
- https://medium.com/@george.shuklin/on-using-firejail-for-network-isolation-in-tests-42f018ecdcac
- https://jaxenter.com/anti-docker-blog-114422.html
- **Why your web server needs full access to the whole System?.** 🤔


# Install

- `nimble install firejail`


# Use

```nim
import firejail

# Create a Firejail, all args are optional, all options are Boolean, super easy!.
let myjail = Firejail(no3d=true, noDbus=true, noDvd=true, noRoot=true, noSound=true,
                      noVideo=true, noShell=true, noX=true, noNet=true, noIp=true)

echo myjail.list() # List all Firejails sandboxes running, return a seq[JsonNode] (computer friendly)

echo myjail.tree() # List all Firejails sandboxes running, return a string (human friendly)

echo myjail.shutdown(pid=42) # Shutdown a running Firejail sandbox by PID, return bool, true if Ok

echo myjail.exec("myApp --some-arg") # Run your App isolated inside the Firejail.

# For more info read the Docs...
```


# API

- API is a 1-1 copy of the CLI Firejails API, so any Firejails Docs work too.
- Best Linux Security made super easy, just 4 `proc`, ~`32` Lines of code.
- Timeout is on Hours, up to `255` hours, `byte` type, when the timeout is reached the Jail is auto stopped.
- `dnsServers` is 1 array of 4 strings, for 4 DNS Servers, `array[4, string]` type, 4 IP addresses must be provided.
- `blacklist` is 1 seq of strings, `seq[string]` type, paths must exist.
- `whitelist` is 1 seq of strings, `seq[string]` type, paths must exist.
- `hostsFile` is 1 file path string, will be the Jails `/etc/hosts`, `string` type, file must exist.
- `chroot` is 1 folder path string, `string` type, folder must exist.
- `tmpfs` is 1 folder path string, `string` type, folder must exist.
- Run `nim doc firejails.nim` for more Documentation.
- Run `nim genDepend firejail.nim` for UML Graphics of internal code structure.
- Run `nim c -r firejails.nim` for an Example.
- Are you a Security Hacker?, **Pull Requests welcome!**


# FAQ

- This works with Docker or Vagrant?.

Yes.

- I have Docker, I dont need this?.

Docker current issues is a lack of strong security,
1 security breach in 1 container can be exploited to access all containers on the server,
since containers share resources with each others.
This doesnt do virtualization but is more like a locked-down secure chroot jail,
which grants a locked-down view of a system.
Sometimes even basic tiny libs and drivers have security vulnerabilities, virtualized or not.
With this your software can only access what it needs to access, and not a whole system, virtualized or not.
This works with simple booleans, as example `noDbus=true` and DBus is gone,
but good luck stripping all D-Bus from the Ubuntu running inside that Docker.

- This works with JavaScript?

No. `firejail` cant run on the browser.

- Whats the option `useMtuJumbo9000`?.

Network MTU Jumbo Frames. This is optional.
This is just a shortcut to improve UX.
https://wiki.archlinux.org/index.php/jumbo_frames

- Whats the option `forceEnUsUtf8`?.

Forces `EN` English as language and `UTF-8` Unicode as encoding on Firejail.
This is optional. This is just a shortcut to improve UX.

- Whats the option `useRandomMac`?.

Random Network MAC Address on Firejail. This is optional.
This is just a shortcut to improve UX.

- Why use a Random MAC Address?.

Devices send a signal to look for networks,
the signal contains the unique physical hardware (MAC) address for your device,
this unique address can be used to track you on a network and "map" a network,
you can use a random MAC address to make it harder to track. This is optional.
