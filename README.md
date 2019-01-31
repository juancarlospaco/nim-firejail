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

- API is a 1-1 copy of the CLI Firejails API, so any Firejails Docs work too.
- Best Linux Security made super easy, just 4 `proc`, `32` Lines of code.
- Run `nim doc firejails.nim` for more Documentation.
- Run `nim genDepend firejail.nim` for Graphics of internal code structure.
- Run `nim c -r firejails.nim` for an Example.
- Are you a Security Expert?, **Pull Requests welcome!**
