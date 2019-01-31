# Firejail

- [Firejail](https://firejail.wordpress.com/features-3/#namespaces) wrapper for [Nim](https://nim-lang.org/learn.html). _Firejail your Production App before is too late!_

![screenshot](https://source.unsplash.com/-YGdiRcY9Sc/800x402 "FireJails")


# Whats Firejail?

_...and why should I use it?_

- https://www.youtube.com/watch?v=UgddGZca5XU  
- https://www.digitalocean.com/community/tutorials/how-to-use-firejail-to-set-up-a-wordpress-installation-in-a-jailed-environment
- https://l3net.wordpress.com/2014/06/08/securing-a-web-server-using-a-linux-namespaces-sandbox
- https://hans-hermann-bode.de/en/content/web-server-sandbox
- https://medium.com/@george.shuklin/on-using-firejail-for-network-isolation-in-tests-42f018ecdcac
- https://jaxenter.com/anti-docker-blog-114422.html


# Use

```nim
import firejail

# Create a Firejail, all args are optional, all options are Boolean, super easy!.
let myjail = Firejail(no3d=true, noDbus=true, noDvd=true, noRoot=true, noSound=true,
                      noVideo=true, noShell=true, noX=true, noNet=true, noIp=true)

echo myjail.list() # List all Firejails sandboxes running, return seq[JsonNode]

echo myjail.tree() # List all Firejails sandboxes running, return human friendly string

echo myjail.shutdown(pid=42) # Shutdown a running Firejail sandbox by PID, return bool

# For more read the Docs...
```
