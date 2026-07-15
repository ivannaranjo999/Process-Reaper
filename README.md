# Process Reaper - pr

This is a system maintenance tool that looks for:
- Zombie processes
- Orphan processes

`pr` can be used to *monitor* and/or *kill* processes that fulfill one of the conditions above. 

## Usage
```
Usage: ./pr [options]
Options:
  -l, --loop           Loop and report every interval seconds.
  -i, --interval N     Set the interval in seconds (default: 5).
  -h, --help           Show this help message.
  -k, --kill           Kill zombies and orphans. Be real careful when running with this option.
``` 

## Compilation
```
gcc -O2 -Wall process_reaper.c -o pr
```
