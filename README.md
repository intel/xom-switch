 # XOM-Switch

xom-switch is the eXecutable-Only-Memory (XOM) enabling tool for x86 Linux
system. It aims to mitigate code disclosure guided ROP attacks by using Intel
Protection Keys feature in recent Intel CPU models. xom-switch protects all
code modules in the runtime including executable and dependent libraries
without requiring source code or heavyweight binary translation/rewriting.
xom-switch protects programs in non-intrusive way by patching only program
loader (ld.so).

## Getting Started

### Prerequsites

xom-switch requires two tools:
  - python 2.7
  - radare2, a static binary analyzer, which could be found in [here](https://github.com/radare/radare2.git)

### Components
xom-switch consists of three modules:
 - vino: static binary rewriter.
 - patch: C code piece that will be patched into program loader
 - analyzer: analyzer of the program loader using radare2

### Patching
 - install python 2.7 and radare2
 - patch your loader: `src/analyzer/patch_loader.sh /lib64/ld-linux-x86-64.so.2 /your/new/ld.so`
 - copy your loader to system dir: ```sudo mv /your/new/ld.so /lib64/ld-xom.so```
 - patch your libc.so (optional): ```src/analyzer/patch_libc.sh /lib/x86_64-linux-gnu/libc.so.6 /your/new/libc.so```

Note: patching your libc allows you to apply XOM to their child processes spawned through execve(2).

### Running
 - apply XOM to your program: `/lib64/ld-xom.so /path/to/your/program`
 - apply XOM to your program and its children: `LD_PRELOAD=/your/new/libc.so /lib64/ld-xom.so /path/to/your/program`

## License

This code is published under GPLv2 version.

## Clarification

This code is for demo purpose only and the status of code is "alpha".
