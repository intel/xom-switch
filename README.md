 # XOM-Switch
 **(eXecutable-Only Memory Switch)**

xom-switch is the eXecutable-Only-Memory (XOM) enabling tool for x86 Linux system. It aims to mitigate code disclosure guided ROP attacks. This is is the 1st tool using Intel's Memory Protection Keys (MPK) feature for XOM enabling. xom-switch protects all code modules in the runtime including executable and dependent libraries without requiring source code or heavyweight binary translation/rewriting. xom-switch uses non-intrusive way to intercept program runtime by instrumenting program loader (ld.so).

## Background

### Why eXecutable-Only Memory
 - [JIT-ROP Attack](https://cs.unc.edu/~fabian/papers/oakland2013.pdf)
 - [Hacking Blind Attack](http://www.scs.stanford.edu/~sorbo/brop/bittau-brop.pdf)
 
### Hardware Support
 - [LWN: Memory Protection Keys](https://lwn.net/Articles/643797/)
 - [Intel's Memory Protection Keys Specification](https://software.intel.com/sites/default/files/managed/7c/f1/253668-sdm-vol-3a.pdf)
 - [ARM's eXecutable-Only Memory](http://infocenter.arm.com/help/topic/com.arm.doc.dui0471j/chr1368698326509.html)
 
### Software Enabling
 - [XOM Enabling on Intel: BlackHat Asia 2018 Presentation](../presentation/xom-switch-mingwei-v1.3)
 - [XOM Enabling on ARM: NORAX](https://www.longlu.org/downloads/NORAX.pdf)


## Getting Started

### Platform Prerequsites
To run xom-switch properly, you need to have hardware and OS support first:
  - Intel CPU with protection keys feature on, e.g, [INTEL® XEON® SCALABLE PROCESSORS](https://www.intel.com/content/www/us/en/products/processors/xeon/scalable.html) **AND**
  - Linux kernel 4.9 or later.
  **OR**
  - Use VM in AWS, choose Amazon Linux 2 LTS Candidate AMI 2017.12.0 (HVM) and then **C5 Instance**.

### Software Prerequsites
xom-switch requires two tools:
  - gcc
  - python 2.7
  - radare2, a static binary analyzer, which could be found in [here](https://github.com/radare/radare2.git)

### Components
xom-switch consists of three modules:
 - rewriter: static binary rewriter.
 - patch: C code piece that will be patched into program loader
 - analysis: analyzer of the program loader using radare2

### Patching
 - install python 2.7 and radare2
 - patch your loader: `src/analysis/patch-loader.sh /lib64/ld-linux-x86-64.so.2 /your/new/ld.so`
 - copy your loader to system dir: ```sudo mv /your/new/ld.so /lib64/ld-xom.so```
 - patch your libc.so (optional): ```src/analysis/patch-libc.sh /lib/x86_64-linux-gnu/libc.so.6 /your/new/libc.so```

Note: patching your libc allows you to apply XOM to their child processes spawned through execve(2).

### Running
 - apply XOM to your program: `/lib64/ld-xom.so /path/to/your/program`
 - apply XOM to your program and its children: `LD_PRELOAD=/your/new/libc.so /lib64/ld-xom.so /path/to/your/program`

## License

This code is published under GPLv2 version.


## Project Status

This code is for demo purpose only and the status of code is **alpha**.


## Task List

- [x] Support CentOS 7.2.
- [x] Support CentOS 7.4.
- [x] Support Ubuntu 17.04.
- [ ] Support Amazon Linux 2 LTS Candidate AMI 2017.12.0 (HVM) with C5 instance.


