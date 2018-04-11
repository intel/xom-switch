 # XOM-Switch
 **(eXecutable-Only Memory Switch)**

xom-switch is the eXecutable-Only-Memory (XOM) enabling tool for x86 Linux system. It aims to mitigate code disclosure guided ROP attacks. This is is the 1st tool using Intel's [Memory Protection Keys (MPK)](https://lwn.net/Articles/643797/) feature for XOM enabling. xom-switch protects all code modules in the runtime including executable and dependent libraries without requiring source code or heavyweight binary translation/rewriting. xom-switch uses non-intrusive way to intercept program runtime by instrumenting program loader (ld.so).

**xom-switch could run in AMS AMI C5 VM. Try it out!**

**Fedora 28 will support GOT protection in lazy binding using memory protection keys. [Link1](https://www.phoronix.com/scan.php?page=news_item&px=Glibc-Memory-Protection-Keys), [Link2](https://fedoraproject.org/wiki/Changes/HardeningFlags28).**

## Background

### Why eXecutable-Only Memory
 - Protect randomized code.
 - Defend against [JIT-ROP Attack](https://cs.unc.edu/~fabian/papers/oakland2013.pdf).
 - Defend against [Hacking Blind Attack](http://www.scs.stanford.edu/~sorbo/brop/bittau-brop.pdf).
 
### Hardware Support
 - [LWN: Memory Protection Keys](https://lwn.net/Articles/643797/)
 - [Intel's Memory Protection Keys Specification](https://software.intel.com/sites/default/files/managed/7c/f1/253668-sdm-vol-3a.pdf)
 - [ARM's eXecutable-Only Memory](http://infocenter.arm.com/help/topic/com.arm.doc.dui0471j/chr1368698326509.html)
 
### Software Enabling
 - [XOM Enabling on Intel: BlackHat Asia 2018 Presentation](presentation/xom-switch-bhasia-2018-v1.3.pdf)
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
  - common tools: bc, binutils, gcc, python 2.7
  - radare2: a static binary analyzer, which could be found in [here](https://github.com/radare/radare2.git)

### Components
xom-switch consists of three modules:
 - [binary rewriter](src/rewriter/README.md): a static binary rewriter for x86 ELF binaries.
 - patch: C code pieces (see [tutorial](src/patch/tutorial/README.md) to write your own instrumentation) that will be patched into program loader.
 - analysis: analyzer/instrumentor of the program loader using radare2.

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

This code is for demo purpose only and the status of code is **beta**.

## Know Limitation
xom-switch has known limitation in the following cases:
 - When binaries has data embedded in the middle of code, xom-switch may crash. To avoid that xom-switch has a white list embedded in code. see
 - Since code modules (exe and libs) are not compiled with XOM support, there would be at least two code pages (the 1st and last code page) for each module where code and data co-exist. xom-switch avoids the issue by marking them as readable and executable. In the future, we will solve that using static analysis.
## Task List

- [x] Support CentOS 7.2.
- [x] Support CentOS 7.4.
- [x] Support Ubuntu 16.04.
- [x] Support Ubuntu 17.04.
- [x] Support simple instrumentation like function interception.
- [x] Support Amazon Linux 2 LTS Candidate AMI 2017.12.0 (HVM) C5 VM.
- [ ] Adding page fault handling to let go legitimate data read.


